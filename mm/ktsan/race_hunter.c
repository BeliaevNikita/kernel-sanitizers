// SPDX-License-Identifier: GPL-2.0
#include "ktsan.h"
#include <asm/processor.h>
#include <linux/hash.h>

#if KT_ENABLE_RACE_HUNTER
#include "c_smc_algorithm.h"
#include "c_smc_event.h"

#define KT_RH_PC_CACHE_BITS 13
#define KT_RH_PC_CACHE_SIZE (1U << KT_RH_PC_CACHE_BITS)
#define KT_RH_PC_RING_SIZE (1U << RH_KT_PC_BITS)
#define KT_RH_PC_RING_MASK (KT_RH_PC_RING_SIZE - 1)

struct kt_rh_pc_entry {
	u64 tag;
	uptr_t pc;
};

static struct kt_rh_pc_entry kt_rh_pc_cache[KT_RH_PC_CACHE_SIZE];
static struct kt_rh_pc_entry kt_rh_pc_ring[KT_RH_PC_RING_SIZE];
static u64 kt_rh_pc_ring_head;
static u64 kt_rh_pc_ring_hits;
static u64 kt_rh_pc_ring_misses;
static u64 kt_rh_pc_ring_wraps;
static enum kt_rh_pc_mode kt_rh_pc_mode = KT_RH_PC_MODE_HASH;
extern bool is_ktsan_tracked(pid_t pid);

static u64 kt_rh_pc_tag(u32 tid, kt_time_t clock)
{
	return ((u64)tid << RH_KT_CLOCK_BITS) | clock;
}

enum kt_rh_pc_mode kt_rh_get_pc_mode(void)
{
	return READ_ONCE(kt_rh_pc_mode);
}

int kt_rh_set_pc_mode(enum kt_rh_pc_mode mode)
{
	struct smc_dynamic_algorithm *dynamic;
	enum smc_iteration_phase phase;
	bool initial_collecting = false;

	if (mode != KT_RH_PC_MODE_HASH && mode != KT_RH_PC_MODE_RING)
		return -EINVAL;
	if (kt_ctx.smc_algorithm) {
		dynamic = &kt_ctx.smc_algorithm->data.dynamic;
		phase = smc_alg_get_phase(kt_ctx.smc_algorithm);
		initial_collecting = phase == SMC_PHASE_COLLECTING &&
			dynamic->iteration_id == 1 &&
			kt_atomic32_load_no_ktsan(&dynamic->active_events) == 0;
		if (phase != SMC_PHASE_IDLE && phase != SMC_PHASE_COMPLETE &&
		    !initial_collecting)
			return -EBUSY;
	}
	WRITE_ONCE(kt_rh_pc_mode, mode);
	return 0;
}

u32 kt_rh_record_pc(kt_thr_t *thr, kt_time_t clock, uptr_t pc)
{
	struct kt_rh_pc_entry *entry;
	u64 tag;
	u64 position;
	u32 index;

	if (!thr || !is_ktsan_tracked(thr->pid))
		return 0;
	tag = kt_rh_pc_tag(thr->id, clock);
	if (READ_ONCE(kt_rh_pc_mode) == KT_RH_PC_MODE_RING) {
		position = kt_atomic64_fetch_add_no_ktsan(&kt_rh_pc_ring_head, 1);
		index = position & KT_RH_PC_RING_MASK;
		if (index == 0 && position != 0)
			kt_atomic64_fetch_add_no_ktsan(&kt_rh_pc_ring_wraps, 1);
		entry = &kt_rh_pc_ring[index];
		kt_atomic64_store_no_ktsan(&entry->tag, 0);
		kt_atomic64_store_no_ktsan(&entry->pc, pc);
		asm volatile("" ::: "memory");
		kt_atomic64_store_no_ktsan(&entry->tag, tag);
		return index;
	}
	entry = &kt_rh_pc_cache[hash_64(tag, KT_RH_PC_CACHE_BITS)];
	kt_atomic64_store_no_ktsan(&entry->tag, 0);
	kt_atomic64_store_no_ktsan(&entry->pc, pc);
	/* x86 stores are ordered; the compiler barrier publishes pc before tag. */
	asm volatile("" ::: "memory");
	kt_atomic64_store_no_ktsan(&entry->tag, tag);
	return clock & KT_RH_PC_RING_MASK;
}

static uptr_t kt_rh_lookup_pc(u32 tid, kt_time_t clock, u32 shadow_pc)
{
	u64 tag = kt_rh_pc_tag(tid, clock);
	struct kt_rh_pc_entry *entry;
	uptr_t pc;
	bool ring = READ_ONCE(kt_rh_pc_mode) == KT_RH_PC_MODE_RING;

	entry = ring ? &kt_rh_pc_ring[shadow_pc & KT_RH_PC_RING_MASK] :
		&kt_rh_pc_cache[hash_64(tag, KT_RH_PC_CACHE_BITS)];

	if (kt_atomic64_load_no_ktsan(&entry->tag) != tag) {
		if (ring)
			kt_atomic64_fetch_add_no_ktsan(&kt_rh_pc_ring_misses, 1);
		return 0;
	}
	asm volatile("" ::: "memory");
	pc = kt_atomic64_load_no_ktsan(&entry->pc);
	asm volatile("" ::: "memory");
	if (kt_atomic64_load_no_ktsan(&entry->tag) != tag) {
		if (ring)
			kt_atomic64_fetch_add_no_ktsan(&kt_rh_pc_ring_misses, 1);
		return 0;
	}
	if (ring)
		kt_atomic64_fetch_add_no_ktsan(&kt_rh_pc_ring_hits, 1);
	return pc;
}

void kt_rh_print_and_reset_pc_statistics(void)
{
	pr_info("KTSAN SMC PC: mode=%s ring_hits=%llu ring_misses=%llu ring_wraps=%llu\n",
		READ_ONCE(kt_rh_pc_mode) == KT_RH_PC_MODE_RING ? "ring" : "hash",
		kt_atomic64_exchange_no_ktsan(&kt_rh_pc_ring_hits, 0),
		kt_atomic64_exchange_no_ktsan(&kt_rh_pc_ring_misses, 0),
		kt_atomic64_exchange_no_ktsan(&kt_rh_pc_ring_wraps, 0));
}

/* RACE HUNTER: central event dispatch guard. It keeps the adapted Race Hunter
 * callbacks from recursively entering themselves through instrumented KTSAN
 * paths.
 */
static void kt_rh_on_event(kt_thr_t *thr, const struct smc_event *event)
{
	if (!kt_ctx.smc_enabled || !kt_ctx.smc_algorithm || !thr ||
	    !thr->smc_handle || thr->smc_inside)
		return;
	if (!on_thread_stack())
		return;
	if (!is_ktsan_tracked(thr->pid))
		return;

	thr->smc_inside++;
	smc_alg_on_event(kt_ctx.smc_algorithm, event, thr->smc_handle);
	thr->smc_inside--;
}

void kt_rh_init(void)
{
	smc_minimal_init(&kt_ctx.smc_algorithm);
}

void kt_rh_thread_create(kt_thr_t *parent, kt_thr_t *child, uptr_t pc)
{
	struct smc_event event = {
		.type = SMC_THREAD_CREATE_TYPE,
		.data.thread_create = {
			.parent = parent ? parent->id : 0,
			.child = child ? child->id : 0,
			.pc = pc,
		},
	};

	/* RACE HUNTER: ThreadCreateEvent is delivered on the parent handle. */
	kt_rh_on_event(parent, &event);
}

void kt_rh_thread_start(kt_thr_t *thr, uptr_t pc)
{
	struct smc_event event = {
		.type = SMC_THREAD_START_TYPE,
		.data.thread_start = {
			.base = {
				.id = thr ? thr->id : 0,
			},
		},
	};

	/* RACE HUNTER: pc is reserved for future start-site tracking. */
	(void)pc;

	/* RACE HUNTER: ThreadStartEvent. */
	kt_rh_on_event(thr, &event);
}

void kt_rh_thread_finish(kt_thr_t *thr, uptr_t pc)
{
	struct smc_event event = {
		.type = SMC_THREAD_FINISH_TYPE,
		.data.thread_finish = {
			.id = thr ? thr->id : 0,
		},
	};

	/* RACE HUNTER: pc is represented by the preceding fence event. */
	(void)pc;

	/* RACE HUNTER: ThreadFinishEvent. */
	kt_rh_on_event(thr, &event);
}

void kt_rh_function_entry(kt_thr_t *thr, uptr_t pc)
{
	struct smc_event event = {
		.type = SMC_FUNCTION_ENTRY_TYPE,
		.data.function_entry = {
			.pc = pc,
		},
	};

	/* RACE HUNTER: FunctionEntryEvent. */
	kt_rh_on_event(thr, &event);
}

void kt_rh_function_exit(kt_thr_t *thr)
{
	struct smc_event event = {
		.type = SMC_FUNCTION_EXIT_TYPE,
	};

	/* RACE HUNTER: FunctionExitEvent. */
	kt_rh_on_event(thr, &event);
}

void kt_rh_fence(kt_thr_t *thr, uptr_t pc)
{
	struct smc_event event = {
		.type = SMC_FENCE_TYPE,
		.data.fence = {
			.pc = pc,
		},
	};

	/* RACE HUNTER: FenceEvent used to flush postponed watchpoint accesses. */
	kt_rh_on_event(thr, &event);
}

void kt_rh_prelock(kt_thr_t *thr, uptr_t pc)
{
	struct smc_event event = {
		.type = SMC_PRELOCK_TYPE,
	};

	/* RACE HUNTER: pc is reserved for future prelock-site tracking. */
	(void)pc;

	/* RACE HUNTER: PrelockEvent for scheduling analyses. */
	kt_rh_on_event(thr, &event);
}

void kt_rh_mem_access(kt_thr_t *thr, uptr_t pc, uptr_t addr, size_t size,
		      bool read, bool atomic, int typ)
{
	struct smc_event event = {
		.type = SMC_MEM_ACCESS_TYPE,
		.data.mem_access = {
			.pc = pc,
			.addr = addr,
			.size = size,
			.is_read = read,
			.is_atomic = atomic,
			.typ = typ,
		},
	};

	/* RACE HUNTER: MemAccess event for watchpoint monitoring. */
	kt_rh_on_event(thr, &event);
}

void kt_rh_shared_mem_access(kt_thr_t *thr, uptr_t cur_pc, uptr_t addr,
			     size_t size, bool read, bool atomic,
			     kt_shadow_t old, int epoch_diff)
{
	struct smc_event event = {
		.type = SMC_SHARED_MEM_ACCESS_TYPE,
		.data.shared_mem_access = {
			.prev_pc = kt_rh_lookup_pc(old.tid, old.clock, old.pc),
			.cur_pc = cur_pc,
			.epoch_diff = epoch_diff,
			.context = NULL,
		},
	};

	/* RACE HUNTER: addr/access flags are available for a richer shared
	 * context once the kernel SharedContext equivalent is introduced.
	 */
	(void)addr;
	(void)size;
	(void)read;
	(void)atomic;

	/* RACE HUNTER: SharedMemAccess event for new target generation. */
	kt_rh_on_event(thr, &event);
}

/* Dedicated deterministic bridge for the userspace-driven SMC self-test. */
void kt_rh_test_shared_mem_access(kt_thr_t *thr, uptr_t prev_pc,
				  uptr_t cur_pc)
{
	struct smc_event event = {
		.type = SMC_SHARED_MEM_ACCESS_TYPE,
		.data.shared_mem_access = {
			.prev_pc = prev_pc,
			.cur_pc = cur_pc,
			.epoch_diff = 1,
			.context = NULL,
		},
	};

	if (!kt_ctx.smc_algorithm ||
	    smc_alg_get_phase(kt_ctx.smc_algorithm) != SMC_PHASE_COLLECTING)
		return;
	kt_rh_on_event(thr, &event);
}

void kt_rh_safe_point(kt_thr_t *thr)
{
	if (!thr || !thr->smc_handle || !READ_ONCE(thr->smc_handle->pending_wait_action))
		return;
	if (thr->inside || thr->smc_inside || thr->event_disable_depth ||
	    thr->interrupt_depth || in_interrupt() || irqs_disabled() ||
	    !preemptible())
		return;
	smc_thread_handle_process_wait(thr->smc_handle);
}
#endif /* KT_ENABLE_RACE_HUNTER */
