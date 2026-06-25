// SPDX-License-Identifier: GPL-2.0
#include "ktsan.h"

#include <linux/kernel.h>
#include <linux/mm_types.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/sched.h>

//MY CODE
static __always_inline kt_shadow_t *get_shadow_slots(uptr_t addr)
{
    struct page *page;
    unsigned long aligned_addr;
    unsigned long shadow_offset;
    
    /* Проверка, что адрес валидный */
    if (!virt_addr_valid((void *)addr))
        return NULL;
    
    /* Получаем страницу по адресу */
    page = virt_to_head_page((void *)addr);
    
    /* Проверяем, выделена ли shadow-память для страницы */
    if (unlikely(!page->shadow))
        return NULL;
    
    /* Выравниваем адрес до границы KT_GRAIN (8 байт) */
    aligned_addr = round_down(addr, KT_GRAIN);
    
    /* Вычисляем смещение в shadow-памяти для этого grain'а */
    /* В каждом grain'е KT_SHADOW_SLOTS слотов (обычно 4) */
    shadow_offset = (aligned_addr & (PAGE_SIZE - 1)) * KT_SHADOW_SLOTS;
    
    /* Возвращаем указатель на слоты для этого адреса */
    return (kt_shadow_t *)(page->shadow + shadow_offset);
}

static void dump_shadow_by_address(uptr_t addr)
{
    struct page *page;
    kt_shadow_t *slots;
    int i;
    u64 raw;
    
    /* Проверяем валидность адреса */
    if (!virt_addr_valid((void *)addr)) {
        pr_info("Invalid address: 0x%lx\n", addr);
        return;
    }
    
    /* Получаем страницу */
    page = virt_to_head_page((void *)addr);
    if (!page) {
        pr_info("No page for address: 0x%lx\n", addr);
        return;
    }
    
    pr_info("Address: 0x%lx\n", addr);
    //pr_info("Page: %p, page->shadow: %p\n", page, page->shadow);
    
    if (!page->shadow) {
        pr_info("No shadow memory allocated for page %p\n", page);
        return;
    }
    
    /* Получаем shadow-слоты */
    slots = get_shadow_slots(addr);
    if (!slots) {
        pr_info("Failed to get shadow slots for address 0x%lx\n", addr);
        return;
    }
    
    /* Дамп всех слотов для этого grain'а */
    pr_info("Shadow slots for grain at 0x%lx:\n", 
            round_down(addr, KT_GRAIN));
    for (i = 0; i < KT_SHADOW_SLOTS; i++) {
        raw = kt_atomic64_load_no_ktsan((atomic64_t *)&slots[i]);
        if (raw == 0) {
            pr_info("  Slot %d: EMPTY\n", i);
            continue;
        }
        
        kt_shadow_t slot = *(kt_shadow_t *)&raw;
        pr_info("  Slot %d: tid=%u, clock=%llu, offset=%u, size=%u, read=%d, atomic=%d\n",
                i, slot.tid, (unsigned long long)slot.clock,
                slot.offset, 1 << slot.size, slot.read, slot.atomic);
    }
}

atomic64_t kt_total_accesses = ATOMIC64_INIT(0);
EXPORT_SYMBOL(kt_total_accesses); 
atomic64_t kt_total_accesses_old = ATOMIC64_INIT(0);
EXPORT_SYMBOL(kt_total_accesses_old);

atomic64_t kt_total_conflict_pairs = ATOMIC64_INIT(0);
EXPORT_SYMBOL(kt_total_conflict_pairs);
atomic64_t kt_total_conflict_pairs_old = ATOMIC64_INIT(0);
EXPORT_SYMBOL(kt_total_conflict_pairs_old);

atomic64_t kt_total_conflict_pairs_unordered = ATOMIC64_INIT(0);
EXPORT_SYMBOL(kt_total_conflict_pairs_unordered);
atomic64_t kt_total_conflict_pairs_unordered_old = ATOMIC64_INIT(0);
EXPORT_SYMBOL(kt_total_conflict_pairs_unordered_old);

atomic64_t kt_total_accesses_from_all = ATOMIC64_INIT(0);
EXPORT_SYMBOL(kt_total_accesses_from_all);
atomic64_t kt_total_accesses_from_all_old = ATOMIC64_INIT(0);
EXPORT_SYMBOL(kt_total_accesses_from_all_old);

atomic64_t kt_total_conflict_pairs_1_tracked = ATOMIC64_INIT(0);
EXPORT_SYMBOL(kt_total_conflict_pairs_1_tracked);
atomic64_t kt_total_conflict_pairs_1_tracked_old = ATOMIC64_INIT(0);
EXPORT_SYMBOL(kt_total_conflict_pairs_1_tracked_old);

atomic64_t kt_total_conflict_pairs_unordered_1_tracked = ATOMIC64_INIT(0);
EXPORT_SYMBOL(kt_total_conflict_pairs_unordered_1_tracked);
atomic64_t kt_total_conflict_pairs_unordered_1_tracked_old = ATOMIC64_INIT(0);
EXPORT_SYMBOL(kt_total_conflict_pairs_unordered_1_tracked_old);
//extern int ktsan_target_pid;

atomic64_t kt_total_unique_races = ATOMIC64_INIT(0);
EXPORT_SYMBOL(kt_total_unique_races);

#define MAX_PIDS 256

extern int ktsan_target_pids[MAX_PIDS];
extern int ktsan_num_pids;
extern struct mutex ktsan_pids_lock;

extern bool is_ktsan_tracked(pid_t pid);
//END 

#define PID_FILTER 1

static __always_inline bool ranges_intersect(int first_offset, int first_size,
					     int second_offset, int second_size)
{
	if (first_offset + first_size <= second_offset)
		return false;

	if (second_offset + second_size <= first_offset)
		return false;

	return true;
}

static __always_inline bool update_one_shadow_slot(kt_thr_t *thr, uptr_t addr,
						   kt_shadow_t *slot,
						   kt_shadow_t value,
						   bool stored)
{
	kt_race_info_t info;
	kt_shadow_t old;
	u64 raw;
    
#if PID_FILTER
	// Игнорируем доступы неотслеживаемых пидов, чтобы теневая память не засорялась
	if (!is_ktsan_tracked(value.tid)) {
		return true;
	}
#endif

	raw = kt_atomic64_load_no_ktsan(slot);
	if (raw == 0) {
		if (!stored)
			kt_atomic64_store_no_ktsan(slot,
						   KT_SHADOW_TO_LONG(value));
		return true;
	}
	old = *(kt_shadow_t *)&raw;

	// DEBUG
	/*if (is_ktsan_tracked(old.tid) && is_ktsan_tracked(thr->pid)) {
		if (old.tid != value.tid) {
			pr_info("BUG: same thread %u but TIDs differ! old.tid=%u value.tid=%u\n",
				thr->pid, old.tid, value.tid);
		}
	}*/
	/* Is the memory access equal to the previous? */

	//DEBUG
	// if (is_ktsan_tracked(old.tid) && is_ktsan_tracked(value.tid)) {
	// 	dump_shadow_by_address(addr);
	// }
	//

	if (value.offset == old.offset && value.size == old.size) {
		/* Same thread? */
		if (likely(value.tid == old.tid)) {
			/* TODO. */
			/*if (is_ktsan_tracked(thr->pid)) {
				pr_info("SAME THREAD: tid=%d addr=0x%lx old.offset=%d new.offset=%d\n",
					old.tid, addr, old.offset, value.offset);
			}*/
			return false;
		}
		//I ve changed order of checks to hard count of conflict pairs
		// without counting happens before
                if (likely(old.read && value.read))
			return false;
		if (likely(old.atomic && value.atomic))
			return false;
                
		//MY CODE
		// В kt_access_impl используем функцию is_ktsan_tracked:
			if (is_ktsan_tracked(old.tid) || is_ktsan_tracked(value.tid)) {
				atomic64_inc(&kt_total_conflict_pairs_1_tracked);
			}
			if (is_ktsan_tracked(old.tid) && is_ktsan_tracked(value.tid)) {
				atomic64_inc(&kt_total_conflict_pairs);
				//pr_info("Old tid: %u, Value tid: %u\n", old.tid, value.tid);
				// dump_shadow_by_address(addr);
			}

		//if (ktsan_target_pid != -1 && ktsan_target_pid == thr->pid) {
			//    atomic64_inc(&kt_total_conflict_pairs);
			//}
			//END
		
		/* Happens-before? */
		if (likely(kt_clk_get(&thr->clk, old.tid) >= old.clock)) {
			if (!stored)
				kt_atomic64_store_no_ktsan(
					slot, KT_SHADOW_TO_LONG(value));
			return true;
		}
                /*
		if (likely(old.read && value.read))
			return false;
		if (likely(old.atomic && value.atomic))
			return false;
		*/
		if (is_ktsan_tracked(old.tid) || is_ktsan_tracked(value.tid)) {
			atomic64_inc(&kt_total_conflict_pairs_unordered_1_tracked);
		}
		if (is_ktsan_tracked(old.tid) && is_ktsan_tracked(value.tid)) {
			atomic64_inc(&kt_total_conflict_pairs_unordered);
			// pr_info("Race: old.tid=%d thr->tid=%d value.tid=%d addr=0x%lx\n", old.tid, thr->pid,
			// 		value.tid, addr);
		}
		goto report_race;
	}

	/* Do the memory accesses intersect? */
	if (unlikely(ranges_intersect(old.offset, (1 << old.size), value.offset,
				      (1 << value.size)))) {
		if (old.tid == value.tid)
			return false;
		if (old.read && value.read)
			return false;
		if (kt_clk_get(&thr->clk, old.tid) >= old.clock)
			return false;
		if (likely(old.atomic && value.atomic))
			return false;

	report_race:
		info.addr = addr;
		info.old = old;
		info.new = value;
		kt_report_race(thr, &info);

		return true;
	}

	return false;
}

static __always_inline void kt_access_impl(kt_thr_t *thr, kt_shadow_t *slots,
					   kt_time_t current_clock, uptr_t addr,
					   size_t size, bool read, bool atomic)
{
	kt_shadow_t value;
	int i;
	bool stored;

        //MY CODE

	atomic64_inc(&kt_total_accesses_from_all);

        if (is_ktsan_tracked(thr->pid)) {
            atomic64_inc(&kt_total_accesses);
        }
        //if (ktsan_target_pid != -1 && ktsan_target_pid == thr->pid) {
        //    atomic64_inc(&kt_total_accesses);
        //}
        //END
	kt_stat_inc(read ? kt_stat_access_read : kt_stat_access_write);
	kt_stat_inc(kt_stat_access_size1 + size);

	// IS RACE POSSIBLE
	value.tid = thr->id;
	value.clock = current_clock;
	value.offset = addr & (KT_GRAIN - 1);
	value.size = size;
	value.read = read;
	value.atomic = atomic;

	stored = false;
	for (i = 0; i < KT_SHADOW_SLOTS; i++)
		stored |= update_one_shadow_slot(thr, addr, &slots[i], value,
						 stored);

	/*pr_err("thread: %d, addr: %lx, size: %u, read: %d, stored: %d\n",
		 (int)thr->id, addr, (int)size, (int)read, stored);*/

	if (!stored) {
		/* Evict random shadow slot. */
		kt_atomic64_store_no_ktsan(
			&slots[current_clock % KT_SHADOW_SLOTS],
			KT_SHADOW_TO_LONG(value));
	}
}

/*
   Size might be 0, 1, 2 or 3 and equals to the binary logarithm
   of the actual access size.
*/
void kt_access(kt_thr_t *thr, uptr_t pc, uptr_t addr, size_t size, bool read,
	       bool atomic)
{
	kt_time_t current_clock;
	kt_shadow_t *slots;

	if (read && thr->read_disable_depth)
		return;

	slots = kt_shadow_get(addr);
	if (unlikely(!slots))
		return; /* FIXME? */

	kt_trace_add_event(thr, kt_event_mop, kt_compress(pc));
	current_clock = kt_clk_get(&thr->clk, thr->id);

	kt_access_impl(thr, slots, current_clock, addr, size, read, atomic);
}

void kt_access_range(kt_thr_t *thr, uptr_t pc, uptr_t addr, size_t size,
		     bool read)
{
	kt_time_t current_clock;
	kt_shadow_t *slots;

	BUG_ON(size == 0);
	if (read && thr->read_disable_depth)
		return;

	slots = kt_shadow_get(addr);
	if (unlikely(!slots))
		return; /* FIXME? */

	kt_trace_add_event(thr, kt_event_mop, kt_compress(pc));
	current_clock = kt_clk_get(&thr->clk, thr->id);

	/* Handle unaligned beginning, if any. */
	if (addr & (KT_GRAIN - 1)) {
		for (; (addr & (KT_GRAIN - 1)) && size; addr++, size--)
			kt_access_impl(thr, slots, current_clock, addr,
				       KT_ACCESS_SIZE_1, read, false);
		slots += KT_SHADOW_SLOTS;
	}

	/* Handle middle part, if any. */
	for (; size >= KT_GRAIN; addr += KT_GRAIN, size -= KT_GRAIN) {
		kt_access_impl(thr, slots, current_clock, addr,
			       KT_ACCESS_SIZE_8, read, false);
		slots += KT_SHADOW_SLOTS;
	}

	/* Handle ending, if any. */
	for (; size; addr++, size--)
		kt_access_impl(thr, slots, current_clock, addr,
			       KT_ACCESS_SIZE_1, read, false);
}

void kt_access_range_imitate(kt_thr_t *thr, uptr_t pc, uptr_t addr, size_t size,
			     bool read)
{
	kt_time_t current_clock;
	kt_shadow_t value;
	kt_shadow_t *slots;
	int i;

	/* Currently it is called only from kt_memblock_alloc, so the address
	 * and size must be multiple of KT_GRAIN. */
	BUG_ON((addr & (KT_GRAIN - 1)) != 0);
	BUG_ON((size & (KT_GRAIN - 1)) != 0);

	slots = kt_shadow_get(addr);
	if (!slots)
		return; /* FIXME? */

	kt_trace_add_event(thr, kt_event_mop, kt_compress(pc));
	current_clock = kt_clk_get(&thr->clk, thr->id);

	/* Below we assume that access size 8 covers whole grain. */
	BUG_ON(KT_GRAIN != (1 << KT_ACCESS_SIZE_8));

	value.tid = thr->id;
	value.clock = current_clock;
	value.offset = 0;
	value.size = KT_ACCESS_SIZE_8;
	value.read = read;
	value.atomic = false;

	for (; size; size -= KT_GRAIN) {
		for (i = 0; i < KT_SHADOW_SLOTS; i++, slots++)
			kt_atomic64_store_no_ktsan(
				slots, i ? 0 : KT_SHADOW_TO_LONG(value));
	}
}
