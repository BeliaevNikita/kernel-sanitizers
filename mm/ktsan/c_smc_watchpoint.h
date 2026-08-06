/*===-- c_smc_watchpoint.h ------------------------------------------------===*
 *
 * This file is a part of SMC RaceHunter, a race detector.
 *
 * C/kernel declarations for smc_watchpoint.h.
 *
 *===----------------------------------------------------------------------===*/

#ifndef C_SMC_WATCHPOINT_H
#define C_SMC_WATCHPOINT_H

#include <linux/atomic.h>
#include <linux/types.h>

#include "c_smc_analysis.h"
#include "c_smc_data.h"
#include "c_smc_event.h"
#include "c_smc_watchpoint_targets.h"

#define SMC_CONFIG_NUM_WATCHPOINTS 5
#define SMC_WATCHPOINT_SHIFT_ADDR 8
#define SMC_WATCHPOINT_CONSUMED (~(smc_uptr_t)0)

struct smc_mutex;
struct smc_report_stack;
struct smc_thread_handle;
struct smc_thread_safe_timer;

enum smc_target_status {
	SMC_TARGET_STATUS_NONE,
	SMC_TARGET_STATUS_ACCESS,
	SMC_TARGET_STATUS_RACE,
};

struct smc_wp_statistics {
	atomic_t race_found;
	atomic_t access_target;
	atomic_t none_target;
	atomic_t monitoring_target;
	atomic_t race_target;
	atomic_t total_iterations;
	atomic_t target_status;
	atomic64_t shared_accesses;
	atomic64_t shared_accesses_iteration;
	atomic64_t targets_fitness_limit;
	atomic64_t targets_unknown_pc;
	atomic64_t targets_lockset;
	atomic64_t targets_created;
	struct smc_thread_safe_timer *shared_transfer_timer;
	struct smc_thread_safe_timer *shared_inner_transfer_timer;
};

struct smc_watchpoint {
	unsigned long addr;
	smc_uptr_t size;
	smc_uptr_t pc;
	u32 owner_id;
	unsigned long owner_epoch;
	u32 life;
	bool is_read;
	bool is_atomic;
};

struct smc_watchpoint_local_state {
	struct smc_local_state base;
	struct smc_local_state *inner;
	int skip_watch;
	int skip_count;
	smc_uptr_t nth_event_count;
	struct smc_ilist covered_accesses;
	struct smc_mem_access *postponed;
};

struct smc_other_info {
	struct smc_mem_access access_info;
	int handle_tid;
	u32 ktsan_tid;
	struct smc_report_stack *stack;
};

struct smc_watchpoint_global_state {
	struct smc_global_state base;
	struct smc_global_state *inner;
	struct smc_watchpoint watchpoints[SMC_CONFIG_NUM_WATCHPOINTS];
	struct smc_other_info other_info[SMC_CONFIG_NUM_WATCHPOINTS];
	u8 slot_locks[SMC_CONFIG_NUM_WATCHPOINTS];
	u8 report_lock;
};

struct smc_watchpoint_wait_action {
	struct smc_thread_handle *handle;
	struct smc_watchpoint_global_state *global_state;
	struct smc_wp_statistics *stats;
	struct smc_watchpoint *watchpoint;
	const struct smc_mem_access *mem_access;
	smc_uptr_t cur_pc;
	unsigned int timeout;
};

struct smc_watchpoint_analysis {
	struct smc_dynamic_analysis base;
	struct smc_dynamic_analysis *inner;
	int timeout;
	bool is_random;
	int fitness_limit;
	bool first_access_only;
	unsigned int intrusion_list_limit;
	bool enable_interesting_check;
	bool intrusion_collect;
	bool composite_intrusion_collect;
	bool weak_mem;
	struct smc_wp_statistics stats;
	struct smc_watchpoint_global_state global_state;
};

int smc_watchpoint_an_init(struct smc_watchpoint_analysis *analysis);
void smc_watchpoint_an_destroy(struct smc_dynamic_analysis *analysis);

void smc_init_watchpoint_thread_locals(void);

void smc_add_race_info(struct smc_other_info *info, u32 handle_tid,
		       smc_uptr_t pc);
void smc_report_race_access(const struct smc_other_info *report,
			    bool is_first, bool is_old, bool postponed);

void smc_watchpoint_local_state_destroy(
	struct smc_watchpoint_local_state *state);
void smc_watchpoint_local_state_print(
	const struct smc_watchpoint_local_state *state);
void smc_watchpoint_local_state_reset(
	struct smc_watchpoint_local_state *state);
bool smc_watchpoint_local_state_is_access_covered(
	const struct smc_watchpoint_local_state *state, smc_uptr_t pc,
	const struct smc_compatible_state *compatible_state);
int smc_watchpoint_local_state_add_covered_access(
	struct smc_watchpoint_local_state *state, smc_uptr_t pc,
	struct smc_compatible_state *compatible_state);
void smc_watchpoint_local_state_clear_covered_accesses(
	struct smc_watchpoint_local_state *state);

void smc_watchpoint_global_state_destroy(
	struct smc_watchpoint_global_state *state);
void smc_watchpoint_global_state_print(
	const struct smc_watchpoint_global_state *state);
void smc_watchpoint_global_state_reset(
	struct smc_watchpoint_global_state *state);
bool smc_watchpoint_global_state_has_watchpoint(
	struct smc_watchpoint_global_state *state);
int smc_watchpoint_global_state_get_slot(
	const struct smc_watchpoint_global_state *state, smc_uptr_t addr);
bool smc_watchpoint_intersects(const struct smc_watchpoint *watchpoint,
			       smc_uptr_t old_addr,
			       const struct smc_mem_access *access);
struct smc_watchpoint *smc_watchpoint_global_state_get_watchpoint(
	struct smc_watchpoint_global_state *state,
	const struct smc_mem_access *access);
struct smc_watchpoint *
smc_watchpoint_global_state_add_if_empty(
	struct smc_watchpoint_global_state *state,
	const struct smc_mem_access *access, bool should_set,
	u32 handle_id);
bool smc_watchpoint_global_state_remove_watchpoint(
	struct smc_watchpoint_global_state *state,
	struct smc_watchpoint *watchpoint);
void smc_watchpoint_global_state_add_info(
	struct smc_watchpoint_global_state *state, u32 id,
	const struct smc_mem_access *mem_access);
void smc_watchpoint_global_state_report_race(
	struct smc_watchpoint_global_state *state, u32 id,
	const struct smc_mem_access *mem_access, smc_uptr_t cur_pc);

bool smc_watchpoint_wait_action_post_wait(
	struct smc_watchpoint_wait_action *action, bool result);
void smc_watchpoint_wait_action_cancel(
	struct smc_watchpoint_wait_action *action);

struct smc_target *smc_watchpoint_an_get_initial_target(
	struct smc_dynamic_analysis *analysis);
struct smc_local_state *smc_watchpoint_an_get_initial_local_state(
	struct smc_dynamic_analysis *analysis, struct smc_thread_handle *handle);
struct smc_global_state *smc_watchpoint_an_get_initial_global_state(
	struct smc_dynamic_analysis *analysis);
struct smc_wait_action *smc_watchpoint_an_transfer(
	struct smc_dynamic_analysis *analysis,
	struct smc_thread_handle *handle, const struct smc_event *event,
	const struct smc_target *target, struct smc_local_state *local_state,
	struct smc_global_state *global_state);
struct smc_ilist *smc_watchpoint_an_get_new_targets(
	struct smc_dynamic_analysis *analysis,
	struct smc_thread_handle *handle, const struct smc_target *target,
	const struct smc_event *event, struct smc_local_state *local_state,
	struct smc_global_state *global_state);
bool smc_watchpoint_an_fast_is_related(
	const struct smc_dynamic_analysis *analysis,
	enum smc_event_type event_type);
struct smc_target *smc_watchpoint_an_get_current_target(
	struct smc_watchpoint_analysis *analysis, const struct smc_target *target,
	struct smc_local_state *local_state,
	struct smc_global_state *global_state);
struct smc_watchpoint_analysis *smc_watchpoint_an_create(
	struct smc_dynamic_analysis *inner);
void smc_watchpoint_an_print_statistics(
	const struct smc_dynamic_analysis *analysis, bool total);
void smc_watchpoint_an_reset_statistics(
	struct smc_watchpoint_analysis *analysis);
void smc_watchpoint_an_start_iteration(
	struct smc_dynamic_analysis *analysis,
	struct smc_global_state *global_state, const struct smc_target *target);
void smc_watchpoint_an_finish_iteration(
	struct smc_dynamic_analysis *analysis,
	struct smc_global_state *global_state, struct smc_target *target);

#endif /* C_SMC_WATCHPOINT_H */
