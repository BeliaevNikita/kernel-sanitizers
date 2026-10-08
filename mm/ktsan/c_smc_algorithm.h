#ifndef C_SMC_ALGORITHM_H
#define C_SMC_ALGORITHM_H

#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/wait.h>

#include "c_smc_analysis.h"
#include "c_smc_waitlist.h"
#include "c_smc_hash.h"

struct smc_mutex;
struct smc_timer;
struct smc_thread_safe_timer;

typedef void *smc_mutation_state_t;

enum smc_algorithm_type {
	SMC_ALGORITHM_DYNAMIC,
};

enum smc_iteration_phase {
	SMC_PHASE_IDLE,
	SMC_PHASE_COLLECTING,
	SMC_PHASE_TARGET,
	SMC_PHASE_FINISHING,
	SMC_PHASE_COMPLETE,
	SMC_PHASE_COUNT,
};

enum smc_drop_kind {
	SMC_DROP_COMPLETION = SMC_EVENT_TYPE_COUNT,
	SMC_DROP_KIND_COUNT,
};

enum smc_iteration_result {
	SMC_ITERATION_NONE,
	SMC_ITERATION_RACE,
	SMC_ITERATION_ACCESS_REACHED,
	SMC_ITERATION_TARGET_NOT_REACHED,
	SMC_ITERATION_TIMEOUT,
	SMC_ITERATION_EVENT_LIMIT,
	SMC_ITERATION_ABORTED,
	SMC_ITERATION_CONTENDED,
};

struct smc_bitmap_pair {
	unsigned int index;
	smc_hash_uptr_t second;
};

#define SMC_HASH_ROW 8
#define SMC_HASH_LIMIT (1 << SMC_HASH_ROW)
#define SMC_BITMAP_SIZE (SMC_HASH_LIMIT >> 6)

struct smc_dynamic_algorithm {
	int restart_count;
	u32 iteration_generation;
	int prep_iterations;
	struct smc_dynamic_analysis *analysis;
	struct smc_global_state *global_state;
	struct smc_mutex *lock;
	struct smc_target *target;
	enum smc_target_type target_type;
	struct smc_reached_set *reached;
	struct smc_waitlist *waitlist;
	struct smc_ilist iteration_targets;
	struct smc_ilist explored_targets;
	u8 event_lock;
	struct smc_coverage coverage;
	enum smc_iteration_phase phase;
	enum smc_iteration_result iteration_result;
	u64 iteration_id;
	bool restart_required;
	bool stop_requested;
	atomic_t active_events;
	struct list_head pending_waits;
	u64 waits_executed;
	u64 waits_cancelled;
	u64 duplicate_targets;
	u64 target_insert_failures;
	u64 dropped_events;
	u64 dropped_events_start;
	u64 iteration_dropped_events;
	u64 event_attempts;
	u64 event_attempts_start;
	u64 iteration_event_attempts;
	u64 iteration_dropped_by_phase[SMC_PHASE_COUNT];
	u64 iteration_dropped_by_type[SMC_DROP_KIND_COUNT];
	wait_queue_head_t quiescent_waitq;
	int reached_targets;
	int feasible_targets;
	int infeasible_targets;
	int iteration_limit;
	int race_limit;
	struct smc_timer *single_threaded_iteration_timer;
	struct smc_timer *single_threaded_prep_timer;
	struct smc_timer *single_threaded_initial_timer;
	struct smc_timer *single_threaded_rest_timer;
	struct smc_timer *single_threaded_restart_timer;
	struct smc_timer *single_threaded_reached_timer;
	struct smc_timer *single_threaded_waiting_timer;
	struct smc_thread_safe_timer *shared_local_transfer_timer;
	struct smc_thread_safe_timer *shared_transfer_timer;
	struct smc_thread_safe_timer *shared_targets_timer;
	struct smc_thread_safe_timer *shared_on_event_timer;
	struct smc_thread_safe_timer *shared_waiting_timer;
	struct smc_thread_safe_timer *hint_timer;
	bool iteration_going;
	const char *smc_target_dir;
	bool smc_target_coverage;
	const char *store_progress_file;
	const char *wrapper_dir;
};

union smc_algorithm_data {
	struct smc_dynamic_algorithm dynamic;
};

struct smc_algorithm {
	enum smc_algorithm_type type;
	union smc_algorithm_data data;
};

void smc_init_alg_thread_locals(void);

void smc_alg_on_event(struct smc_algorithm *algorithm,
			    const struct smc_event *event,
			    struct smc_thread_handle *handle);
bool smc_alg_on_finalize(struct smc_algorithm *algorithm);
int smc_alg_start_iteration(struct smc_algorithm *algorithm);
enum smc_iteration_result smc_alg_finish_iteration(
	struct smc_algorithm *algorithm);
enum smc_iteration_phase smc_alg_get_phase(struct smc_algorithm *algorithm);
bool smc_alg_restart_required(struct smc_algorithm *algorithm);
enum smc_waitlist_type smc_alg_get_waitlist_type(
	struct smc_algorithm *algorithm);
int smc_alg_set_waitlist_type(struct smc_algorithm *algorithm,
			      enum smc_waitlist_type type);

void smc_dyn_alg_init(struct smc_dynamic_algorithm *algorithm,
				struct smc_dynamic_analysis *analysis);
void smc_dyn_alg_destroy(struct smc_dynamic_algorithm *algorithm);
void smc_dyn_alg_init_thread_local(
	struct smc_dynamic_algorithm *algorithm);
void smc_dyn_alg_restart_thread_data(
	struct smc_dynamic_algorithm *algorithm);
bool smc_dyn_alg_restart(struct smc_dynamic_algorithm *algorithm,
				   struct smc_thread_handle *handle);
void smc_dyn_alg_start_iteration(
	struct smc_dynamic_algorithm *algorithm);
void smc_dyn_alg_finish_iteration(
	struct smc_dynamic_algorithm *algorithm,
	struct smc_thread_handle *handle);
size_t smc_dyn_alg_mutate_target(
	struct smc_dynamic_algorithm *algorithm, unsigned char *data,
	size_t size, size_t max_size, smc_mutation_state_t state,
	struct smc_thread_handle *handle);
smc_mutation_state_t smc_dyn_alg_pop_target_successors(
	struct smc_dynamic_algorithm *algorithm);
size_t smc_dyn_alg_get_initial_target_as_binary_data(
	struct smc_dynamic_algorithm *algorithm, unsigned char *data,
	size_t size);
void smc_dyn_alg_on_event(struct smc_dynamic_algorithm *algorithm,
				    const struct smc_event *event,
				    struct smc_thread_handle *handle);
bool smc_dyn_alg_on_finalize(
	struct smc_dynamic_algorithm *algorithm);

void smc_dyn_alg_print_statistics(
	struct smc_dynamic_algorithm *algorithm, bool total);
bool smc_dyn_alg_should_break(
	struct smc_dynamic_algorithm *algorithm, struct smc_target *target);
void smc_dyn_alg_dump_target(
	struct smc_dynamic_algorithm *algorithm, struct smc_target *target);
struct smc_target *smc_dyn_alg_read_target_from_file(
	struct smc_dynamic_algorithm *algorithm, const char *name);
bool smc_dyn_alg_save_coverage_info(
	struct smc_dynamic_algorithm *algorithm, struct smc_target *target);
void smc_dyn_alg_add_to_coverage(
	struct smc_dynamic_algorithm *algorithm, const struct smc_event *event);
void smc_dyn_alg_set_next_target(
	struct smc_dynamic_algorithm *algorithm, struct smc_target *target);
void smc_dyn_alg_reset_current_coverage(
	struct smc_dynamic_algorithm *algorithm);

#endif /* C_SMC_ALGORITHM_H */
