#ifndef C_SMC_ALGORITHM_H
#define C_SMC_ALGORITHM_H

#include <linux/types.h>

#include "c_smc_analysis.h"
#include "c_smc_waitlist.h"
#include "smc_hash_c.h"

struct smc_mutex;
struct smc_timer;
struct smc_thread_safe_timer;

typedef void *smc_mutation_state_t;

enum smc_algorithm_type {
	SMC_ALGORITHM_DYNAMIC,
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
	int prep_iterations;
	struct smc_dynamic_analysis *analysis;
	struct smc_global_state *global_state;
	struct smc_mutex *lock;
	struct smc_target *target;
	enum smc_target_type target_type;
	struct smc_reached_set *reached;
	struct smc_coverage coverage;
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

void smc_init_algorithm_thread_locals(void);

void smc_algorithm_on_event(struct smc_algorithm *algorithm,
			    const struct smc_event *event,
			    struct smc_thread_handle *handle);
bool smc_algorithm_on_finalize(struct smc_algorithm *algorithm);

void smc_dynamic_algorithm_init(struct smc_dynamic_algorithm *algorithm,
				struct smc_dynamic_analysis *analysis);
void smc_dynamic_algorithm_destroy(struct smc_dynamic_algorithm *algorithm);
void smc_dynamic_algorithm_init_thread_local(
	struct smc_dynamic_algorithm *algorithm);
void smc_dynamic_algorithm_restart_thread_data(
	struct smc_dynamic_algorithm *algorithm);
bool smc_dynamic_algorithm_restart(struct smc_dynamic_algorithm *algorithm,
				   struct smc_thread_handle *handle);
void smc_dynamic_algorithm_start_iteration(
	struct smc_dynamic_algorithm *algorithm);
void smc_dynamic_algorithm_finish_iteration(
	struct smc_dynamic_algorithm *algorithm,
	struct smc_thread_handle *handle);
size_t smc_dynamic_algorithm_mutate_target(
	struct smc_dynamic_algorithm *algorithm, unsigned char *data,
	size_t size, size_t max_size, smc_mutation_state_t state,
	struct smc_thread_handle *handle);
smc_mutation_state_t smc_dynamic_algorithm_pop_target_successors(
	struct smc_dynamic_algorithm *algorithm);
size_t smc_dynamic_algorithm_get_initial_target_as_binary_data(
	struct smc_dynamic_algorithm *algorithm, unsigned char *data,
	size_t size);
void smc_dynamic_algorithm_on_event(struct smc_dynamic_algorithm *algorithm,
				    const struct smc_event *event,
				    struct smc_thread_handle *handle);
bool smc_dynamic_algorithm_on_finalize(
	struct smc_dynamic_algorithm *algorithm);

void smc_dynamic_algorithm_print_statistics(
	struct smc_dynamic_algorithm *algorithm, bool total);
bool smc_dynamic_algorithm_should_break(
	struct smc_dynamic_algorithm *algorithm, struct smc_target *target);
void smc_dynamic_algorithm_dump_target(
	struct smc_dynamic_algorithm *algorithm, struct smc_target *target);
struct smc_target *smc_dynamic_algorithm_read_target_from_file(
	struct smc_dynamic_algorithm *algorithm, const char *name);
bool smc_dynamic_algorithm_save_coverage_info(
	struct smc_dynamic_algorithm *algorithm, struct smc_target *target);
void smc_dynamic_algorithm_add_to_coverage(
	struct smc_dynamic_algorithm *algorithm, const struct smc_event *event);
void smc_dynamic_algorithm_set_next_target(
	struct smc_dynamic_algorithm *algorithm, struct smc_target *target);
void smc_dynamic_algorithm_reset_current_coverage(
	struct smc_dynamic_algorithm *algorithm);

#endif /* C_SMC_ALGORITHM_H */
