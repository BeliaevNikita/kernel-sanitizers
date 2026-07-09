#ifndef C_SMC_ANALYSIS_H
#define C_SMC_ANALYSIS_H

#include <linux/atomic.h>
#include <linux/list.h>
#include <linux/types.h>

#include "c_smc_data.h"
#include "c_smc_event.h"

struct file;
struct smc_thread_handle;

#define SMC_SERIALIZER_BUFFER_MAX_SIZE (1U << 12)
#define SMC_MAX_FITNESS 1147483647
#define SMC_TARGET_FITNESS_INTERVALS 7
#define SMC_TARGET_REQUEST_STOP ((u32)1 << 31)
#define SMC_TARGET_STOP_VALUE (~(u32)0)

enum smc_serializer_type {
	SMC_SERIALIZER_FILE,
	SMC_SERIALIZER_BUFFER,
};

struct smc_file_serializer {
	struct file *file;
	loff_t pos;
};

struct smc_buffer_serializer {
	unsigned char buffer[SMC_SERIALIZER_BUFFER_MAX_SIZE];
	size_t pos;
	size_t size;
};

union smc_serializer_data {
	struct smc_file_serializer file;
	struct smc_buffer_serializer buffer;
};

struct smc_serializer {
	enum smc_serializer_type type;
	union smc_serializer_data data;
};

enum smc_global_state_type {
	SMC_SYNC_GLOBAL_STATE_TYPE,
	SMC_MARK_GLOBAL_STATE_TYPE,
	SMC_WATCHPOINT_GLOBAL_STATE_TYPE,
	SMC_THREAD_GLOBAL_STATE_TYPE,
	SMC_THREAD_ID_GLOBAL_STATE_TYPE,
	SMC_THREAD_ID_BACKGROUND_GLOBAL_STATE_TYPE,
	SMC_COMPOSITE_GLOBAL_STATE_TYPE,
	SMC_CONTEXT_BOUNDING_STATE_TYPE,
	SMC_DPOR_STATE_TYPE,
};

struct smc_global_state {
	enum smc_global_state_type type;
};

enum smc_local_state_type {
	SMC_SYNC_LOCAL_STATE_TYPE,
	SMC_MARK_LOCAL_STATE_TYPE,
	SMC_WP_LOCAL_STATE_TYPE,
	SMC_CONTEXT_BOUNDING_LOCAL_STATE_TYPE,
	SMC_DPOR_LOCAL_STATE_TYPE,
	SMC_THREAD_LOCAL_STATE_TYPE,
	SMC_THREAD_ID_LOCAL_STATE_TYPE,
	SMC_WRAPPER_LOCAL_STATE_TYPE,
	SMC_COMPOSITE_LOCAL_STATE_TYPE,
	SMC_CALLSTACK_LOCAL_STATE_TYPE,
};

enum smc_compatible_state_type {
	SMC_SYNC_COMPATIBLE_STATE_TYPE,
	SMC_MARK_COMPATIBLE_STATE_TYPE,
	SMC_THREAD_COMPATIBLE_STATE_TYPE,
	SMC_COMPOSITE_COMPATIBLE_STATE_TYPE,
	SMC_CALLSTACK_COMPATIBLE_STATE_TYPE,
};

struct smc_compatible_state {
	enum smc_compatible_state_type type;
};

struct smc_local_state {
	enum smc_local_state_type type;
};

enum smc_target_type {
	SMC_RANDOM_SHARED_TARGET_TYPE,
	SMC_SHARED_TARGET_COLLECTION_TYPE,
	SMC_SHARED_TARGET_MONITORING_TYPE,
	SMC_SHARED_TARGET_INTRUSION_TYPE,
	SMC_SHARED_TARGET_NTH_INTRUSION_TYPE,
	SMC_INTRUSION_GAMETE_TYPE,
	SMC_CONTEXT_BOUNDING_TARGET_TYPE,
	SMC_DPOR_TARGET_TYPE,
	SMC_COMPOSITE_TARGET_TYPE,
	SMC_SYNC_TARGET_TYPE,
};

struct smc_target {
	enum smc_target_type type;
	struct list_head new_targets_list;
	int fitness;
	int raw_fitness;
	bool explored;
	bool reached;
	bool request_stop;
	atomic_t progress_counter;
};

enum smc_wait_action_type {
	SMC_WAIT_ACTION_DEFAULT,
	SMC_WAIT_ACTION_DUMMY,
};

struct smc_wait_action {
	enum smc_wait_action_type type;
	unsigned int timeout;
};

enum smc_dynamic_analysis_type {
	SMC_DYNAMIC_ANALYSIS_WATCHPOINT,
	SMC_DYNAMIC_ANALYSIS_SYNC,
	SMC_DYNAMIC_ANALYSIS_THREAD,
	SMC_DYNAMIC_ANALYSIS_THREAD_ID,
	SMC_DYNAMIC_ANALYSIS_CALLSTACK,
	SMC_DYNAMIC_ANALYSIS_MARK,
	SMC_DYNAMIC_ANALYSIS_CONTEXT_BOUNDING,
	SMC_DYNAMIC_ANALYSIS_DPOR,
	SMC_DYNAMIC_ANALYSIS_COMPOSITE,
	SMC_DYNAMIC_ANALYSIS_WRAPPED,
};

struct smc_dynamic_analysis {
	enum smc_dynamic_analysis_type type;
};

struct smc_thread_id_provider {
	enum smc_dynamic_analysis_type type;
};

void smc_serializer_write_data(struct smc_serializer *serializer,
			       const void *data, size_t size);
void smc_serializer_read_data(struct smc_serializer *serializer,
			      void *data, size_t size);
void smc_file_serializer_open(struct smc_serializer *serializer,
			      struct file *file);
void smc_buffer_serializer_clear(struct smc_serializer *serializer);
void smc_buffer_serializer_load(struct smc_serializer *serializer,
				const void *data, size_t size);
void smc_buffer_serializer_dump_to(const struct smc_serializer *serializer,
				   void *data);
size_t smc_buffer_serializer_get_target_size(
	const struct smc_serializer *serializer);

void smc_global_state_reset(struct smc_global_state *state);
void smc_global_state_print(const struct smc_global_state *state);

void smc_compatible_state_print(const struct smc_compatible_state *state);
bool smc_compatible_state_equals(const struct smc_compatible_state *state,
				 const struct smc_compatible_state *other);
bool smc_compatible_state_compatible(
	const struct smc_compatible_state *state,
	const struct smc_compatible_state *other);
bool smc_compatible_state_is_related(
	const struct smc_compatible_state *state, const struct smc_event *event);
bool smc_compatible_state_is_interesting(
	const struct smc_compatible_state *state);
void smc_compatible_state_serialize(
	const struct smc_compatible_state *state,
	struct smc_serializer *serializer);
struct smc_compatible_state *
smc_compatible_state_copy(const struct smc_compatible_state *state);
struct smc_compatible_state *
smc_compatible_state_deserialize(struct smc_serializer *serializer);

void smc_local_state_print(const struct smc_local_state *state);
struct smc_compatible_state *
smc_local_state_get_compatible_state(const struct smc_local_state *state,
				     struct smc_global_state *global_state);
void smc_local_state_reset(struct smc_local_state *state);

void smc_target_init(struct smc_target *target, enum smc_target_type type,
		     int fitness, bool request_stop);
bool smc_target_is_related(const struct smc_target *target,
			   const struct smc_event *event);
bool smc_target_is_feasible(const struct smc_target *target);
bool smc_target_equals(const struct smc_target *target,
		       const struct smc_target *other);
bool smc_target_merge(struct smc_target *target,
		      const struct smc_target *other);
bool smc_target_set_in_progress(struct smc_target *target);
void smc_target_release(struct smc_target *target);
bool smc_target_try_stop(struct smc_target *target);
void smc_target_restart(struct smc_target *target);
bool smc_target_is_complete(const struct smc_target *target);
struct smc_target *smc_target_copy(const struct smc_target *target);
void smc_target_serialize(const struct smc_target *target,
			  struct smc_serializer *serializer);
struct smc_target *smc_target_deserialize(struct smc_serializer *serializer);
void smc_target_print(const struct smc_target *target);
struct smc_target *smc_target_confirm_by(const struct smc_target *target,
					 const struct smc_target *other);
void smc_target_set_fitness(struct smc_target *target, int raw_fitness);
unsigned int smc_target_convert_fitness(int fitness);

struct smc_wait_action *smc_dummy_wait_action_get_instance(void);
bool smc_wait_action_post_wait(struct smc_wait_action *action, bool result);
void smc_wait_action_cancel(struct smc_wait_action *action);
void smc_wait_action_destroy(struct smc_wait_action *action);

struct smc_target *
smc_dynamic_analysis_get_initial_target(struct smc_dynamic_analysis *analysis);
struct smc_local_state *
smc_dynamic_analysis_get_initial_local_state(
	struct smc_dynamic_analysis *analysis);
struct smc_global_state *
smc_dynamic_analysis_get_initial_global_state(
	struct smc_dynamic_analysis *analysis);
bool smc_dynamic_analysis_local_transfer(
	const struct smc_dynamic_analysis *analysis, const struct smc_event *event,
	struct smc_local_state *local_state);
struct smc_wait_action *smc_dynamic_analysis_transfer(
	struct smc_dynamic_analysis *analysis, struct smc_thread_handle *handle,
	const struct smc_event *event, const struct smc_target *target,
	struct smc_local_state *local_state,
	struct smc_global_state *global_state);
struct smc_ilist *smc_dynamic_analysis_get_new_targets(
	struct smc_dynamic_analysis *analysis, struct smc_thread_handle *handle,
	const struct smc_target *target, const struct smc_event *event,
	struct smc_local_state *local_state,
	struct smc_global_state *global_state);
bool smc_dynamic_analysis_fast_is_related(
	const struct smc_dynamic_analysis *analysis,
	enum smc_event_type event_type);
bool smc_dynamic_analysis_fast_is_related_to_target(
	const struct smc_dynamic_analysis *analysis,
	enum smc_target_type target_type, enum smc_event_type event_type);
void smc_dynamic_analysis_finish_iteration(
	struct smc_dynamic_analysis *analysis,
	struct smc_global_state *global_state, struct smc_target *target);
void smc_dynamic_analysis_start_iteration(
	struct smc_dynamic_analysis *analysis,
	struct smc_global_state *global_state, const struct smc_target *target);
void smc_dynamic_analysis_print_statistics(
	const struct smc_dynamic_analysis *analysis, bool total);
struct smc_wait_action *smc_dynamic_analysis_agree_to_wait(
	struct smc_dynamic_analysis *analysis, struct smc_thread_handle *handle,
	const struct smc_event *event, const struct smc_target *target,
	struct smc_local_state *local_state,
	struct smc_global_state *global_state);
struct smc_target *smc_dynamic_analysis_get_current_target(
	struct smc_dynamic_analysis *analysis, const struct smc_target *target,
	struct smc_local_state *local_state,
	struct smc_global_state *global_state);
smc_uptr_t smc_dynamic_analysis_get_coverage_hash(
	struct smc_dynamic_analysis *analysis, const struct smc_event *event);
struct smc_dynamic_analysis *
smc_dynamic_analysis_create_from_configuration(const char *config);

smc_uptr_t smc_thread_id_provider_get_compatible_id(
	struct smc_thread_id_provider *provider, smc_uptr_t id,
	struct smc_global_state *state);

#endif /* C_SMC_ANALYSIS_H */
