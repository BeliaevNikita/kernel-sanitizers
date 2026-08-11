#ifndef C_SMC_MINIMAL_H
#define C_SMC_MINIMAL_H

#include <linux/atomic.h>
#include <linux/types.h>

struct smc_event;
struct smc_algorithm;
struct smc_dynamic_algorithm;
struct smc_local_state;
struct smc_wait_action;

struct smc_thread_handle {
	u32 id;
	atomic64_t events;
	void *thread;
	struct smc_local_state *local_state;
	u32 local_state_generation;
	struct smc_wait_action *pending_wait_action;
	struct smc_dynamic_algorithm *pending_wait_algorithm;
};

void smc_minimal_init(struct smc_algorithm **algorithm);
void smc_thread_handle_init(struct smc_thread_handle *handle, u32 id);
void smc_thread_handle_destroy(struct smc_thread_handle *handle);
void smc_thread_handle_process_wait(struct smc_thread_handle *handle);
void smc_alg_on_event(struct smc_algorithm *algorithm,
			    const struct smc_event *event,
			    struct smc_thread_handle *handle);
void smc_minimal_print_and_reset_statistics(void);

#endif
