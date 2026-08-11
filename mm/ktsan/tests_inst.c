// SPDX-License-Identifier: GPL-2.0
#include "ktsan.h"

#include <linux/kernel.h>
#include <linux/sched.h>

/* Minimal userspace-driven SMC demonstration workload. */
static volatile int kt_smc_race_value;

static noinline int kt_smc_race_load(void)
{
	kt_thr_t *thr;
	int value = kt_smc_race_value;

	thr = current->ktsan.task ? current->ktsan.task->thr : NULL;
	kt_rh_mem_access(thr, (uptr_t)kt_smc_race_load,
			 (uptr_t)&kt_smc_race_value, sizeof(kt_smc_race_value),
			 true, false, 0);
	return value;
}

static noinline void kt_smc_race_store(int value)
{
	kt_thr_t *thr;

	kt_smc_race_value = value;
	thr = current->ktsan.task ? current->ktsan.task->thr : NULL;
	kt_rh_mem_access(thr, (uptr_t)kt_smc_race_store,
			 (uptr_t)&kt_smc_race_value, sizeof(kt_smc_race_value),
			 false, false, 0);
}

int kt_smc_race_test_read(unsigned int iterations)
{
	unsigned int i;
	int value = 0;

	for (i = 0; i < iterations; i++) {
		value ^= kt_smc_race_load();
		kt_smc_race_store(i);
		cond_resched();
	}
	return value;
}

void kt_smc_race_test_write(unsigned int iterations)
{
	kt_thr_t *thr;
	unsigned int i;

	thr = current->ktsan.task ? current->ktsan.task->thr : NULL;
	kt_rh_test_shared_mem_access(thr, (uptr_t)kt_smc_race_load,
				     (uptr_t)kt_smc_race_store);
	for (i = 0; i < iterations; i++) {
		(void)kt_smc_race_load();
		kt_smc_race_store(i);
		cond_resched();
	}
}
