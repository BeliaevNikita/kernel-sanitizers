// SPDX-License-Identifier: GPL-2.0
#include "ktsan.h"

#include <linux/preempt.h>

static void kt_tame_acquire_and_release_clocks(kt_thr_t *thr)
{
	if (thr->acquire_active)
		thr->acquire_active--;

	if (thr->release_active)
		thr->release_active--;
}

void kt_func_entry(kt_thr_t *thr, uptr_t pc)
{
	kt_stat_inc(kt_stat_func_entry);

	kt_trace_add_event(thr, kt_event_func_enter, kt_compress(pc));
	/* RACE HUNTER: callstack-compatible function entry event. */
	kt_rh_function_entry(thr, pc);

	kt_stack_push(&thr->stack, pc);

	kt_tame_acquire_and_release_clocks(thr);
}

void kt_func_exit(kt_thr_t *thr)
{
	kt_stat_inc(kt_stat_func_exit);

	kt_trace_add_event(thr, kt_event_func_exit, 0);
	/* RACE HUNTER: callstack-compatible function exit event. */
	kt_rh_function_exit(thr);

	kt_stack_pop(&thr->stack);

	kt_tame_acquire_and_release_clocks(thr);
}
