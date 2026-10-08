// SPDX-License-Identifier: GPL-2.0
#include "ktsan.h"
#include "c_smc_log.h"

#define SMC_LOG_SLOTS 128
#define SMC_LOG_BYTES 256

static char smc_log_records[SMC_LOG_SLOTS][SMC_LOG_BYTES];
static unsigned int smc_log_head, smc_log_tail, smc_log_count;
static u64 smc_log_dropped;
static kt_spinlock_t smc_log_lock;

void smc_log_record(const char *fmt, ...)
{
	char text[SMC_LOG_BYTES];
	unsigned long flags;
	kt_task_t *task;
	kt_thr_t *thr;
	va_list args;
	int length, i;

	preempt_disable();
	flags = arch_local_irq_save();
	task = current->ktsan.task;
	thr = task ? task->thr : NULL;
	if (thr)
		thr->smc_inside++;
	barrier();
	va_start(args, fmt);
	length = vscnprintf(text, sizeof(text), fmt, args);
	va_end(args);
	if (kt_atomic8_exchange_no_ktsan(&smc_log_lock.state, 1)) {
		kt_atomic64_fetch_add_no_ktsan(&smc_log_dropped, 1);
		goto out;
	}
	if (smc_log_count == SMC_LOG_SLOTS) {
		kt_atomic64_fetch_add_no_ktsan(&smc_log_dropped, 1);
	} else {
		for (i = 0; i <= length; i++)
			((volatile char *)smc_log_records[smc_log_head])[i] = text[i];
		smc_log_head = (smc_log_head + 1) % SMC_LOG_SLOTS;
		smc_log_count++;
	}
	kt_spin_unlock(&smc_log_lock);
out:
	barrier();
	if (thr)
		thr->smc_inside--;
	arch_local_irq_restore(flags);
	preempt_enable();
}

void smc_log_flush(void)
{
	char text[SMC_LOG_BYTES];
	unsigned long flags;
	unsigned int n, i;
	u64 dropped;

	for (n = 0; n < SMC_LOG_SLOTS; n++) {
		preempt_disable();
		flags = arch_local_irq_save();
		if (kt_atomic8_exchange_no_ktsan(&smc_log_lock.state, 1)) {
			arch_local_irq_restore(flags);
			preempt_enable();
			break;
		}
		if (!smc_log_count) {
			kt_spin_unlock(&smc_log_lock);
			arch_local_irq_restore(flags);
			preempt_enable();
			break;
		}
		for (i = 0; i < SMC_LOG_BYTES; i++)
			text[i] = ((volatile char *)smc_log_records[smc_log_tail])[i];
		smc_log_tail = (smc_log_tail + 1) % SMC_LOG_SLOTS;
		smc_log_count--;
		kt_spin_unlock(&smc_log_lock);
		arch_local_irq_restore(flags);
		preempt_enable();
		printk_deferred("%s", text);
	}
	dropped = kt_atomic64_exchange_no_ktsan(&smc_log_dropped, 0);
	if (dropped)
		printk_deferred(KERN_WARNING "KTSAN SMC log: dropped=%llu (buffer full or busy)\n", dropped);
}
