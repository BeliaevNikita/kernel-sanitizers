// SPDX-License-Identifier: GPL-2.0
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/bitmap.h>
#include "ktsan.h"
#include "c_smc_algorithm.h"

#define MAX_PIDS 512

static int ktsan_target_pids[MAX_PIDS];
static int ktsan_num_pids = 0;

EXPORT_SYMBOL(ktsan_target_pids);
EXPORT_SYMBOL(ktsan_num_pids);

// extern atomic64_t kt_total_accesses;
// extern atomic64_t kt_total_conflict_pairs;
// extern atomic64_t kt_total_conflict_pairs_unordered;

// extern atomic64_t kt_total_accesses_from_all;
// extern atomic64_t kt_total_conflict_pairs_1_tracked;
// extern atomic64_t kt_total_conflict_pairs_unordered_1_tracked;
// extern atomic64_t kt_total_unique_races;
extern atomic64_t kt_max_shadow_clock;
extern unsigned long kt_test_tids[];

extern void kt_reset_race_reporting(void);

static void print_and_reset_test_tids(void)
{
	char buf[256];
	int offset = 0;
	int tid;
	bool any = false;

	offset += scnprintf(buf + offset, sizeof(buf) - offset,
			    "kt_test_tids:");
	for (tid = 0; tid < KT_MAX_THREAD_COUNT; tid++) {
		if (!test_bit(tid, kt_test_tids))
			continue;
		any = true;
		if (offset > sizeof(buf) - 16) {
			pr_info("%s\n", buf);
			offset = scnprintf(buf, sizeof(buf), "kt_test_tids:");
		}
		offset += scnprintf(buf + offset, sizeof(buf) - offset, " %d", tid);
	}
	if (!any)
		offset += scnprintf(buf + offset, sizeof(buf) - offset, " none");
	pr_info("%s\n", buf);
	bitmap_zero(kt_test_tids, KT_MAX_THREAD_COUNT);
}

// Сброс счетчиков
static void reset_ktsan_counters(void)
{
	smc_minimal_print_and_reset_statistics();
    // pr_info("kt_total_accesses: %lld\n", atomic64_read(&kt_total_accesses));
    // pr_info("kt_total_conflict_pairs: %lld\n", atomic64_read(&kt_total_conflict_pairs));
	// pr_info("kt_total_conflict_pairs_unordered: %lld\n", atomic64_read(&kt_total_conflict_pairs_unordered));
    // pr_info("kt_total_accesses_from_all: %lld\n", atomic64_read(&kt_total_accesses_from_all));
    // pr_info("kt_total_conflict_pairs_1_tracked: %lld\n", atomic64_read(&kt_total_conflict_pairs_1_tracked));
    // pr_info("kt_total_conflict_pairs_unordered_1_tracked: %lld\n", atomic64_read(&kt_total_conflict_pairs_unordered_1_tracked));
    // pr_info("kt_total_unique_races: %lld\n", atomic64_read(&kt_total_unique_races));
    // pr_info("kt_max_shadow_clock: %lld\n", atomic64_read(&kt_max_shadow_clock));
    print_and_reset_test_tids();
    // atomic64_set(&kt_total_accesses, 0);
    // atomic64_set(&kt_total_unique_races, 0);
    // atomic64_set(&kt_max_shadow_clock, 0);
    // atomic64_set(&kt_total_conflict_pairs, 0);
    // atomic64_set(&kt_total_conflict_pairs_unordered, 0);
    // atomic64_set(&kt_total_accesses_from_all, 0);
    // atomic64_set(&kt_total_conflict_pairs_1_tracked, 0);
    // atomic64_set(&kt_total_conflict_pairs_unordered_1_tracked, 0);
    pr_info("KTSAN: Reset total_accesses and total_conflict_pairs to 0\n");
    
    kt_reset_race_reporting();
}

// Функция для проверки, нужно ли отслеживать PID
bool is_ktsan_tracked(pid_t pid)
{
    bool tracked = false;
    int i;
    
    for (i = 0; i < ktsan_num_pids; i++) {
        if (ktsan_target_pids[i] == pid) {
            tracked = true;
            break;
        }
    }
    
    return tracked;
}
EXPORT_SYMBOL(is_ktsan_tracked);

// Добавить PID
static int add_pid(int pid)
{
    int i;
    
    if (pid <= 0)
        return -EINVAL;
    
    
    // Проверяем, не существует ли уже
    for (i = 0; i < ktsan_num_pids; i++) {
        if (ktsan_target_pids[i] == pid) {
            return -EEXIST;
        }
    }
    
    if (ktsan_num_pids >= MAX_PIDS) {
        return -ENOSPC;
    }
    
    ktsan_target_pids[ktsan_num_pids++] = pid;
    pr_info("KTSAN: Added PID %d to tracking list (total: %d)\n", 
            pid, ktsan_num_pids);
    
    return 0;
}

// Удалить PID
static int remove_pid(int pid)
{
    int i, found = 0;
    
    
    for (i = 0; i < ktsan_num_pids; i++) {
        if (ktsan_target_pids[i] == pid) {
            found = 1;
            break;
        }
    }
    
    if (!found) {
        return -ENOENT;
    }
    
    // Сдвигаем оставшиеся элементы
    for (; i < ktsan_num_pids - 1; i++) {
        ktsan_target_pids[i] = ktsan_target_pids[i + 1];
    }
    ktsan_num_pids--;
    
    pr_info("KTSAN: Removed PID %d from tracking list (remaining: %d)\n", 
            pid, ktsan_num_pids);
    
    return 0;
}

// Очистить все PID
static void clear_all_pids(void)
{
    ktsan_num_pids = 0;
    pr_info("KTSAN: Cleared all PIDs from tracking list\n");
}

// Показать список PID
static ssize_t pid_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int i, offset = 0;
    
    
    if (ktsan_num_pids == 0) {
        offset = sprintf(buf, "none\n");
    } else {
        for (i = 0; i < ktsan_num_pids; i++) {
            offset += sprintf(buf + offset, "%d ", ktsan_target_pids[i]);
        }
        offset += sprintf(buf + offset, "\n");
    }
    
    return offset;
}

// Форматы ввода:
// 0 - Сброс счетчиков kt_total_accesses, kt_total_conflict_pairs
// "123" - добавить PID 123
// "-123" - удалить PID 123
// "clear" - очистить все
// "123,456,789" - добавить несколько (необязательно)
static ssize_t pid_store(struct kobject *kobj, struct kobj_attribute *attr,
                         const char *buf, size_t count)
{
    char *copy, *token;
    int ret = 0;
    
    copy = kstrdup(buf, GFP_KERNEL);
    if (!copy)
        return -ENOMEM;
    
    // Обработка команды "clear"
    if (strncmp(copy, "clear", 5) == 0) {
        clear_all_pids();
        goto out;
    }
    
    // Разбор по пробелам и запятым
    token = strsep(&copy, " ,\n");
    while (token && *token) {
        int pid;
        
        ret = kstrtoint(token, 10, &pid);
        if (ret)
            goto out;
        
        if (pid > 0) {
            add_pid(pid);
        } else if (pid < 0) {
            remove_pid(-pid);
        } else {
            reset_ktsan_counters();
        }
        
        token = strsep(&copy, " ,\n");
    }
    
out:
    kfree(copy);
    return count;
}

static struct kobj_attribute pid_attribute = __ATTR(pid, 0644, pid_show, pid_store);

static const char *smc_phase_name(enum smc_iteration_phase phase)
{
	switch (phase) {
	case SMC_PHASE_IDLE: return "idle";
	case SMC_PHASE_COLLECTING: return "collecting";
	case SMC_PHASE_TARGET: return "target";
	case SMC_PHASE_FINISHING: return "finishing";
	case SMC_PHASE_COMPLETE: return "complete";
	}
	return "unknown";
}

static ssize_t smc_control_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	struct smc_algorithm *algorithm = kt_ctx.smc_algorithm;
	struct smc_dynamic_algorithm *dynamic;

	if (!algorithm)
		return scnprintf(buf, PAGE_SIZE, "unavailable\n");
	dynamic = &algorithm->data.dynamic;
	return scnprintf(buf, PAGE_SIZE,
		"phase=%s iteration=%llu restart_required=%d stop_requested=%d queued=%u temporary=%lu result=%d\n",
		smc_phase_name(smc_alg_get_phase(algorithm)), dynamic->iteration_id,
		smc_alg_restart_required(algorithm), dynamic->stop_requested,
		smc_waitlist_size(dynamic->waitlist),
		(unsigned long)smc_ilist_size(&dynamic->iteration_targets),
		dynamic->iteration_result);
}

static ssize_t smc_control_store(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 const char *buf, size_t count)
{
	int ret;

	if (!kt_ctx.smc_algorithm)
		return -ENODEV;
	if (sysfs_streq(buf, "start")) {
		ret = smc_alg_start_iteration(kt_ctx.smc_algorithm);
		if (ret)
			return ret;
	} else if (sysfs_streq(buf, "finish")) {
		smc_alg_finish_iteration(kt_ctx.smc_algorithm);
	} else {
		return -EINVAL;
	}
	return count;
}

static struct kobj_attribute smc_control_attribute =
	__ATTR(smc_control, 0644, smc_control_show, smc_control_store);

#define SMC_RACE_TEST_DEFAULT_ITERATIONS 1000U
#define SMC_RACE_TEST_MAX_ITERATIONS 10000000U

static ssize_t smc_race_read_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	int value = kt_smc_race_test_read(SMC_RACE_TEST_DEFAULT_ITERATIONS);

	return scnprintf(buf, PAGE_SIZE, "%d\n", value);
}

static ssize_t smc_race_write_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buf, size_t count)
{
	unsigned int iterations = SMC_RACE_TEST_DEFAULT_ITERATIONS;

	if (!sysfs_streq(buf, "run") &&
	    (kstrtouint(buf, 10, &iterations) || !iterations ||
	     iterations > SMC_RACE_TEST_MAX_ITERATIONS))
		return -EINVAL;
	kt_smc_race_test_write(iterations);
	return count;
}

static struct kobj_attribute smc_race_read_attribute =
	__ATTR(smc_race_read, 0444, smc_race_read_show, NULL);
static struct kobj_attribute smc_race_write_attribute =
	__ATTR(smc_race_write, 0200, NULL, smc_race_write_store);
static struct kobject *ktsan_kobj;

static int __init ktsan_sysfs_init(void)
{
    ktsan_kobj = kobject_create_and_add("ktsan", kernel_kobj);
    if (!ktsan_kobj)
        return -ENOMEM;
    
    if (sysfs_create_file(ktsan_kobj, &pid_attribute.attr)) {
        kobject_put(ktsan_kobj);
        return -ENOMEM;
    }
	if (sysfs_create_file(ktsan_kobj, &smc_control_attribute.attr)) {
		sysfs_remove_file(ktsan_kobj, &pid_attribute.attr);
		kobject_put(ktsan_kobj);
		return -ENOMEM;
	}
	if (sysfs_create_file(ktsan_kobj, &smc_race_read_attribute.attr))
		goto remove_smc_control;
	if (sysfs_create_file(ktsan_kobj, &smc_race_write_attribute.attr))
		goto remove_smc_race_read;
    
    pr_info("KTSAN: sysfs interface created at /sys/kernel/ktsan/pid\n");
    pr_info("KTSAN: Usage examples:\n");
    pr_info("  echo 123 > /sys/kernel/ktsan/pid     # Add PID 123\n");
    pr_info("  echo -123 > /sys/kernel/ktsan/pid    # Remove PID 123\n");
    pr_info("  echo clear > /sys/kernel/ktsan/pid   # Clear all PIDs\n");
    pr_info("  echo 123 456 789 > /sys/kernel/ktsan/pid  # Add multiple\n");
	pr_info("  echo finish > /sys/kernel/ktsan/smc_control # finish run\n");
	pr_info("  echo start > /sys/kernel/ktsan/smc_control  # start next target\n");
	pr_info("  cat smc_race_read & echo run > smc_race_write # SMC race test\n");
    
    return 0;

remove_smc_race_read:
	sysfs_remove_file(ktsan_kobj, &smc_race_read_attribute.attr);
remove_smc_control:
	sysfs_remove_file(ktsan_kobj, &smc_control_attribute.attr);
	sysfs_remove_file(ktsan_kobj, &pid_attribute.attr);
	kobject_put(ktsan_kobj);
	return -ENOMEM;
}
late_initcall(ktsan_sysfs_init);
