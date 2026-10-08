// SPDX-License-Identifier: GPL-2.0
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/bitmap.h>
#include "ktsan.h"
#include "c_smc_algorithm.h"
#include "c_smc_log.h"
#include "c_smc_watchpoint.h"

#define MAX_PIDS 512

static int ktsan_target_pids[MAX_PIDS];
static int ktsan_num_pids = 0;
static bool ktsan_pid_filter_enabled = true;

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
	kt_rh_print_and_reset_pc_statistics();
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

    if (!READ_ONCE(ktsan_pid_filter_enabled))
        return true;
    
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

static ssize_t pid_filter_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 READ_ONCE(ktsan_pid_filter_enabled));
}

static ssize_t pid_filter_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	bool enabled;

	if (kstrtobool(buf, &enabled))
		return -EINVAL;
	WRITE_ONCE(ktsan_pid_filter_enabled, enabled);
	pr_info("KTSAN: PID filtering %s\n", enabled ? "enabled" : "disabled");
	return count;
}

static struct kobj_attribute pid_filter_attribute =
	__ATTR(pid_filter, 0644, pid_filter_show, pid_filter_store);

static ssize_t pc_mode_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%s\n",
		kt_rh_get_pc_mode() == KT_RH_PC_MODE_RING ? "ring" : "hash");
}

static ssize_t pc_mode_store(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	enum kt_rh_pc_mode mode;
	int ret;

	if (sysfs_streq(buf, "hash"))
		mode = KT_RH_PC_MODE_HASH;
	else if (sysfs_streq(buf, "ring"))
		mode = KT_RH_PC_MODE_RING;
	else
		return -EINVAL;
	ret = kt_rh_set_pc_mode(mode);
	if (ret)
		return ret;
	pr_info("KTSAN: PC storage mode set to %s\n",
		mode == KT_RH_PC_MODE_RING ? "ring" : "hash");
	return count;
}

static struct kobj_attribute pc_mode_attribute =
	__ATTR(pc_mode, 0644, pc_mode_show, pc_mode_store);

static ssize_t waitlist_mode_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%s\n",
		smc_alg_get_waitlist_type(kt_ctx.smc_algorithm) ==
		SMC_WAITLIST_TARGET_DIFFERENCE ? "fitness" : "dfs");
}

static ssize_t waitlist_mode_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	enum smc_waitlist_type type;
	int ret;

	if (sysfs_streq(buf, "dfs"))
		type = SMC_WAITLIST_DFS;
	else if (sysfs_streq(buf, "fitness"))
		type = SMC_WAITLIST_TARGET_DIFFERENCE;
	else
		return -EINVAL;
	ret = smc_alg_set_waitlist_type(kt_ctx.smc_algorithm, type);
	if (ret)
		return ret;
	pr_info("KTSAN SMC: waitlist mode set to %s\n",
		type == SMC_WAITLIST_TARGET_DIFFERENCE ? "fitness" : "dfs");
	return count;
}

static struct kobj_attribute waitlist_mode_attribute =
	__ATTR(waitlist_mode, 0644, waitlist_mode_show, waitlist_mode_store);

static struct smc_watchpoint_analysis *ktsan_watchpoint_analysis(void)
{
	struct smc_algorithm *algorithm = kt_ctx.smc_algorithm;
	struct smc_dynamic_analysis *analysis;

	if (!algorithm || algorithm->type != SMC_ALGORITHM_DYNAMIC)
		return NULL;
	analysis = algorithm->data.dynamic.analysis;
	if (!analysis || analysis->type != SMC_DYNAMIC_ANALYSIS_WATCHPOINT)
		return NULL;
	return container_of(analysis, struct smc_watchpoint_analysis, base);
}

static ssize_t fitness_limit_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	struct smc_watchpoint_analysis *analysis = ktsan_watchpoint_analysis();

	if (!analysis)
		return -ENODEV;
	return scnprintf(buf, PAGE_SIZE, "%d\n",
		smc_watchpoint_an_get_fitness_limit(analysis));
}

static ssize_t fitness_limit_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	struct smc_watchpoint_analysis *analysis = ktsan_watchpoint_analysis();
	struct smc_dynamic_algorithm *dynamic;
	unsigned int limit;
	bool initial_collecting;
	int ret;

	if (!analysis)
		return -ENODEV;
	if (kstrtouint(buf, 10, &limit) ||
	    limit >= (1U << (RH_KT_CLOCK_BITS - 1)))
		return -EINVAL;
	dynamic = &kt_ctx.smc_algorithm->data.dynamic;
	initial_collecting = dynamic->phase == SMC_PHASE_COLLECTING &&
		dynamic->iteration_id == 1 &&
		kt_atomic32_load_no_ktsan(&dynamic->active_events) == 0;
	if (!initial_collecting && dynamic->phase != SMC_PHASE_IDLE &&
	    dynamic->phase != SMC_PHASE_COMPLETE)
		return -EBUSY;
	ret = smc_watchpoint_an_set_fitness_limit(analysis, (int)limit);
	if (ret)
		return ret;
	pr_info("KTSAN SMC: fitness limit set to %u\n", limit);
	return count;
}

static struct kobj_attribute fitness_limit_attribute =
	__ATTR(fitness_limit, 0644, fitness_limit_show, fitness_limit_store);

static const char *smc_phase_name(enum smc_iteration_phase phase)
{
	switch (phase) {
	case SMC_PHASE_IDLE: return "idle";
	case SMC_PHASE_COLLECTING: return "collecting";
	case SMC_PHASE_TARGET: return "target";
	case SMC_PHASE_FINISHING: return "finishing";
	case SMC_PHASE_COMPLETE: return "complete";
	case SMC_PHASE_COUNT: return "invalid";
	}
	return "unknown";
}

static ssize_t smc_control_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	struct smc_algorithm *algorithm = kt_ctx.smc_algorithm;
	struct smc_dynamic_algorithm *dynamic;
	struct smc_watchpoint_analysis *watchpoint;
	u64 dropped_other;
	u64 dropped_event_callbacks = 0;
	u64 processed_events;
	unsigned int i;

	if (!algorithm)
		return scnprintf(buf, PAGE_SIZE, "unavailable\n");
	smc_log_flush();
	dynamic = &algorithm->data.dynamic;
	watchpoint = ktsan_watchpoint_analysis();
	dropped_other = kt_atomic64_load_no_ktsan(
		&dynamic->iteration_dropped_by_type[SMC_DROP_COMPLETION]);
	for (i = 0; i < SMC_EVENT_TYPE_COUNT; i++) {
		dropped_event_callbacks += kt_atomic64_load_no_ktsan(
			&dynamic->iteration_dropped_by_type[i]);
		if (i != SMC_MEM_ACCESS_TYPE && i != SMC_SHARED_MEM_ACCESS_TYPE &&
		    i != SMC_FENCE_TYPE)
			dropped_other += kt_atomic64_load_no_ktsan(
				&dynamic->iteration_dropped_by_type[i]);
	}
	processed_events = dynamic->iteration_event_attempts >=
		dropped_event_callbacks ? dynamic->iteration_event_attempts -
		dropped_event_callbacks : 0;
	return scnprintf(buf, PAGE_SIZE,
		"phase=%s iteration=%llu restart_required=%d stop_requested=%d queued=%u temporary=%lu result=%d waitlist=%s fitness_limit=%d analysis_valid=%d dropped_events=%llu total_events=%llu processed_events=%llu dropped_event_callbacks=%llu dropped_mem=%llu dropped_shared=%llu dropped_fence=%llu dropped_other=%llu dropped_collecting=%llu dropped_target=%llu dropped_finishing=%llu\n",
		smc_phase_name(smc_alg_get_phase(algorithm)), dynamic->iteration_id,
		smc_alg_restart_required(algorithm), dynamic->stop_requested,
		smc_waitlist_size(dynamic->waitlist),
		(unsigned long)smc_ilist_size(&dynamic->iteration_targets),
		dynamic->iteration_result,
		smc_alg_get_waitlist_type(algorithm) ==
			SMC_WAITLIST_TARGET_DIFFERENCE ? "fitness" : "dfs",
		watchpoint ? smc_watchpoint_an_get_fitness_limit(watchpoint) : 0,
		(dynamic->phase == SMC_PHASE_IDLE || dynamic->phase == SMC_PHASE_COMPLETE) &&
			dynamic->iteration_result != SMC_ITERATION_NONE &&
			dynamic->iteration_result != SMC_ITERATION_ABORTED &&
			dynamic->iteration_result != SMC_ITERATION_CONTENDED,
		dynamic->iteration_dropped_events,
		dynamic->iteration_event_attempts, processed_events,
		dropped_event_callbacks,
		kt_atomic64_load_no_ktsan(&dynamic->iteration_dropped_by_type[
			SMC_MEM_ACCESS_TYPE]),
		kt_atomic64_load_no_ktsan(&dynamic->iteration_dropped_by_type[
			SMC_SHARED_MEM_ACCESS_TYPE]),
		kt_atomic64_load_no_ktsan(&dynamic->iteration_dropped_by_type[
			SMC_FENCE_TYPE]), dropped_other,
		kt_atomic64_load_no_ktsan(&dynamic->iteration_dropped_by_phase[
			SMC_PHASE_COLLECTING]),
		kt_atomic64_load_no_ktsan(&dynamic->iteration_dropped_by_phase[
			SMC_PHASE_TARGET]),
		kt_atomic64_load_no_ktsan(&dynamic->iteration_dropped_by_phase[
			SMC_PHASE_FINISHING]));
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

static ssize_t benchmark_mode_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buf)
{
	if (!kt_ctx.enabled)
		return scnprintf(buf, PAGE_SIZE, "invalid-disabled-ktsan\n");
	return scnprintf(buf, PAGE_SIZE, "%s\n",
			 KT_ENABLE_RACE_HUNTER ? "ktsan_rh" : "ktsan");
}

static struct kobj_attribute benchmark_mode_attribute =
	__ATTR(benchmark_mode, 0444, benchmark_mode_show, NULL);
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
	if (sysfs_create_file(ktsan_kobj, &pid_filter_attribute.attr))
		goto remove_pid;
	if (sysfs_create_file(ktsan_kobj, &pc_mode_attribute.attr))
		goto remove_pid_filter;
	if (sysfs_create_file(ktsan_kobj, &waitlist_mode_attribute.attr))
		goto remove_pc_mode;
	if (sysfs_create_file(ktsan_kobj, &fitness_limit_attribute.attr))
		goto remove_waitlist_mode;
	if (sysfs_create_file(ktsan_kobj, &smc_control_attribute.attr)) {
		goto remove_fitness_limit;
	}
	if (sysfs_create_file(ktsan_kobj, &smc_race_read_attribute.attr))
		goto remove_smc_control;
	if (sysfs_create_file(ktsan_kobj, &smc_race_write_attribute.attr))
		goto remove_smc_race_read;
	if (sysfs_create_file(ktsan_kobj, &benchmark_mode_attribute.attr))
		goto remove_smc_race_write;
    
    pr_info("KTSAN: sysfs interface created at /sys/kernel/ktsan/pid\n");
    pr_info("KTSAN: Usage examples:\n");
    pr_info("  echo 123 > /sys/kernel/ktsan/pid     # Add PID 123\n");
    pr_info("  echo -123 > /sys/kernel/ktsan/pid    # Remove PID 123\n");
    pr_info("  echo clear > /sys/kernel/ktsan/pid   # Clear all PIDs\n");
    pr_info("  echo 123 456 789 > /sys/kernel/ktsan/pid  # Add multiple\n");
	pr_info("  echo 0 > /sys/kernel/ktsan/pid_filter # Disable PID filtering\n");
	pr_info("  echo 1 > /sys/kernel/ktsan/pid_filter # Enable PID filtering\n");
	pr_info("  echo hash > /sys/kernel/ktsan/pc_mode # Use PC hash table\n");
	pr_info("  echo ring > /sys/kernel/ktsan/pc_mode # Store ring index in shadow\n");
	pr_info("  echo fitness > /sys/kernel/ktsan/waitlist_mode # Prioritize fitness\n");
	pr_info("  echo dfs > /sys/kernel/ktsan/waitlist_mode # Use plain DFS\n");
	pr_info("  echo 1000 > /sys/kernel/ktsan/fitness_limit # Set fitness cutoff\n");
	pr_info("  echo finish > /sys/kernel/ktsan/smc_control # finish run\n");
	pr_info("  echo start > /sys/kernel/ktsan/smc_control  # start next target\n");
	pr_info("  cat smc_race_read & echo run > smc_race_write # SMC race test\n");
    
    return 0;

remove_smc_race_write:
	sysfs_remove_file(ktsan_kobj, &smc_race_write_attribute.attr);
remove_smc_race_read:
	sysfs_remove_file(ktsan_kobj, &smc_race_read_attribute.attr);
remove_smc_control:
	sysfs_remove_file(ktsan_kobj, &smc_control_attribute.attr);
remove_fitness_limit:
	sysfs_remove_file(ktsan_kobj, &fitness_limit_attribute.attr);
remove_waitlist_mode:
	sysfs_remove_file(ktsan_kobj, &waitlist_mode_attribute.attr);
remove_pc_mode:
	sysfs_remove_file(ktsan_kobj, &pc_mode_attribute.attr);
remove_pid_filter:
	sysfs_remove_file(ktsan_kobj, &pid_filter_attribute.attr);
remove_pid:
	sysfs_remove_file(ktsan_kobj, &pid_attribute.attr);
	kobject_put(ktsan_kobj);
	return -ENOMEM;
}
late_initcall(ktsan_sysfs_init);
