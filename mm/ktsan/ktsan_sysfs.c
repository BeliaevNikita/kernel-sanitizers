// SPDX-License-Identifier: GPL-2.0
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/sched.h>
#include <linux/slab.h>

#define MAX_PIDS 512

static int ktsan_target_pids[MAX_PIDS];
static int ktsan_num_pids = 0;

EXPORT_SYMBOL(ktsan_target_pids);
EXPORT_SYMBOL(ktsan_num_pids);

extern atomic64_t kt_total_accesses;
extern atomic64_t kt_total_conflict_pairs;
extern atomic64_t kt_total_conflict_pairs_unordered;

extern atomic64_t kt_total_accesses_from_all;
extern atomic64_t kt_total_conflict_pairs_1_tracked;
extern atomic64_t kt_total_conflict_pairs_unordered_1_tracked;
extern atomic64_t kt_total_unique_races;

extern void kt_reset_race_reporting(void);

// Сброс счетчиков
static void reset_ktsan_counters(void)
{
    pr_info("kt_total_accesses: %lld\n", atomic64_read(&kt_total_accesses));
    pr_info("kt_total_conflict_pairs: %lld\n", atomic64_read(&kt_total_conflict_pairs));
	pr_info("kt_total_conflict_pairs_unordered: %lld\n", atomic64_read(&kt_total_conflict_pairs_unordered));
    pr_info("kt_total_accesses_from_all: %lld\n", atomic64_read(&kt_total_accesses_from_all));
    pr_info("kt_total_conflict_pairs_1_tracked: %lld\n", atomic64_read(&kt_total_conflict_pairs_1_tracked));
    pr_info("kt_total_conflict_pairs_unordered_1_tracked: %lld\n", atomic64_read(&kt_total_conflict_pairs_unordered_1_tracked));
    pr_info("kt_total_unique_races: %lld\n", atomic64_read(&kt_total_unique_races));
    atomic64_set(&kt_total_accesses, 0);
    atomic64_set(&kt_total_unique_races, 0);
    atomic64_set(&kt_total_conflict_pairs, 0);
    atomic64_set(&kt_total_conflict_pairs_unordered, 0);
    atomic64_set(&kt_total_accesses_from_all, 0);
    atomic64_set(&kt_total_conflict_pairs_1_tracked, 0);
    atomic64_set(&kt_total_conflict_pairs_unordered_1_tracked, 0);
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
    
    pr_info("KTSAN: sysfs interface created at /sys/kernel/ktsan/pid\n");
    pr_info("KTSAN: Usage examples:\n");
    pr_info("  echo 123 > /sys/kernel/ktsan/pid     # Add PID 123\n");
    pr_info("  echo -123 > /sys/kernel/ktsan/pid    # Remove PID 123\n");
    pr_info("  echo clear > /sys/kernel/ktsan/pid   # Clear all PIDs\n");
    pr_info("  echo 123 456 789 > /sys/kernel/ktsan/pid  # Add multiple\n");
    
    return 0;
}
late_initcall(ktsan_sysfs_init);