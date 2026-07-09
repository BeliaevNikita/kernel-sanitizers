/*
Я не делал аналог конструкторов, потому что решил,
что в ядре можно просто проиницилизировать поля
в ктсане было тоже инициализация полей прямо в функции
*/

#ifndef C_SMC_EVENT_H
#define C_SMC_EVENT_H

#include <linux/types.h>

typedef unsigned long smc_uptr_t;

struct smc_thread_state;
struct smc_mutex_set;
struct smc_shared_context;

typedef __u32 smc_pc_shadow_t;

enum smc_access_type {
	SMC_ACCESS_REGULAR,
	SMC_ACCESS_IMITATE,
	SMC_ACCESS_RESET,
};

enum smc_event_type {
	SMC_INFO_EVENT_TYPE,
	SMC_EFFECT_EVENT_TYPE,
	SMC_MARK_EVENT_TYPE,
	SMC_MEM_ACCESS_TYPE,
	SMC_SHARED_MEM_ACCESS_TYPE,
	SMC_THREAD_CREATE_TYPE,
	SMC_THREAD_START_TYPE,
	SMC_THREAD_FINISH_TYPE,
	SMC_THREAD_JOIN_TYPE,
	SMC_FUNCTION_ENTRY_TYPE,
	SMC_FUNCTION_EXIT_TYPE,
	SMC_FENCE_TYPE,
	SMC_PRELOCK_TYPE,
};

struct smc_sync_event {
	unsigned int id;
	bool is_start;
};

struct smc_mark_event_int {
	smc_uptr_t pc;
	int mark;
};

struct smc_info_event_int {
	struct smc_sync_event base;
	int info;
};

struct smc_effect_event {
	struct smc_sync_event base;
};

struct smc_thread_event {
	smc_uptr_t id;
};

struct smc_thread_finish_event {
	smc_uptr_t id;
};

struct smc_thread_create_event {
	smc_uptr_t parent;
	smc_uptr_t child;
	smc_uptr_t pc;
};

struct smc_thread_start_event {
	struct smc_thread_event base;
};

struct smc_thread_join_event {
	struct smc_thread_event base;
};

struct smc_function_entry_event {
	smc_uptr_t pc;
};

struct smc_function_exit_event {
	unsigned char unused;
};

struct smc_mem_access {
	smc_uptr_t pc;
	smc_uptr_t addr;
	smc_uptr_t size;
	bool is_read;
	bool is_atomic;
	enum smc_access_type typ;
};

struct smc_shared_mem_access {
	smc_uptr_t prev_pc;
	smc_uptr_t cur_pc;
	int epoch_diff;
	struct smc_shared_context *context;
};

struct smc_fence_event {
	smc_uptr_t pc;
};

struct smc_prelock_event {
	unsigned char unused;
};

union smc_event_data {
	struct smc_mark_event_int mark_int;
	struct smc_info_event_int info_int;
	struct smc_effect_event effect;
	struct smc_thread_finish_event thread_finish;
	struct smc_thread_create_event thread_create;
	struct smc_thread_start_event thread_start;
	struct smc_thread_join_event thread_join;
	struct smc_function_entry_event function_entry;
	struct smc_function_exit_event function_exit;
	struct smc_mem_access mem_access;
	struct smc_shared_mem_access shared_mem_access;
	struct smc_fence_event fence;
	struct smc_prelock_event prelock;
};

struct smc_event {
	enum smc_event_type type;
	union smc_event_data data;
};

// не уверен, что нужны принт функции
void smc_print_pc(struct smc_thread_state *thr, const char *desc,
		  smc_uptr_t pc);
void smc_print_mset(const struct smc_mutex_set *mset);
bool smc_mset_intersect(const struct smc_mutex_set *mset0,
			const struct smc_mutex_set *mset1);

void smc_event_print(const struct smc_event *event);

void smc_sync_event_print(const struct smc_sync_event *event);

void smc_mark_event_int_print(const struct smc_mark_event_int *event);

void smc_info_event_int_print(const struct smc_info_event_int *event);

void smc_effect_event_print(const struct smc_effect_event *event);

void smc_thread_finish_event_print(
	const struct smc_thread_finish_event *event);

void smc_thread_create_event_print(
	const struct smc_thread_create_event *event);

void smc_thread_start_event_print(const struct smc_thread_start_event *event);

void smc_thread_join_event_print(const struct smc_thread_join_event *event);

void smc_function_entry_event_print(
	const struct smc_function_entry_event *event);

void smc_function_exit_event_print(
	const struct smc_function_exit_event *event);

void smc_mem_access_print(const struct smc_mem_access *event);
bool smc_mem_access_intersects_old(const struct smc_mem_access *event,
				   smc_uptr_t old_addr, bool old_is_read,
				   bool old_is_atomic, smc_uptr_t old_size);
bool smc_mem_access_intersects(const struct smc_mem_access *event,
			       const struct smc_mem_access *other);
bool smc_mem_access_equals(const struct smc_mem_access *event,
			   const struct smc_mem_access *other);
struct smc_mem_access *
smc_mem_access_copy(const struct smc_mem_access *event);

smc_pc_shadow_t
smc_shared_mem_access_get_pc_shadow(
	const struct smc_shared_mem_access *event);
smc_uptr_t
smc_shared_mem_access_calculate_prev_pc(
	const struct smc_shared_mem_access *event);
void smc_shared_mem_access_print(const struct smc_shared_mem_access *event);

void smc_fence_event_print(const struct smc_fence_event *event);

void smc_prelock_event_print(const struct smc_prelock_event *event);

#endif /* C_SMC_EVENT_H */
