// SPDX-License-Identifier: GPL-2.0
#include "ktsan.h"

#include <linux/kernel.h>
#include <linux/ratelimit.h>
#include <linux/slab.h>

#include "c_smc_watchpoint.h"
#include "c_smc_watchpoint_targets.h"

#define SMC_WP_DEFAULT_LIFE 64
#define SMC_WP_DEFAULT_FITNESS_LIMIT 1000
#define SMC_WP_TARGET_EVENT_LIMIT 4096

/** Берёт @lock слота watchpoint через внутренний спинлок KTSAN. */
static void smc_wp_lock(u8 *lock)
{
	kt_spin_lock((kt_spinlock_t *)lock);
}

/** Освобождает ранее взятый @lock слота watchpoint. */
static void smc_wp_unlock(u8 *lock)
{
	kt_spin_unlock((kt_spinlock_t *)lock);
}

/** Проверяет пересечение полуинтервалов [@a,@a+@as) и [@b,@b+@bs).
 * Нулевой размер означает пустой диапазон. Return: есть ли общие байты. */
static bool smc_ranges_intersect(smc_uptr_t a, smc_uptr_t as,
				 smc_uptr_t b, smc_uptr_t bs)
{
	if (!as || !bs)
		return false;
	return a < b + bs && b < a + as;
}

static struct smc_watchpoint_analysis *
/** Преобразует встроенную базу @base в содержащий smc_watchpoint_analysis.
 * @base обязан действительно быть частью watchpoint analysis. */
smc_to_watchpoint(struct smc_dynamic_analysis *base)
{
	return container_of(base, struct smc_watchpoint_analysis, base);
}

/** Сопоставляет новый @event со старым доступом @old_addr/@old_size и флагами
 * @old_is_read/@old_is_atomic. Два чтения и два atomic не считаются гонкой;
 * иначе проверяется пересечение диапазонов. */
bool smc_mem_access_intersects_old(const struct smc_mem_access *event,
				   smc_uptr_t old_addr, bool old_is_read,
				   bool old_is_atomic, smc_uptr_t old_size)
{
	if (!event || (event->is_read && old_is_read) ||
	    (event->is_atomic && old_is_atomic))
		return false;
	return smc_ranges_intersect(event->addr, event->size, old_addr,
				    old_size);
}

/** Проверяет конфликт и пересечение доступов @event/@other, делегируя полной
 * проверке старого доступа. NULL @other возвращает false. */
bool smc_mem_access_intersects(const struct smc_mem_access *event,
			       const struct smc_mem_access *other)
{
	return other && smc_mem_access_intersects_old(event, other->addr,
			other->is_read, other->is_atomic, other->size);
}

/** Return: полностью ли совпадают @event/@other по PC, адресу, размеру,
 * read/atomic и подтипу доступа; NULL никогда не равен. */
bool smc_mem_access_equals(const struct smc_mem_access *event,
			   const struct smc_mem_access *other)
{
	return event && other && event->pc == other->pc &&
		event->addr == other->addr && event->size == other->size &&
		event->is_read == other->is_read &&
		event->is_atomic == other->is_atomic && event->typ == other->typ;
}

/** Копирует @event через kmemdup(GFP_ATOMIC). Return: отдельный объект,
 * который должен быть kfree(), либо NULL для NULL/ошибки. */
struct smc_mem_access *smc_mem_access_copy(const struct smc_mem_access *event)
{
	return event ? kmemdup(event, sizeof(*event), GFP_ATOMIC) : NULL;
}

/** Хеширует @addr сдвигом и modulo в индекс массива watchpoints. */
static int smc_watchpoint_slot(smc_uptr_t addr)
{
	return (addr >> SMC_WATCHPOINT_SHIFT_ADDR) %
		SMC_CONFIG_NUM_WATCHPOINTS;
}

/** Полностью обнуляет @watchpoint, тем самым помечая слот свободным. */
static void smc_watchpoint_clear(struct smc_watchpoint *watchpoint)
{
	memset(watchpoint, 0, sizeof(*watchpoint));
}

/** Заполняет @info идентификаторами потока @handle_tid и адресом команды @pc;
 * NULL безопасно игнорируется, прочие поля сохраняются. */
void smc_add_race_info(struct smc_other_info *info, u32 handle_tid,
		       smc_uptr_t pc)
{
	if (!info)
		return;
	info->handle_tid = handle_tid;
	info->ktsan_tid = handle_tid;
	info->access_info.pc = pc;
}

/** Печатает один доступ @report в race-report. @is_first начинает сообщение,
 * @is_old помечает старый доступ, @postponed — отложенный; вывод ratelimited. */
void smc_report_race_access(const struct smc_other_info *report,
			    bool is_first, bool is_old, bool postponed)
{
	const struct smc_mem_access *access;

	if (!report)
		return;
	access = &report->access_info;
	pr_err_ratelimited("KTSAN SMC: %s%s%s %s at pc=%px addr=%px/%lu thread=%d\n",
		is_first ? "data race: " : "",
		is_old ? "previous " : "", postponed ? "postponed " : "",
		access->is_read ? "read" : "write", (void *)access->pc,
		(void *)access->addr, access->size, report->handle_tid);
}

/** Очищает список covered-accesses и освобождает postponed в @state.
 * Сам @state освобождает владелец handle. */
void smc_watchpoint_local_state_destroy(struct smc_watchpoint_local_state *state)
{
	if (!state)
		return;
	smc_local_state_destroy(state->inner);
	state->inner = NULL;
	smc_watchpoint_local_state_clear_covered_accesses(state);
	kfree(state->postponed);
	state->postponed = NULL;
}

/** Печатает skip_count и номер события локального @state; NULL игнорируется. */
void smc_watchpoint_local_state_print(
	const struct smc_watchpoint_local_state *state)
{
	if (state)
		pr_info("KTSAN SMC: wp local skip=%d nth=%lu\n",
			state->skip_count, state->nth_event_count);
}

/** Сбрасывает @state к началу итерации: восстанавливает skip_count, обнуляет
 * nth-event и очищает covered/postponed данные. */
void smc_watchpoint_local_state_reset(struct smc_watchpoint_local_state *state)
{
	if (!state)
		return;
	smc_local_state_reset(state->inner);
	state->skip_count = state->skip_watch;
	state->nth_event_count = 0;
	smc_watchpoint_local_state_clear_covered_accesses(state);
	kfree(state->postponed);
	state->postponed = NULL;
}

/** Ищет пару @pc/@compatible_state в covered_accesses @state. Состояние
 * сравнивается по адресу указателя, не через equals. */
bool smc_watchpoint_local_state_is_access_covered(
	const struct smc_watchpoint_local_state *state, smc_uptr_t pc,
	const struct smc_compatible_state *compatible_state)
{
	struct smc_ilist_const_iter iter;
	struct smc_ilist_const_iter end;

	if (!state)
		return false;
	end = smc_ilist_cend(&state->covered_accesses);
	for (iter = smc_ilist_cbegin(&state->covered_accesses);
	     !smc_ilist_const_iter_equal(&iter, &end);
	     smc_ilist_const_iter_next(&iter)) {
		const struct smc_intrusion_info *info =
			smc_ilist_const_iter_get(&iter);
		if (info->pc == pc && info->info == compatible_state)
			return true;
	}
	return false;
}

/** Добавляет пару @pc/@compatible_state в локальный список @state без передачи
 * владения state. Return: 0, ошибка списка либо -EINVAL для NULL. */
int smc_watchpoint_local_state_add_covered_access(
	struct smc_watchpoint_local_state *state, smc_uptr_t pc,
	struct smc_compatible_state *compatible_state)
{
	struct smc_intrusion_info info = { .pc = pc, .info = compatible_state };

	return state ? smc_ilist_push_front(&state->covered_accesses, &info) :
		-EINVAL;
}

/** Удаляет все записи covered_accesses из @state; compatible-state указатели
 * заимствованы и здесь не уничтожаются. */
void smc_watchpoint_local_state_clear_covered_accesses(
	struct smc_watchpoint_local_state *state)
{
	if (state)
		smc_ilist_clear(&state->covered_accesses);
}

/** Под отдельным lock каждого слота очищает все watchpoints и other_info
 * глобального @state. NULL безопасно игнорируется. */
void smc_watchpoint_global_state_reset(struct smc_watchpoint_global_state *state)
{
	int i;

	if (!state)
		return;
	for (i = 0; i < SMC_CONFIG_NUM_WATCHPOINTS; i++) {
		smc_wp_lock(&state->slot_locks[i]);
		smc_watchpoint_clear(&state->watchpoints[i]);
		memset(&state->other_info[i], 0, sizeof(state->other_info[i]));
		smc_wp_unlock(&state->slot_locks[i]);
	}
	smc_global_state_reset(state->inner);
}

/** Завершает использование глобального @state его сбросом; память встроена в
 * analysis и здесь не освобождается. */
void smc_watchpoint_global_state_destroy(
	struct smc_watchpoint_global_state *state)
{
	if (!state)
		return;
	smc_watchpoint_global_state_reset(state);
	smc_global_state_destroy(state->inner);
	state->inner = NULL;
}

/** Печатает непустые слоты @state: индекс, диапазон и owner. Диагностическое
 * чтение выполняется без slot-lock и потому является моментальным снимком. */
void smc_watchpoint_global_state_print(
	const struct smc_watchpoint_global_state *state)
{
	int i;

	if (!state)
		return;
	for (i = 0; i < SMC_CONFIG_NUM_WATCHPOINTS; i++)
		if (state->watchpoints[i].addr)
			pr_info("KTSAN SMC: wp[%d]=%px/%lu owner=%u\n", i,
				(void *)state->watchpoints[i].addr,
				state->watchpoints[i].size,
				state->watchpoints[i].owner_id);
	smc_global_state_print(state->inner);
}

/** Return: существует ли в @state хотя бы один слот с ненулевым адресом. */
bool smc_watchpoint_global_state_has_watchpoint(
	struct smc_watchpoint_global_state *state)
{
	int i;

	for (i = 0; state && i < SMC_CONFIG_NUM_WATCHPOINTS; i++)
		if (state->watchpoints[i].addr)
			return true;
	return false;
}

/** Return: хеш-слот адреса @addr; @state сейчас не используется и не влияет. */
int smc_watchpoint_global_state_get_slot(
	const struct smc_watchpoint_global_state *state, smc_uptr_t addr)
{
	(void)state;
	return smc_watchpoint_slot(addr);
}

/** Проверяет конфликт @access с @watchpoint, используя его flags/size, но
 * переданный @old_addr как начало старого диапазона. */
bool smc_watchpoint_intersects(const struct smc_watchpoint *watchpoint,
			       smc_uptr_t old_addr,
			       const struct smc_mem_access *access)
{
	return watchpoint && smc_mem_access_intersects_old(access, old_addr,
		watchpoint->is_read, watchpoint->is_atomic, watchpoint->size);
}

/** Return: заимствованный слот @state для адреса @access либо NULL. Функция
 * только вычисляет слот и не проверяет, установлен ли watchpoint. */
struct smc_watchpoint *smc_watchpoint_global_state_get_watchpoint(
	struct smc_watchpoint_global_state *state,
	const struct smc_mem_access *access)
{
	return state && access ?
		&state->watchpoints[smc_watchpoint_slot(access->addr)] : NULL;
}

/** Обрабатывает @access потока @handle_id в @state. При пустом слоте и
 * @should_set устанавливает наблюдение; при конфликте другого неупорядоченного
 * потока печатает гонку и возвращает SMC_WATCHPOINT_CONSUMED; иначе старит
 * слот. Return: установленный слот, CONSUMED или NULL. */
struct smc_watchpoint *smc_watchpoint_global_state_add_if_empty(
	struct smc_watchpoint_global_state *state,
	const struct smc_mem_access *access, bool should_set, u32 handle_id)
{
	struct smc_watchpoint *watchpoint;
	struct smc_other_info old_info;
	kt_thr_t *current_thr;
	bool race = false;
	bool installed = false;
	bool ordered;
	int slot;

	if (!state || !access || !access->addr || !access->size)
		return NULL;
	slot = smc_watchpoint_slot(access->addr);
	watchpoint = &state->watchpoints[slot];
	current_thr = handle_id < KT_MAX_THREAD_COUNT ? kt_thr_get(handle_id) :
		NULL;
	smc_wp_lock(&state->slot_locks[slot]);
	if (!watchpoint->addr) {
		if (should_set) {
			watchpoint->addr = access->addr;
			watchpoint->size = access->size;
			watchpoint->pc = access->pc;
			watchpoint->owner_id = handle_id;
			watchpoint->owner_epoch = current_thr ?
				kt_clk_get(&current_thr->clk, current_thr->id) : 0;
			watchpoint->life = SMC_WP_DEFAULT_LIFE;
			watchpoint->is_read = access->is_read;
			watchpoint->is_atomic = access->is_atomic;
			state->other_info[slot].access_info = *access;
			state->other_info[slot].handle_tid = handle_id;
			state->other_info[slot].ktsan_tid = handle_id;
			installed = true;
		}
	} else if (watchpoint->owner_id != handle_id &&
		   smc_watchpoint_intersects(watchpoint, watchpoint->addr, access)) {
		ordered = current_thr && watchpoint->owner_epoch &&
			kt_clk_get(&current_thr->clk, watchpoint->owner_id) >=
			watchpoint->owner_epoch;
		if (ordered)
			goto age_watchpoint;
		old_info = state->other_info[slot];
		smc_watchpoint_clear(watchpoint);
		memset(&state->other_info[slot], 0, sizeof(state->other_info[slot]));
		race = true;
	} else {
age_watchpoint:
		if (--watchpoint->life)
			goto unlock;
		smc_watchpoint_clear(watchpoint);
		memset(&state->other_info[slot], 0, sizeof(state->other_info[slot]));
	}
unlock:
	smc_wp_unlock(&state->slot_locks[slot]);

	if (race) {
		struct smc_other_info cur_info = {
			.access_info = *access,
			.handle_tid = handle_id,
			.ktsan_tid = handle_id,
		};
		smc_report_race_access(&cur_info, true, false, false);
		smc_report_race_access(&old_info, false, true, false);
		return (struct smc_watchpoint *)SMC_WATCHPOINT_CONSUMED;
	}
	return installed ? watchpoint : NULL;
}

/** Удаляет принадлежащий массиву @state указатель @watchpoint под slot-lock.
 * Rejects NULL, CONSUMED и чужие указатели. Return: был ли слот очищен. */
bool smc_watchpoint_global_state_remove_watchpoint(
	struct smc_watchpoint_global_state *state,
	struct smc_watchpoint *watchpoint)
{
	int slot;

	if (!state || !watchpoint ||
	    watchpoint == (void *)SMC_WATCHPOINT_CONSUMED)
		return false;
	slot = watchpoint - state->watchpoints;
	if (slot < 0 || slot >= SMC_CONFIG_NUM_WATCHPOINTS)
		return false;
	smc_wp_lock(&state->slot_locks[slot]);
	smc_watchpoint_clear(watchpoint);
	memset(&state->other_info[slot], 0, sizeof(state->other_info[slot]));
	smc_wp_unlock(&state->slot_locks[slot]);
	return true;
}

/** Сохраняет копию @mem_access и owner @id в other_info соответствующего
 * слота @state. Вызывающий должен обеспечить необходимую синхронизацию. */
void smc_watchpoint_global_state_add_info(
	struct smc_watchpoint_global_state *state, u32 id,
	const struct smc_mem_access *mem_access)
{
	int slot;

	if (!state || !mem_access)
		return;
	slot = smc_watchpoint_slot(mem_access->addr);
	state->other_info[slot].access_info = *mem_access;
	state->other_info[slot].handle_tid = id;
}

/** Печатает пару конфликтующих доступов: текущий @mem_access потока @id с
 * текущим PC @cur_pc и ранее сохранённый доступ из слота @state. */
void smc_watchpoint_global_state_report_race(
	struct smc_watchpoint_global_state *state, u32 id,
	const struct smc_mem_access *mem_access, smc_uptr_t cur_pc)
{
	struct smc_other_info cur_info;
	int slot;

	if (!state || !mem_access)
		return;
	slot = smc_watchpoint_slot(mem_access->addr);
	memset(&cur_info, 0, sizeof(cur_info));
	cur_info.access_info = *mem_access;
	cur_info.handle_tid = id;
	smc_report_race_access(&cur_info, true, false,
		cur_pc && cur_pc != mem_access->pc);
	smc_report_race_access(&state->other_info[slot], false, true, false);
}

/** Инициализирует @analysis: таблицу методов, параметры, статистику, global
 * state и locks всех слотов. Return: 0 либо -EINVAL для NULL. */
int smc_watchpoint_an_init(struct smc_watchpoint_analysis *analysis)
{
	int i;

	if (!analysis)
		return -EINVAL;
	memset(analysis, 0, sizeof(*analysis));
	analysis->base.type = SMC_DYNAMIC_ANALYSIS_WATCHPOINT;
	analysis->base.init = NULL;
	analysis->base.destroy = smc_watchpoint_an_destroy;
	analysis->base.get_initial_target =
		smc_watchpoint_an_get_initial_target;
	analysis->base.get_initial_local_state =
		smc_watchpoint_an_get_initial_local_state;
	analysis->base.get_initial_global_state =
		smc_watchpoint_an_get_initial_global_state;
	analysis->base.transfer = smc_watchpoint_an_transfer;
	analysis->base.get_new_targets =
		smc_watchpoint_an_get_new_targets;
	analysis->base.fast_is_related =
		smc_watchpoint_an_fast_is_related;
	analysis->base.print_statistics =
		smc_watchpoint_an_print_statistics;
	analysis->base.start_iteration =
		smc_watchpoint_an_start_iteration;
	analysis->base.finish_iteration =
		smc_watchpoint_an_finish_iteration;
	analysis->timeout = SMC_WP_DEFAULT_LIFE;
	analysis->fitness_limit = SMC_WP_DEFAULT_FITNESS_LIMIT;
	analysis->first_access_only = false;
	analysis->intrusion_list_limit = SMC_INTRUSION_LIST_LIMIT_DEFAULT;
	analysis->enable_interesting_check = false;
	analysis->global_state.base.type = SMC_WATCHPOINT_GLOBAL_STATE_TYPE;
	for (i = 0; i < SMC_CONFIG_NUM_WATCHPOINTS; i++)
		kt_spin_init((kt_spinlock_t *)&analysis->global_state.slot_locks[i]);
	kt_spin_init((kt_spinlock_t *)&analysis->global_state.report_lock);
	return 0;
}

/** Атомарно обнуляет все счётчики и статус цели @analysis, не затрагивая
 * конфигурацию, цели и установленные watchpoints. */
void smc_watchpoint_an_reset_statistics(
	struct smc_watchpoint_analysis *analysis)
{
	if (!analysis)
		return;
	kt_atomic32_store_no_ktsan(&analysis->stats.race_found, 0);
	kt_atomic32_store_no_ktsan(&analysis->stats.access_target, 0);
	kt_atomic32_store_no_ktsan(&analysis->stats.none_target, 0);
	kt_atomic32_store_no_ktsan(&analysis->stats.monitoring_target, 0);
	kt_atomic32_store_no_ktsan(&analysis->stats.race_target, 0);
	kt_atomic32_store_no_ktsan(&analysis->stats.total_iterations, 0);
	kt_atomic32_store_no_ktsan(&analysis->stats.target_status,
		SMC_TARGET_STATUS_NONE);
	kt_atomic64_store_no_ktsan(&analysis->stats.shared_accesses, 0);
	kt_atomic64_store_no_ktsan(&analysis->stats.shared_accesses_iteration, 0);
	kt_atomic64_store_no_ktsan(&analysis->stats.targets_fitness_limit, 0);
	kt_atomic64_store_no_ktsan(&analysis->stats.targets_unknown_pc, 0);
	kt_atomic64_store_no_ktsan(&analysis->stats.targets_lockset, 0);
	kt_atomic64_store_no_ktsan(&analysis->stats.targets_created, 0);
}

/** Завершает watchpoint-анализ, заданный базой @base, очищая global state.
 * Память analysis не освобождается, так как может быть статической. */
void smc_watchpoint_an_destroy(struct smc_dynamic_analysis *base)
{
	struct smc_watchpoint_analysis *analysis;

	if (!base)
		return;
	analysis = smc_to_watchpoint(base);
	smc_watchpoint_global_state_destroy(&analysis->global_state);
}

/** Создаёт для анализа @base стартовую collection-цель с GFP_ATOMIC.
 * Return: новая цель либо NULL; @base пока не используется. */
struct smc_target *smc_watchpoint_an_get_initial_target(
	struct smc_dynamic_analysis *base)
{
	(void)base;
	return smc_shared_collection_target_create(GFP_ATOMIC);
}

/** Создаёт local state анализа @base для @handle: skip-параметры и атомарный
 * список covered accesses. Return: новая base с владением handle либо NULL. */
struct smc_local_state *smc_watchpoint_an_get_initial_local_state(
	struct smc_dynamic_analysis *base, struct smc_thread_handle *handle)
{
	struct smc_watchpoint_local_state *state;

	(void)base;
	(void)handle;
	state = kzalloc(sizeof(*state), GFP_ATOMIC);
	if (!state)
		return NULL;
	state->base.type = SMC_WP_LOCAL_STATE_TYPE;
	if (base && smc_to_watchpoint(base)->inner &&
	    smc_to_watchpoint(base)->inner->get_initial_local_state)
		state->inner = smc_to_watchpoint(base)->inner->get_initial_local_state(
			smc_to_watchpoint(base)->inner, handle);
	state->skip_watch = SMC_WP_DEFAULT_LIFE;
	state->skip_count = state->skip_watch;
	smc_ilist_init(&state->covered_accesses,
		sizeof(struct smc_intrusion_info), GFP_ATOMIC, NULL);
	return &state->base;
}

/** Return: адрес встроенного global state анализа @base либо NULL; владение
 * остаётся у analysis, освобождать результат нельзя. */
struct smc_global_state *smc_watchpoint_an_get_initial_global_state(
	struct smc_dynamic_analysis *base)
{
	struct smc_watchpoint_analysis *analysis;

	if (!base)
		return NULL;
	analysis = smc_to_watchpoint(base);
	if (!analysis->global_state.inner && analysis->inner &&
	    analysis->inner->get_initial_global_state)
		analysis->global_state.inner =
			analysis->inner->get_initial_global_state(analysis->inner);
	return &analysis->global_state.base;
}

/** Выполняет переход анализа @base для @event/@handle и текущей @target.
 * Shared-access учитывается статистикой; обычный доступ по целевому PC ставит
 * watchpoint либо обнаруживает гонку. @local_state/@global_state сейчас не
 * используются. Return: NULL, так как реальное ожидание ещё не реализовано. */
struct smc_wait_action *smc_watchpoint_an_transfer(
	struct smc_dynamic_analysis *base,
	struct smc_thread_handle *handle, const struct smc_event *event,
	const struct smc_target *target, struct smc_local_state *local_state,
	struct smc_global_state *global_state)
{
	struct smc_watchpoint_analysis *analysis;
	struct smc_watchpoint *result;
	struct smc_target *mutable_target = (struct smc_target *)target;
	bool should_set;

	(void)local_state;
	(void)global_state;
	if (!base || !handle || !event)
		return NULL;
	analysis = smc_to_watchpoint(base);
	if (event->type == SMC_SHARED_MEM_ACCESS_TYPE) {
		kt_atomic64_fetch_add_no_ktsan(&analysis->stats.shared_accesses, 1);
		kt_atomic64_fetch_add_no_ktsan(
			&analysis->stats.shared_accesses_iteration, 1);
		return NULL;
	}
	if (event->type != SMC_MEM_ACCESS_TYPE)
		return NULL;
	should_set = smc_watchpoint_target_has_pc(target,
		event->data.mem_access.pc);
	result = smc_watchpoint_global_state_add_if_empty(
		&analysis->global_state, &event->data.mem_access,
		should_set && !event->data.mem_access.is_atomic, handle->id);
	if (result == (void *)SMC_WATCHPOINT_CONSUMED) {
		kt_atomic32_fetch_add_no_ktsan(&analysis->stats.race_found, 1);
		kt_atomic32_store_no_ktsan(&analysis->stats.target_status,
			SMC_TARGET_STATUS_RACE);
		if (mutable_target) {
			mutable_target->reached = true;
			mutable_target->explored = true;
		}
	} else if (result) {
		kt_atomic32_fetch_add_no_ktsan(&analysis->stats.access_target, 1);
		kt_atomic32_compare_exchange_no_ktsan(
			&analysis->stats.target_status, SMC_TARGET_STATUS_NONE,
			SMC_TARGET_STATUS_ACCESS);
	}
	if (mutable_target &&
	    ++mutable_target->events >= SMC_WP_TARGET_EVENT_LIMIT)
		mutable_target->explored = true;
	return NULL;
}

/** Строит intrusion-цели из prev_pc/cur_pc shared-события @event для @base.
 * Учитывает fitness limit/first_access_only, пытается merge и аккуратно
 * освобождает частичные результаты. @handle/@local_state/@global_state пока
 * не участвуют. Return: владеющий список целей либо NULL. */
struct smc_ilist *smc_watchpoint_an_get_new_targets(
	struct smc_dynamic_analysis *base,
	struct smc_thread_handle *handle, const struct smc_target *target,
	const struct smc_event *event, struct smc_local_state *local_state,
	struct smc_global_state *global_state)
{
	struct smc_watchpoint_analysis *analysis;
	struct smc_ilist *targets;
	struct smc_target *first = NULL;
	struct smc_target *second = NULL;
	const struct smc_shared_mem_access *shared;
	unsigned int created_count = 0;

	(void)handle; (void)local_state; (void)global_state;
	if (!base || !target || !event ||
	    event->type != SMC_SHARED_MEM_ACCESS_TYPE)
		return NULL;
	analysis = smc_to_watchpoint(base);
	shared = &event->data.shared_mem_access;
	if (shared->epoch_diff > analysis->fitness_limit) {
		kt_atomic64_fetch_add_no_ktsan(
			&analysis->stats.targets_fitness_limit, 1);
		return NULL;
	}
	targets = kmalloc(sizeof(*targets), GFP_ATOMIC);
	if (!targets)
		return NULL;
	smc_ilist_init(targets, sizeof(struct smc_target *), GFP_ATOMIC, NULL);
	if (shared->prev_pc) {
		first = smc_shared_intrusion_target_create_full(shared->prev_pc,
			NULL, shared->epoch_diff, analysis->intrusion_list_limit,
			analysis->enable_interesting_check, GFP_ATOMIC);
		if (first)
			created_count++;
	}
	if (shared->cur_pc && (!analysis->first_access_only || !shared->prev_pc)) {
		second = smc_shared_intrusion_target_create_full(shared->cur_pc,
			NULL, shared->epoch_diff, analysis->intrusion_list_limit,
			analysis->enable_interesting_check, GFP_ATOMIC);
		if (second)
			created_count++;
	}
	if (first && second && smc_target_merge(first, second)) {
		second->ops->destroy(second);
		second = NULL;
	}
	if (first && smc_ilist_push_back(targets, &first)) {
		first->ops->destroy(first);
		first = NULL;
	}
	if (second && smc_ilist_push_back(targets, &second)) {
		second->ops->destroy(second);
		second = NULL;
	}
	kt_atomic64_fetch_add_no_ktsan(&analysis->stats.targets_created,
		created_count);
	if (smc_ilist_empty(targets)) {
		kfree(targets);
		return NULL;
	}
	return targets;
}

/** Быстрый фильтр @event_type для @base: пропускает memory, shared-memory и
 * fence события. Не проверяет текущую цель. */
bool smc_watchpoint_an_fast_is_related(
	const struct smc_dynamic_analysis *base, enum smc_event_type event_type)
{
	(void)base;
	return event_type == SMC_MEM_ACCESS_TYPE ||
		event_type == SMC_SHARED_MEM_ACCESS_TYPE ||
		event_type == SMC_FENCE_TYPE;
}

/** Возвращает изменяемое представление текущей @target. @analysis,
 * @local_state и @global_state зарезервированы для будущей композиции. */
struct smc_target *smc_watchpoint_an_get_current_target(
	struct smc_watchpoint_analysis *analysis, const struct smc_target *target,
	struct smc_local_state *local_state,
	struct smc_global_state *global_state)
{
	(void)analysis; (void)local_state; (void)global_state;
	return (struct smc_target *)target;
}

/** Динамически создаёт и инициализирует анализ с вложенным анализом @inner.
 * Return: объект для последующего destroy+kfree либо NULL. */
struct smc_watchpoint_analysis *smc_watchpoint_an_create(
	struct smc_dynamic_analysis *inner)
{
	struct smc_watchpoint_analysis *analysis;

	analysis = kzalloc(sizeof(*analysis), GFP_KERNEL);
	if (!analysis)
		return NULL;
	if (smc_watchpoint_an_init(analysis)) {
		kfree(analysis);
		return NULL;
	}
	analysis->inner = inner;
	return analysis;
}

/** Печатает основные атомарные счётчики анализа @base. Флаг @total пока не
 * меняет формат; NULL игнорируется. */
void smc_watchpoint_an_print_statistics(
	const struct smc_dynamic_analysis *base, bool total)
{
	const struct smc_watchpoint_analysis *analysis;

	(void)total;
	if (!base)
		return;
	analysis = container_of(base, struct smc_watchpoint_analysis, base);
	pr_info("KTSAN SMC WP: races=%d accesses=%d shared=%lld targets=%lld\n",
		kt_atomic32_load_no_ktsan(&analysis->stats.race_found),
		kt_atomic32_load_no_ktsan(&analysis->stats.access_target),
		kt_atomic64_load_no_ktsan(&analysis->stats.shared_accesses),
		kt_atomic64_load_no_ktsan(&analysis->stats.targets_created));
}

/** Отмечает старт итерации @target в @base увеличением total_iterations.
 * @global_state/@target сейчас не меняются. */
void smc_watchpoint_an_start_iteration(
	struct smc_dynamic_analysis *base,
	struct smc_global_state *global_state, const struct smc_target *target)
{
	struct smc_watchpoint_analysis *analysis = base ?
		smc_to_watchpoint(base) : NULL;

	(void)global_state; (void)target;
	if (analysis)
		kt_atomic32_fetch_add_no_ktsan(&analysis->stats.total_iterations, 1);
}

/** Завершает итерацию @target анализа @base, сбрасывая target_status в NONE.
 * @global_state и сама цель сохраняются/обрабатываются алгоритмом. */
void smc_watchpoint_an_finish_iteration(
	struct smc_dynamic_analysis *base,
	struct smc_global_state *global_state, struct smc_target *target)
{
	struct smc_watchpoint_analysis *analysis = base ?
		smc_to_watchpoint(base) : NULL;

	(void)global_state; (void)target;
	if (analysis)
		kt_atomic32_store_no_ktsan(&analysis->stats.target_status,
			SMC_TARGET_STATUS_NONE);
}

/** Точка глобальной инициализации thread-local watchpoint данных; в текущем
 * переносе не нужна, поскольку local state создаётся лениво для handle. */
void smc_init_watchpoint_thread_locals(void) {}

/** Завершает watchpoint wait @action результатом @result. Ожидание пока
 * заглушено, поэтому action не меняется, а result возвращается без изменений. */
bool smc_watchpoint_wait_action_post_wait(
	struct smc_watchpoint_wait_action *action, bool result)
{
	(void)action;
	return result;
}

/** Отменяет @action; минимальная реализация не содержит ресурсов и является
 * заглушкой до появления настоящего механизма ожидания. */
void smc_watchpoint_wait_action_cancel(
	struct smc_watchpoint_wait_action *action)
{
	(void)action;
}
