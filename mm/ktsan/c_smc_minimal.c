#include "ktsan.h"

#include <linux/kernel.h>
#include <linux/slab.h>

#include "c_smc_algorithm.h"
#include "c_smc_watchpoint.h"
#include "c_smc_watchpoint_targets.h"

static struct smc_algorithm smc_runtime;
static struct smc_watchpoint_analysis watchpoint_analysis;
static struct smc_waitlist target_waitlist;

static void smc_destroy_target(struct smc_target *target)
{
	if (target && target->ops && target->ops->destroy)
		target->ops->destroy(target);
}

static bool smc_target_list_contains(const struct smc_ilist *list,
				     const struct smc_target *target)
{
	struct smc_ilist_const_iter iter, end;

	end = smc_ilist_cend(list);
	for (iter = smc_ilist_cbegin(list);
	     !smc_ilist_const_iter_equal(&iter, &end);
	     smc_ilist_const_iter_next(&iter)) {
		struct smc_target *const *queued = smc_ilist_const_iter_get(&iter);

		if (smc_target_equals(*queued, target))
			return true;
	}
	return false;
}

/** Печатает добавленную @target и состояние @algorithm; для intrusion выводит
 * первый PC/размер списка, для monitoring — оба PC. Только отладочный вывод. */
static void smc_debug_target_added(const struct smc_dynamic_algorithm *algorithm,
				   const struct smc_target *target)
{
	switch (target->type) {
	case SMC_SHARED_TARGET_INTRUSION_TYPE: {
		const struct smc_shared_intrusion_target *intrusion =
			container_of(target, struct smc_shared_intrusion_target, base);

		pr_info("KTSAN SMC: target added #%d type=intrusion first_pc=%px pcs=%u fitness=%d queued=%u\n",
			algorithm->reached_targets,
			(void *)smc_shared_intrusion_target_first_pc(intrusion),
			smc_shared_intrusion_target_size(intrusion),
			target->raw_fitness,
			smc_waitlist_size(algorithm->waitlist));
		break;
	}
	case SMC_SHARED_TARGET_MONITORING_TYPE: {
		const struct smc_shared_monitoring_target *monitoring =
			container_of(target, struct smc_shared_monitoring_target, base);

		pr_info("KTSAN SMC: target added #%d type=monitoring first_pc=%px second_pc=%px fitness=%d queued=%u\n",
			algorithm->reached_targets, (void *)monitoring->first_pc,
			(void *)monitoring->second_pc, target->raw_fitness,
			smc_waitlist_size(algorithm->waitlist));
		break;
	}
	default:
		pr_info("KTSAN SMC: target added #%d type=%d fitness=%d queued=%u\n",
			algorithm->reached_targets, target->type,
			target->raw_fitness, smc_waitlist_size(algorithm->waitlist));
		break;
	}
}

/** Берёт внутренний @lock runtime через неинструментируемый спинлок KTSAN. */
static void smc_runtime_lock(u8 *lock)
{
	kt_spin_lock((kt_spinlock_t *)lock);
}

/** Освобождает внутренний @lock; должна парно следовать runtime_lock. */
static void smc_runtime_unlock(u8 *lock)
{
	kt_spin_unlock((kt_spinlock_t *)lock);
}

/** Инициализирует @handle потока с идентификатором @id, нулевым атомарным
 * счётчиком событий и ещё не созданным локальным состоянием анализа. */
void smc_thread_handle_init(struct smc_thread_handle *handle, u32 id)
{
	handle->id = id;
	kt_atomic64_store_no_ktsan(&handle->events, 0);
	handle->thread = NULL;
	handle->local_state = NULL;
	handle->local_state_generation = 0;
}

/** Освобождает принадлежащее @handle локальное состояние с учётом его типа.
 * NULL и уже очищенный handle безопасны; сам handle не освобождается. */
void smc_thread_handle_destroy(struct smc_thread_handle *handle)
{
	if (!handle || !handle->local_state)
		return;
	smc_local_state_destroy(handle->local_state);
	handle->local_state = NULL;
	handle->local_state_generation = 0;
}

/** Делает @target текущей целью @algorithm, синхронизирует target_type и
 * вызывает analysis->start_iteration при наличии цели и метода. */
void smc_dyn_alg_set_next_target(
	struct smc_dynamic_algorithm *algorithm, struct smc_target *target)
{
	algorithm->target = target;
	algorithm->target_type = target ? target->type :
		SMC_SHARED_TARGET_COLLECTION_TYPE;
	if (target && algorithm->analysis->start_iteration)
		algorithm->analysis->start_iteration(algorithm->analysis,
			algorithm->global_state, target);
}

/** Полностью инициализирует динамический @algorithm анализом @analysis:
 * создаёт global state, DFS waitlist, coverage, lock и начальную цель. */
void smc_dyn_alg_init(struct smc_dynamic_algorithm *algorithm,
				struct smc_dynamic_analysis *analysis)
{
	memset(algorithm, 0, sizeof(*algorithm));
	algorithm->analysis = analysis;
	algorithm->iteration_generation = 1;
	algorithm->global_state = analysis->get_initial_global_state ?
		analysis->get_initial_global_state(analysis) : NULL;
	algorithm->waitlist = &target_waitlist;
	kt_spin_init((kt_spinlock_t *)&algorithm->event_lock);
	smc_waitlist_init(algorithm->waitlist, SMC_WAITLIST_DFS);
	smc_ilist_init(&algorithm->iteration_targets,
		sizeof(struct smc_target *), GFP_ATOMIC, NULL);
	smc_ilist_init(&algorithm->explored_targets,
		sizeof(struct smc_target *), GFP_ATOMIC, NULL);
	smc_coverage_init(&algorithm->coverage);
	atomic_set(&algorithm->active_events, 0);
	init_waitqueue_head(&algorithm->quiescent_waitq);
	smc_dyn_alg_set_next_target(algorithm,
		analysis->get_initial_target ?
		analysis->get_initial_target(analysis) : NULL);
	algorithm->iteration_going = true;
	algorithm->phase = SMC_PHASE_COLLECTING;
	algorithm->iteration_id = 1;
}

/** Создаёт глобальный минимальный runtime и возвращает его через @algorithm.
 * При ошибке watchpoint-init записывает NULL; объекты имеют статическое время
 * жизни, поэтому функция не выделяет оболочку алгоритма. */
void smc_minimal_init(struct smc_algorithm **algorithm)
{
	if (smc_watchpoint_an_init(&watchpoint_analysis)) {
		*algorithm = NULL;
		return;
	}
	memset(&smc_runtime, 0, sizeof(smc_runtime));
	smc_runtime.type = SMC_ALGORITHM_DYNAMIC;
	smc_dyn_alg_init(&smc_runtime.data.dynamic,
		&watchpoint_analysis.base);
	*algorithm = &smc_runtime;
	pr_info("KTSAN: target-driven SMC watchpoint analysis initialized\n");
}

/** Сохраняет цели текущего запуска отдельно от основной очереди. */
static void smc_add_new_targets(struct smc_dynamic_algorithm *algorithm,
				struct smc_ilist *targets)
{
	struct smc_target *target;

	if (!targets)
		return;
	while (smc_ilist_pop_front(targets, &target)) {
		if (!target)
			continue;
		if (smc_target_list_contains(&algorithm->iteration_targets, target) ||
		    smc_target_list_contains(&algorithm->explored_targets, target) ||
		    smc_ilist_push_back(&algorithm->iteration_targets, &target)) {
			pr_info("KTSAN SMC: target duplicate type=%d fitness=%d (not queued)\n",
				target->type, target->raw_fitness);
			if (target->ops && target->ops->destroy)
				target->ops->destroy(target);
		} else {
			algorithm->reached_targets++;
			smc_debug_target_added(algorithm, target);
		}
	}
	kfree(targets);
}

static void smc_discard_iteration_targets(struct smc_dynamic_algorithm *algorithm)
{
	struct smc_target *target;

	while (smc_ilist_pop_front(&algorithm->iteration_targets, &target))
		smc_destroy_target(target);
}

static void smc_commit_iteration_targets(struct smc_dynamic_algorithm *algorithm)
{
	struct smc_target *target;

	while (smc_ilist_pop_front(&algorithm->iteration_targets, &target)) {
		if (!smc_waitlist_add(algorithm->waitlist, target))
			smc_destroy_target(target);
	}
}

/** Завершает текущую цель и фиксирует цели, найденные в этой итерации. */
static void smc_finish_target(struct smc_dynamic_algorithm *algorithm)
{
	struct smc_target *old = algorithm->target;
	bool new_coverage;

	if (old) {
		if (algorithm->analysis->finish_iteration)
			algorithm->analysis->finish_iteration(algorithm->analysis,
				algorithm->global_state, old);
		if (smc_ilist_push_back(&algorithm->explored_targets, &old))
			smc_destroy_target(old);
	}
	algorithm->target = NULL;
	new_coverage = smc_coverage_save_current(&algorithm->coverage);
	if (!algorithm->smc_target_coverage || new_coverage)
		smc_commit_iteration_targets(algorithm);
	else
		smc_discard_iteration_targets(algorithm);
	smc_coverage_reset_current(&algorithm->coverage);
	smc_global_state_reset(algorithm->global_state);
	algorithm->iteration_going = false;
	algorithm->stop_requested = false;
	algorithm->restart_required = smc_waitlist_size(algorithm->waitlist) != 0;
	algorithm->phase = algorithm->restart_required ? SMC_PHASE_IDLE :
		SMC_PHASE_COMPLETE;
}

/** Обрабатывает @event потока @handle в @algorithm. Под event_lock фильтрует
 * событие/цель, создаёт local state, выполняет local_transfer,
 * transfer и get_new_targets, затем освобождает цель и при необходимости
 * переключает итерацию. Сallbacks исполняются под lock. */
void smc_dyn_alg_on_event(struct smc_dynamic_algorithm *algorithm,
				    const struct smc_event *event,
				    struct smc_thread_handle *handle)
{
	struct smc_wait_action *action = NULL;
	struct smc_ilist *new_targets;

	if (!algorithm || !algorithm->analysis || !event || !handle)
		return;
	if (algorithm->phase != SMC_PHASE_COLLECTING &&
	    algorithm->phase != SMC_PHASE_TARGET)
		return;
	atomic_inc(&algorithm->active_events);

	smc_runtime_lock(&algorithm->event_lock);
	if (!algorithm->iteration_going || algorithm->phase == SMC_PHASE_FINISHING)
		goto unlock;
	if (event->type == SMC_SHARED_MEM_ACCESS_TYPE)
		smc_coverage_add_shared_access(&algorithm->coverage,
			event->data.shared_mem_access.prev_pc,
			event->data.shared_mem_access.cur_pc, 0);
	if (!algorithm->target ||
	    !algorithm->analysis->fast_is_related ||
	    !algorithm->analysis->fast_is_related(algorithm->analysis,
		event->type) ||
	    !smc_target_is_related(algorithm->target, event))
		goto unlock;
	if (!handle->local_state &&
	    algorithm->analysis->get_initial_local_state)
		handle->local_state =
			algorithm->analysis->get_initial_local_state(
				algorithm->analysis, handle);
	if (handle->local_state && !handle->local_state_generation)
		handle->local_state_generation = algorithm->iteration_generation;
	else if (handle->local_state &&
		 handle->local_state_generation != algorithm->iteration_generation) {
		smc_local_state_reset(handle->local_state);
		handle->local_state_generation = algorithm->iteration_generation;
	}
	if (!smc_target_set_in_progress(algorithm->target))
		goto unlock;

	if (algorithm->analysis->local_transfer)
		algorithm->analysis->local_transfer(algorithm->analysis, event,
			handle->local_state);
	action = algorithm->analysis->transfer ?
		algorithm->analysis->transfer(algorithm->analysis, handle, event,
			algorithm->target, handle->local_state,
			algorithm->global_state) : NULL;
	new_targets = algorithm->analysis->get_new_targets ?
		algorithm->analysis->get_new_targets(algorithm->analysis, handle,
			algorithm->target, event, handle->local_state,
			algorithm->global_state) : NULL;
	smc_add_new_targets(algorithm, new_targets);
	smc_target_release(algorithm->target);

	if (algorithm->target->explored || algorithm->target->request_stop)
		algorithm->stop_requested = true;
unlock:
	smc_runtime_unlock(&algorithm->event_lock);
	if (action) {
		bool waited = smc_wait_action_wait(action);

		smc_wait_action_post_wait(action, waited);
		smc_wait_action_destroy(action);
		smc_runtime_lock(&algorithm->event_lock);
		if (algorithm->target && (algorithm->target->explored ||
		    algorithm->target->request_stop))
			algorithm->stop_requested = true;
		smc_runtime_unlock(&algorithm->event_lock);
	}
	if (atomic_dec_and_test(&algorithm->active_events))
		wake_up_all(&algorithm->quiescent_waitq);
}

/** Общая точка входа события @event для @algorithm и потока @handle.
 * При динамическом типе увеличивает no-KTSAN счётчик и передаёт событие
 * динамической реализации; неверный тип/NULL игнорируются. */
void smc_alg_on_event(struct smc_algorithm *algorithm,
			    const struct smc_event *event,
			    struct smc_thread_handle *handle)
{
	if (!algorithm || algorithm->type != SMC_ALGORITHM_DYNAMIC)
		return;
	kt_atomic64_fetch_add_no_ktsan(&handle->events, 1);
	smc_dyn_alg_on_event(&algorithm->data.dynamic, event, handle);
}

/** Завершает текущий запуск @algorithm переходом к следующей цели.
 * Return: осталась ли после перехода активная цель. */
bool smc_alg_on_finalize(struct smc_algorithm *algorithm)
{
	if (!algorithm)
		return false;
	smc_alg_finish_iteration(algorithm);
	return smc_alg_restart_required(algorithm);
}

int smc_alg_start_iteration(struct smc_algorithm *algorithm)
{
	struct smc_dynamic_algorithm *dynamic;
	struct smc_target *next;

	if (!algorithm || algorithm->type != SMC_ALGORITHM_DYNAMIC)
		return -EINVAL;
	dynamic = &algorithm->data.dynamic;
	smc_runtime_lock(&dynamic->event_lock);
	if (dynamic->phase != SMC_PHASE_IDLE) {
		smc_runtime_unlock(&dynamic->event_lock);
		return -EBUSY;
	}
	next = smc_waitlist_get_next(dynamic->waitlist);
	if (!next) {
		dynamic->phase = SMC_PHASE_COMPLETE;
		dynamic->restart_required = false;
		smc_runtime_unlock(&dynamic->event_lock);
		return -ENOENT;
	}
	dynamic->iteration_generation++;
	if (!dynamic->iteration_generation)
		dynamic->iteration_generation = 1;
	dynamic->iteration_id++;
	dynamic->iteration_result = SMC_ITERATION_NONE;
	dynamic->stop_requested = false;
	dynamic->restart_required = false;
	dynamic->iteration_going = true;
	dynamic->phase = SMC_PHASE_TARGET;
	smc_dyn_alg_set_next_target(dynamic, next);
	dynamic->restart_count++;
	smc_runtime_unlock(&dynamic->event_lock);
	return 0;
}

enum smc_iteration_result smc_alg_finish_iteration(
	struct smc_algorithm *algorithm)
{
	struct smc_dynamic_algorithm *dynamic;

	if (!algorithm || algorithm->type != SMC_ALGORITHM_DYNAMIC)
		return SMC_ITERATION_ABORTED;
	dynamic = &algorithm->data.dynamic;
	smc_runtime_lock(&dynamic->event_lock);
	if (dynamic->phase != SMC_PHASE_COLLECTING &&
	    dynamic->phase != SMC_PHASE_TARGET) {
		smc_runtime_unlock(&dynamic->event_lock);
		return dynamic->iteration_result;
	}
	dynamic->phase = SMC_PHASE_FINISHING;
	dynamic->iteration_going = false;
	smc_runtime_unlock(&dynamic->event_lock);
	if (dynamic->analysis->type == SMC_DYNAMIC_ANALYSIS_WATCHPOINT)
		smc_watchpoint_an_cancel_waits(container_of(dynamic->analysis,
			struct smc_watchpoint_analysis, base));
	wait_event(dynamic->quiescent_waitq,
		atomic_read(&dynamic->active_events) == 0);
	smc_runtime_lock(&dynamic->event_lock);
	if (dynamic->iteration_result == SMC_ITERATION_NONE) {
		if (dynamic->analysis->type == SMC_DYNAMIC_ANALYSIS_WATCHPOINT &&
		    kt_atomic32_load_no_ktsan(&container_of(dynamic->analysis,
			struct smc_watchpoint_analysis, base)->stats.target_status) ==
			SMC_TARGET_STATUS_RACE)
			dynamic->iteration_result = SMC_ITERATION_RACE;
		else if (dynamic->target && dynamic->target->events >= 4096)
			dynamic->iteration_result = SMC_ITERATION_EVENT_LIMIT;
		else if (dynamic->target && dynamic->target->reached)
			dynamic->iteration_result = SMC_ITERATION_ACCESS_REACHED;
		else
			dynamic->iteration_result = SMC_ITERATION_TARGET_NOT_REACHED;
	}
	smc_finish_target(dynamic);
	smc_runtime_unlock(&dynamic->event_lock);
	return dynamic->iteration_result;
}

enum smc_iteration_phase smc_alg_get_phase(struct smc_algorithm *algorithm)
{
	return algorithm && algorithm->type == SMC_ALGORITHM_DYNAMIC ?
		algorithm->data.dynamic.phase : SMC_PHASE_COMPLETE;
}

bool smc_alg_restart_required(struct smc_algorithm *algorithm)
{
	return algorithm && algorithm->type == SMC_ALGORITHM_DYNAMIC &&
		algorithm->data.dynamic.restart_required;
}

/** Печатает общую и watchpoint-статистику глобального runtime, после чего
 * сбрасывает только счётчики анализа; очередь и текущая цель сохраняются. */
void smc_minimal_print_and_reset_statistics(void)
{
	struct smc_dynamic_algorithm *algorithm = &smc_runtime.data.dynamic;

	pr_info("KTSAN SMC: iterations=%d queued=%u generated=%d\n",
		algorithm->restart_count,
		smc_waitlist_size(algorithm->waitlist),
		algorithm->reached_targets);
	if (algorithm->analysis->print_statistics)
		algorithm->analysis->print_statistics(algorithm->analysis, true);
	smc_watchpoint_an_reset_statistics(&watchpoint_analysis);
}
