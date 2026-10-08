#include "ktsan.h"

#include <linux/kernel.h>
#include <linux/slab.h>

#include "c_smc_algorithm.h"
#include "c_smc_watchpoint.h"
#include "c_smc_watchpoint_targets.h"

#define SMC_EVENT_LOCK_MAX_TRIES 8U

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
	kt_task_t *task;

	preempt_disable();
	task = current->ktsan.task;
	if (task && task->thr)
		task->thr->smc_inside++;
	barrier();
	kt_spin_lock((kt_spinlock_t *)lock);
}

/** Освобождает внутренний @lock; должна парно следовать runtime_lock. */
static void smc_runtime_unlock(u8 *lock)
{
	kt_task_t *task = current->ktsan.task;

	kt_spin_unlock((kt_spinlock_t *)lock);
	barrier();
	if (task && task->thr)
		task->thr->smc_inside--;
	preempt_enable();
}

static bool smc_runtime_trylock(u8 *lock)
{
	kt_task_t *task;
	unsigned int attempt;

	preempt_disable();
	task = current->ktsan.task;
	if (task && task->thr)
		task->thr->smc_inside++;
	barrier();
	for (attempt = 0; attempt < SMC_EVENT_LOCK_MAX_TRIES; attempt++) {
		if (kt_atomic8_load_no_ktsan(lock) == 0 &&
		    kt_atomic8_compare_exchange_no_ktsan(lock, 0, 1) == 0)
			return true;
		if (attempt + 1 < SMC_EVENT_LOCK_MAX_TRIES)
			cpu_relax();
	}
	if (task && task->thr)
		task->thr->smc_inside--;
	preempt_enable();
	return false;
}

static void smc_event_done(struct smc_dynamic_algorithm *algorithm)
{
	if (kt_atomic32_fetch_add_no_ktsan(&algorithm->active_events,
		(u32)-1) == 1)
		wake_up_all(&algorithm->quiescent_waitq);
}

static void smc_record_dropped_event(struct smc_dynamic_algorithm *algorithm,
				     enum smc_iteration_phase phase,
				     enum smc_drop_kind kind)
{
	kt_atomic64_fetch_add_no_ktsan(&algorithm->dropped_events, 1);
	if ((unsigned int)phase < SMC_PHASE_COUNT)
		kt_atomic64_fetch_add_no_ktsan(
			&algorithm->iteration_dropped_by_phase[phase], 1);
	if ((unsigned int)kind < SMC_DROP_KIND_COUNT)
		kt_atomic64_fetch_add_no_ktsan(
			&algorithm->iteration_dropped_by_type[kind], 1);
}

static bool smc_event_is_candidate(
	const struct smc_dynamic_algorithm *algorithm,
	const struct smc_event *event, enum smc_iteration_phase phase)
{
	if (!algorithm->analysis->fast_is_related ||
	    !algorithm->analysis->fast_is_related(algorithm->analysis,
		 event->type))
		return false;
	if (phase == SMC_PHASE_COLLECTING)
		return event->type == SMC_SHARED_MEM_ACCESS_TYPE;
	return phase == SMC_PHASE_TARGET;
}

static void smc_reset_iteration_drop_counters(
	struct smc_dynamic_algorithm *algorithm)
{
	unsigned int i;

	for (i = 0; i < SMC_PHASE_COUNT; i++)
		kt_atomic64_store_no_ktsan(
			&algorithm->iteration_dropped_by_phase[i], 0);
	for (i = 0; i < SMC_DROP_KIND_COUNT; i++)
		kt_atomic64_store_no_ktsan(
			&algorithm->iteration_dropped_by_type[i], 0);
}

static kt_spinlock_t smc_pending_lock;

static unsigned long smc_pending_lock_irqsave(void)
{
	unsigned long flags;

	preempt_disable();
	flags = arch_local_irq_save();
	kt_spin_lock(&smc_pending_lock);
	return flags;
}

static void smc_pending_unlock_irqrestore(unsigned long flags)
{
	kt_spin_unlock(&smc_pending_lock);
	arch_local_irq_restore(flags);
	preempt_enable();
}

static struct smc_wait_action *smc_take_pending_locked(
	struct smc_thread_handle *handle,
	struct smc_dynamic_algorithm **algorithm)
{
	struct smc_wait_action *action = handle->pending_wait_action;

	*algorithm = handle->pending_wait_algorithm;
	if (action) {
		list_del_init(&handle->pending_wait_node);
		handle->pending_wait_action = NULL;
		handle->pending_wait_algorithm = NULL;
	}
	return action;
}

static void smc_cancel_owned_wait(struct smc_dynamic_algorithm *algorithm,
	struct smc_wait_action *action)
{
	smc_wait_action_cancel(action);
	smc_wait_action_post_wait(action, false);
	smc_wait_action_destroy(action);
	kt_atomic64_fetch_add_no_ktsan(&algorithm->waits_cancelled, 1);
	if (kt_atomic32_fetch_add_no_ktsan(&algorithm->active_events,
		(u32)-1) == 1)
		wake_up_all(&algorithm->quiescent_waitq);
}

static void smc_cancel_pending_waits(struct smc_dynamic_algorithm *algorithm)
{
	for (;;) {
		struct smc_thread_handle *handle;
		struct smc_dynamic_algorithm *owner;
		struct smc_wait_action *action;
		unsigned long flags = smc_pending_lock_irqsave();

		if (list_empty(&algorithm->pending_waits)) {
			smc_pending_unlock_irqrestore(flags);
			break;
		}
		handle = list_first_entry(&algorithm->pending_waits,
			struct smc_thread_handle, pending_wait_node);
		action = smc_take_pending_locked(handle, &owner);
		smc_pending_unlock_irqrestore(flags);
		smc_cancel_owned_wait(owner, action);
	}
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
	INIT_LIST_HEAD(&handle->pending_wait_node);
	handle->pending_wait_action = NULL;
	handle->pending_wait_algorithm = NULL;
}

/** Освобождает принадлежащее @handle локальное состояние с учётом его типа.
 * NULL и уже очищенный handle безопасны; сам handle не освобождается. */
void smc_thread_handle_destroy(struct smc_thread_handle *handle)
{
	struct smc_wait_action *action;
	struct smc_dynamic_algorithm *algorithm;

	if (!handle)
		return;
	{
		unsigned long flags = smc_pending_lock_irqsave();

		action = smc_take_pending_locked(handle, &algorithm);
		smc_pending_unlock_irqrestore(flags);
	}
	if (action)
		smc_cancel_owned_wait(algorithm, action);
	if (!handle->local_state)
		return;
	smc_local_state_destroy(handle->local_state);
	handle->local_state = NULL;
	handle->local_state_generation = 0;
}

static void smc_complete_wait_action(struct smc_dynamic_algorithm *algorithm,
	struct smc_wait_action *action)
{
	bool waited;

	if (!algorithm || !action)
		return;
	kt_atomic64_fetch_add_no_ktsan(&algorithm->waits_executed, 1);
	waited = smc_wait_action_wait(action);
	smc_wait_action_post_wait(action, waited);
	smc_wait_action_destroy(action);
	if (smc_runtime_trylock(&algorithm->event_lock)) {
		if (algorithm->target && (algorithm->target->explored ||
		    algorithm->target->request_stop))
			algorithm->stop_requested = true;
		smc_runtime_unlock(&algorithm->event_lock);
	} else {
		smc_record_dropped_event(algorithm,
			READ_ONCE(algorithm->phase), SMC_DROP_COMPLETION);
	}
	smc_event_done(algorithm);
}

/** Выполняет отложенное ожидание после выхода из KTSAN ENTER/LEAVE. */
void smc_thread_handle_process_wait(struct smc_thread_handle *handle)
{
	struct smc_wait_action *action;
	struct smc_dynamic_algorithm *algorithm;
	kt_thr_t *thr;

	if (!handle)
		return;
	thr = handle->thread;
	/*
	 * LEAVE has already cleared thr->inside before calling us.  Keep Race
	 * Hunter disabled while waitqueue, printk, allocator and scheduler code
	 * execute, otherwise those internals recursively enter the same analysis.
	 */
	if (thr)
		thr->smc_inside++;
	{
		unsigned long flags = smc_pending_lock_irqsave();

		action = smc_take_pending_locked(handle, &algorithm);
		smc_pending_unlock_irqrestore(flags);
	}
	if (!action) {
		if (thr)
			thr->smc_inside--;
		return;
	}
	smc_complete_wait_action(algorithm, action);
	if (thr)
		thr->smc_inside--;
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
	smc_waitlist_init(algorithm->waitlist,
		SMC_WAITLIST_TARGET_DIFFERENCE);
	smc_ilist_init(&algorithm->iteration_targets,
		sizeof(struct smc_target *), GFP_ATOMIC, NULL);
	smc_ilist_init(&algorithm->explored_targets,
		sizeof(struct smc_target *), GFP_ATOMIC, NULL);
	smc_coverage_init(&algorithm->coverage);
	kt_atomic32_store_no_ktsan(&algorithm->active_events, 0);
	INIT_LIST_HEAD(&algorithm->pending_waits);
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
		    smc_target_list_contains(&algorithm->explored_targets, target)) {
			kt_atomic64_fetch_add_no_ktsan(&algorithm->duplicate_targets, 1);
			smc_destroy_target(target);
			continue;
		}
		if (smc_ilist_push_back(&algorithm->iteration_targets, &target)) {
			kt_atomic64_fetch_add_no_ktsan(&algorithm->target_insert_failures, 1);
			if (target->ops && target->ops->destroy)
				target->ops->destroy(target);
		} else {
			algorithm->reached_targets++;
			smc_debug_target_added(algorithm, target);
		}
	}
	kfree(targets);
}

static void smc_discard_explored_targets(struct smc_dynamic_algorithm *algorithm)
{
	struct smc_target *target;

	while (smc_ilist_pop_front(&algorithm->explored_targets, &target))
		smc_destroy_target(target);
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
		if (algorithm->iteration_result == SMC_ITERATION_CONTENDED ||
		    smc_ilist_push_back(&algorithm->explored_targets, &old))
			smc_destroy_target(old);
	}
	algorithm->target = NULL;
	new_coverage = algorithm->iteration_result != SMC_ITERATION_CONTENDED &&
		smc_coverage_save_current(&algorithm->coverage);
	if (algorithm->iteration_result != SMC_ITERATION_CONTENDED &&
	    (!algorithm->smc_target_coverage || new_coverage))
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
	enum smc_iteration_phase phase;
	bool wait_deferred = false;

	if (!algorithm || !algorithm->analysis || !event || !handle)
		return;
	phase = READ_ONCE(algorithm->phase);
	if ((phase != SMC_PHASE_COLLECTING && phase != SMC_PHASE_TARGET) ||
	    !smc_event_is_candidate(algorithm, event, phase))
		return;
	kt_atomic32_fetch_add_no_ktsan(&algorithm->active_events, 1);
	if (READ_ONCE(algorithm->phase) != SMC_PHASE_COLLECTING &&
	    READ_ONCE(algorithm->phase) != SMC_PHASE_TARGET) {
		smc_event_done(algorithm);
		return;
	}
	kt_atomic64_fetch_add_no_ktsan(&algorithm->event_attempts, 1);
	if (!smc_runtime_trylock(&algorithm->event_lock)) {
		smc_record_dropped_event(algorithm,
			READ_ONCE(algorithm->phase),
			(enum smc_drop_kind)event->type);
		smc_event_done(algorithm);
		return;
	}
	if (!algorithm->iteration_going ||
	    (algorithm->phase != SMC_PHASE_COLLECTING &&
	     algorithm->phase != SMC_PHASE_TARGET)) {
		smc_runtime_unlock(&algorithm->event_lock);
		smc_event_done(algorithm);
		return;
	}
	if (event->type == SMC_SHARED_MEM_ACCESS_TYPE)
		smc_coverage_add_shared_access(&algorithm->coverage,
			event->data.shared_mem_access.prev_pc,
			event->data.shared_mem_access.cur_pc, 0);
	if (!algorithm->target ||
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
	if (action) {
		unsigned long flags = smc_pending_lock_irqsave();

		if (!handle->pending_wait_action) {
			handle->pending_wait_algorithm = algorithm;
			handle->pending_wait_action = action;
			list_add_tail(&handle->pending_wait_node,
				&algorithm->pending_waits);
			wait_deferred = true;
		}
		smc_pending_unlock_irqrestore(flags);
	}
	smc_runtime_unlock(&algorithm->event_lock);
	if (action && !wait_deferred) {
		smc_wait_action_cancel(action);
		smc_wait_action_post_wait(action, false);
		smc_wait_action_destroy(action);
	}
	if (!wait_deferred)
		smc_event_done(algorithm);
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
	bool collecting = false;

	if (!algorithm || algorithm->type != SMC_ALGORITHM_DYNAMIC)
		return -EINVAL;
	dynamic = &algorithm->data.dynamic;
	smc_runtime_lock(&dynamic->event_lock);
	if (dynamic->phase != SMC_PHASE_IDLE &&
	    dynamic->phase != SMC_PHASE_COMPLETE) {
		smc_runtime_unlock(&dynamic->event_lock);
		return -EBUSY;
	}
	next = smc_waitlist_get_next(dynamic->waitlist);
	if (!next) {
		next = dynamic->analysis->get_initial_target ?
			dynamic->analysis->get_initial_target(dynamic->analysis) : NULL;
		if (!next) {
			dynamic->phase = SMC_PHASE_COMPLETE;
			dynamic->restart_required = false;
			smc_runtime_unlock(&dynamic->event_lock);
			return -ENOMEM;
		}
		smc_discard_iteration_targets(dynamic);
		smc_discard_explored_targets(dynamic);
		collecting = true;
	}
	dynamic->iteration_generation++;
	if (!dynamic->iteration_generation)
		dynamic->iteration_generation = 1;
	dynamic->iteration_id++;
	dynamic->iteration_result = SMC_ITERATION_NONE;
	dynamic->iteration_dropped_events = 0;
	dynamic->iteration_event_attempts = 0;
	smc_reset_iteration_drop_counters(dynamic);
	dynamic->dropped_events_start =
		kt_atomic64_load_no_ktsan(&dynamic->dropped_events);
	dynamic->event_attempts_start =
		kt_atomic64_load_no_ktsan(&dynamic->event_attempts);
	dynamic->stop_requested = false;
	dynamic->restart_required = false;
	dynamic->iteration_going = true;
	dynamic->phase = collecting ? SMC_PHASE_COLLECTING : SMC_PHASE_TARGET;
	smc_dyn_alg_set_next_target(dynamic, next);
	if (collecting)
		dynamic->prep_iterations++;
	else
		dynamic->restart_count++;
	smc_runtime_unlock(&dynamic->event_lock);
	if (collecting)
		pr_info("KTSAN SMC: queue empty, started collecting iteration %llu\n",
			dynamic->iteration_id);
	return 0;
}

enum smc_iteration_result smc_alg_finish_iteration(
	struct smc_algorithm *algorithm)
{
	struct smc_dynamic_algorithm *dynamic;
	long quiescent;

	if (!algorithm || algorithm->type != SMC_ALGORITHM_DYNAMIC)
		return SMC_ITERATION_ABORTED;
	dynamic = &algorithm->data.dynamic;
	smc_runtime_lock(&dynamic->event_lock);
	if (dynamic->phase != SMC_PHASE_COLLECTING &&
	    dynamic->phase != SMC_PHASE_TARGET) {
		smc_runtime_unlock(&dynamic->event_lock);
		return dynamic->iteration_result;
	}
	WRITE_ONCE(dynamic->phase, SMC_PHASE_FINISHING);
	dynamic->iteration_going = false;
	smc_runtime_unlock(&dynamic->event_lock);
	kt_thread_fence_no_ktsan(ktsan_memory_order_acq_rel);
	if (dynamic->analysis->type == SMC_DYNAMIC_ANALYSIS_WATCHPOINT)
		smc_watchpoint_an_cancel_waits(container_of(dynamic->analysis,
			struct smc_watchpoint_analysis, base));
	smc_cancel_pending_waits(dynamic);
	do {
		quiescent = wait_event_timeout(dynamic->quiescent_waitq,
			kt_atomic32_load_no_ktsan(&dynamic->active_events) == 0,
			30 * HZ);
		if (!quiescent)
			pr_err("KTSAN SMC: waiting for %d active events in iteration %llu phase=%d stop_requested=%d\n",
				kt_atomic32_load_no_ktsan(&dynamic->active_events),
				dynamic->iteration_id, dynamic->phase,
				dynamic->stop_requested);
	} while (!quiescent);
	smc_runtime_lock(&dynamic->event_lock);
	dynamic->iteration_dropped_events =
		kt_atomic64_load_no_ktsan(&dynamic->dropped_events) -
		dynamic->dropped_events_start;
	dynamic->iteration_event_attempts =
		kt_atomic64_load_no_ktsan(&dynamic->event_attempts) -
		dynamic->event_attempts_start;
	if (dynamic->iteration_result == SMC_ITERATION_RACE ||
	    (dynamic->analysis->type == SMC_DYNAMIC_ANALYSIS_WATCHPOINT &&
	     kt_atomic32_load_no_ktsan(&container_of(dynamic->analysis,
		struct smc_watchpoint_analysis, base)->stats.target_status) ==
		SMC_TARGET_STATUS_RACE))
		dynamic->iteration_result = SMC_ITERATION_RACE;
	else if (dynamic->iteration_dropped_events)
		dynamic->iteration_result = SMC_ITERATION_CONTENDED;
	if (dynamic->iteration_result == SMC_ITERATION_NONE) {
		if (dynamic->target && dynamic->target->events >= 4096)
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

enum smc_waitlist_type smc_alg_get_waitlist_type(
	struct smc_algorithm *algorithm)
{
	if (!algorithm || algorithm->type != SMC_ALGORITHM_DYNAMIC ||
	    !algorithm->data.dynamic.waitlist)
		return SMC_WAITLIST_DFS;
	return algorithm->data.dynamic.waitlist->type;
}

int smc_alg_set_waitlist_type(struct smc_algorithm *algorithm,
			      enum smc_waitlist_type type)
{
	struct smc_dynamic_algorithm *dynamic;
	bool initial_collecting;

	if (!algorithm || algorithm->type != SMC_ALGORITHM_DYNAMIC ||
	    (type != SMC_WAITLIST_DFS &&
	     type != SMC_WAITLIST_TARGET_DIFFERENCE))
		return -EINVAL;
	dynamic = &algorithm->data.dynamic;
	smc_runtime_lock(&dynamic->event_lock);
	if (dynamic->waitlist->type == type) {
		smc_runtime_unlock(&dynamic->event_lock);
		return 0;
	}
	initial_collecting = dynamic->phase == SMC_PHASE_COLLECTING &&
		dynamic->iteration_id == 1 &&
		kt_atomic32_load_no_ktsan(&dynamic->active_events) == 0;
	if ((!initial_collecting && dynamic->phase != SMC_PHASE_IDLE &&
	     dynamic->phase != SMC_PHASE_COMPLETE) ||
	    smc_waitlist_size(dynamic->waitlist)) {
		smc_runtime_unlock(&dynamic->event_lock);
		return -EBUSY;
	}
	smc_waitlist_destroy(dynamic->waitlist);
	smc_waitlist_init(dynamic->waitlist, type);
	smc_runtime_unlock(&dynamic->event_lock);
	return 0;
}

/** Печатает общую и watchpoint-статистику глобального runtime, после чего
 * сбрасывает только счётчики анализа; очередь и текущая цель сохраняются. */
void smc_minimal_print_and_reset_statistics(void)
{
	struct smc_dynamic_algorithm *algorithm = &smc_runtime.data.dynamic;

	if (!algorithm->analysis)
		return;

	pr_info("KTSAN SMC: iterations=%d queued=%u generated=%d\n",
		algorithm->restart_count,
		smc_waitlist_size(algorithm->waitlist),
		algorithm->reached_targets);
	pr_info("KTSAN SMC targets: duplicates=%llu insert_failures=%llu\n",
		kt_atomic64_load_no_ktsan(&algorithm->duplicate_targets),
		kt_atomic64_load_no_ktsan(&algorithm->target_insert_failures));
	pr_info("KTSAN SMC waits: executed=%llu cancelled_pending=%llu active=%u\n",
		kt_atomic64_load_no_ktsan(&algorithm->waits_executed),
		kt_atomic64_load_no_ktsan(&algorithm->waits_cancelled),
		kt_atomic32_load_no_ktsan(&algorithm->active_events));
	if (algorithm->analysis->print_statistics)
		algorithm->analysis->print_statistics(algorithm->analysis, true);
	smc_waitlist_print_and_reset_statistics(algorithm->waitlist);
	smc_watchpoint_an_reset_statistics(&watchpoint_analysis);
}
