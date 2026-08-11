#include "ktsan.h"

#include <linux/slab.h>
#include <linux/jiffies.h>
#include <linux/preempt.h>

#include "c_smc_analysis.h"
#include "c_smc_watchpoint.h"

/** Инициализирует @target типа @type: обнуляет поля, задаёт исходную
 * пригодность @fitness/@request_stop, список новых целей и атомарный счётчик. */
void smc_target_init(struct smc_target *target, enum smc_target_type type,
		     int fitness, bool request_stop)
{
	memset(target, 0, sizeof(*target));
	target->type = type;
	INIT_LIST_HEAD(&target->new_targets_list);
	target->raw_fitness = fitness;
	target->fitness = smc_target_convert_fitness(fitness);
	target->request_stop = request_stop;
	kt_atomic32_store_no_ktsan(&target->progress_counter, 0);
}

/** Проверяет связь @event с @target через target->ops->is_related; при
 * отсутствующем объекте или методе возвращает false. */
bool smc_target_is_related(const struct smc_target *target,
			   const struct smc_event *event)
{
	return target && target->ops && target->ops->is_related &&
		target->ops->is_related(target, event);
}

/** Проверяет достижимость @target виртуальным is_feasible. Цель без
 * специализированной проверки считается достижимой; NULL — недостижимой. */
bool smc_target_is_feasible(const struct smc_target *target)
{
	return target && (!target->ops || !target->ops->is_feasible ||
		target->ops->is_feasible(target));
}

/** Сравнивает @target и @other виртуальным equals первой цели. Возвращает
 * false, если первая цель или реализация сравнения отсутствует. */
bool smc_target_equals(const struct smc_target *target,
		       const struct smc_target *other)
{
	return target && target->ops && target->ops->equals &&
		target->ops->equals(target, other);
}

/** Пытается поглотить @other изменяемой целью @target через ops->merge.
 * Return: true только если объединение выполнено; @other не уничтожается. */
bool smc_target_merge(struct smc_target *target,
		      const struct smc_target *other)
{
	return target && target->ops && target->ops->merge &&
		target->ops->merge(target, other);
}

/** Захватывает @target для обработки: отклоняет NULL/остановленную цель и
 * атомарно увеличивает progress_counter. Return: удалось ли начать работу. */
bool smc_target_set_in_progress(struct smc_target *target)
{
	if (!target || target->request_stop)
		return false;
	kt_atomic32_fetch_add_no_ktsan(&target->progress_counter, 1);
	return true;
}

/** Завершает одну обработку @target, атомарно уменьшая ненулевой счётчик.
 * No-KTSAN атомики предотвращают рекурсивное инструментирование runtime. */
void smc_target_release(struct smc_target *target)
{
	if (target && kt_atomic32_load_no_ktsan(&target->progress_counter))
		kt_atomic32_fetch_add_no_ktsan(&target->progress_counter, (u32)-1);
}

/** Просит остановить @target, только если её никто не обрабатывает.
 * Return: true, если request_stop был установлен без гонки с обработчиком. */
bool smc_target_try_stop(struct smc_target *target)
{
	if (!target || kt_atomic32_load_no_ktsan(&target->progress_counter))
		return false;
	target->request_stop = true;
	return true;
}

/** Возобновляет @target: снимает request_stop и сбрасывает число активных
 * обработчиков. Вызывать следует лишь при внешне гарантированном покое цели. */
void smc_target_restart(struct smc_target *target)
{
	if (!target)
		return;
	target->request_stop = false;
	kt_atomic32_store_no_ktsan(&target->progress_counter, 0);
}

/** Return: является ли @target законченной целью; intrusion-gamete пока
 * считается промежуточным типом, NULL также даёт false. */
bool smc_target_is_complete(const struct smc_target *target)
{
	return target && target->type != SMC_INTRUSION_GAMETE_TYPE;
}

/** Создаёт глубокую копию @target через ops->copy с GFP_ATOMIC.
 * Return: новая принадлежащая вызывающему цель либо NULL. */
struct smc_target *smc_target_copy(const struct smc_target *target)
{
	return target && target->ops && target->ops->copy ?
		target->ops->copy(target, GFP_ATOMIC) : NULL;
}

/** Печатает @target специализированным ops->print либо общий набор полей.
 * NULL игнорируется; вывод направляется в kernel log через pr_info. */
void smc_target_print(const struct smc_target *target)
{
	if (!target)
		return;
	if (target->ops && target->ops->print) {
		target->ops->print(target);
		return;
	}
	pr_info("KTSAN SMC: target type=%d fitness=%d reached=%d explored=%d\n",
		target->type, target->raw_fitness, target->reached,
		target->explored);
}

/** Сравнивает @state и @other: одинаковые указатели равны, разные типы — нет,
 * одинаковые типы делегируются ops->equals первой совместимой сущности. */
bool smc_compatible_state_equals(const struct smc_compatible_state *state,
				 const struct smc_compatible_state *other)
{
	if (state == other)
		return true;
	return state && other && state->type == other->type && state->ops &&
		state->ops->equals && state->ops->equals(state, other);
}

/** Проверяет совместимость @state и @other. NULL совместим лишь с NULL;
 * при отсутствии ops->compatible используется более строгое equals. */
bool smc_compatible_state_compatible(
	const struct smc_compatible_state *state,
	const struct smc_compatible_state *other)
{
	if (!state || !other)
		return state == other;
	if (state->type != other->type)
		return false;
	return state->ops && state->ops->compatible ?
		state->ops->compatible(state, other) :
		smc_compatible_state_equals(state, other);
}

/** Проверяет, относится ли @event к @state, вызывая виртуальный is_related.
 * Отсутствующее состояние или метод дают false. */
bool smc_compatible_state_is_related(
	const struct smc_compatible_state *state, const struct smc_event *event)
{
	return state && state->ops && state->ops->is_related &&
		state->ops->is_related(state, event);
}

/** Проверяет полезность @state для продолжения анализа. NULL и состояние без
 * фильтра считаются интересными; иначе вызывается ops->is_interesting. */
bool smc_compatible_state_is_interesting(
	const struct smc_compatible_state *state)
{
	return !state || !state->ops || !state->ops->is_interesting ||
		state->ops->is_interesting(state);
}

struct smc_compatible_state *
/** Глубоко копирует @state виртуальным copy с GFP_ATOMIC.
 * Return: новая сущность с отдельным владением либо NULL. */
smc_compatible_state_copy(const struct smc_compatible_state *state)
{
	return state && state->ops && state->ops->copy ?
		state->ops->copy(state, GFP_ATOMIC) : NULL;
}

/** Уничтожает @state через реализацию ops->destroy; NULL и состояние без
 * деструктора безопасно игнорируются. */
void smc_compatible_state_destroy(struct smc_compatible_state *state)
{
	if (state && state->ops && state->ops->destroy)
		state->ops->destroy(state);
}

/** Записывает в @target исходный @raw_fitness и его дискретный приоритет.
 * NULL безопасно игнорируется. */
void smc_target_set_fitness(struct smc_target *target, int raw_fitness)
{
	if (!target)
		return;
	target->raw_fitness = raw_fitness;
	target->fitness = smc_target_convert_fitness(raw_fitness);
}

/** Преобразует знаковый @fitness в корзину приоритета по фиксированным
 * порогам; отрицательные значения попадают в нулевую корзину. */
unsigned int smc_target_convert_fitness(int fitness)
{
	static const int limits[] = { 0, 1, 5, 10, 30, 100, 1000 };
	unsigned int i;
	if (fitness < 0)
		return 0;
	for (i = 0; i < ARRAY_SIZE(limits); i++)
		if (fitness < limits[i])
			return i;
	return ARRAY_SIZE(limits);
}

static struct smc_wait_action dummy_action = {
	.type = SMC_WAIT_ACTION_DUMMY,
};

/** Return: адрес единственного статического dummy-действия ожидания; его
 * нельзя освобождать как динамический объект. */
struct smc_wait_action *smc_dummy_wait_action_get_instance(void)
{
	return &dummy_action;
}

/** Завершает ожидание @action результатом @result. Dummy/NULL пока лишь
 * пропускают результат, прочие типы не реализованы и возвращают false. */
bool smc_wait_action_post_wait(struct smc_wait_action *action, bool result)
{
	if (!action || action->type == SMC_WAIT_ACTION_DUMMY)
		return result;
	if (action->type == SMC_WAIT_ACTION_WATCHPOINT)
		return smc_watchpoint_wait_action_post_wait(container_of(action,
			struct smc_watchpoint_wait_action, base), result);
	return false;
}

bool smc_wait_action_wait(struct smc_wait_action *action)
{
	struct smc_watchpoint_wait_action *watch;
	long timeout;

	if (!action || action->type == SMC_WAIT_ACTION_DUMMY)
		return false;
	if (action->type != SMC_WAIT_ACTION_WATCHPOINT || in_atomic() || irqs_disabled())
		return false;
	watch = container_of(action, struct smc_watchpoint_wait_action, base);
	timeout = wait_event_timeout(watch->waitq,
		atomic_read(&watch->state) != SMC_WP_WAIT_ARMED,
		msecs_to_jiffies(action->timeout));
	if (!timeout)
		atomic_cmpxchg(&watch->state, SMC_WP_WAIT_ARMED,
			SMC_WP_WAIT_TIMEOUT);
	return atomic_read(&watch->state) == SMC_WP_WAIT_RACE;
}

void smc_wait_action_cancel(struct smc_wait_action *action)
{
	if (action && action->type == SMC_WAIT_ACTION_WATCHPOINT)
		smc_watchpoint_wait_action_cancel(container_of(action,
			struct smc_watchpoint_wait_action, base));
}
/** Освобождает динамическое @action, но не NULL и не статический dummy. */
void smc_wait_action_destroy(struct smc_wait_action *action)
{
	if (action && action != &dummy_action)
		smc_wait_action_cancel(action);
	if (action && action != &dummy_action)
		kfree(action);
}
