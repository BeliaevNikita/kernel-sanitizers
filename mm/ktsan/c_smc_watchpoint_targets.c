// SPDX-License-Identifier: GPL-2.0
#include <linux/slab.h>

#include "c_smc_watchpoint_targets.h"

/** Для collection-цели @target принимает @event только при включённом collect
 * и типе shared-memory-access. Return: нужно ли запускать анализ события. */
static bool collection_related(const struct smc_target *target,
			       const struct smc_event *event)
{
	const struct smc_shared_collection_target *collection =
		container_of(target, struct smc_shared_collection_target, base);

	return collection->collect && event->type == SMC_SHARED_MEM_ACCESS_TYPE;
}

/** Сравнивает элементы @a/@b intrusion-списка по PC и глубокому равенству
 * compatible state. Оба указателя обязаны быть валидны. */
static bool intrusion_info_equal(const struct smc_intrusion_info *a,
				 const struct smc_intrusion_info *b)
{
	return a->pc == b->pc &&
		smc_compatible_state_equals(a->info, b->info);
}

/** Ищет @pc в списке @target линейным обходом. Return: внутренний элемент,
 * действительный до изменения/уничтожения цели, либо NULL. */
static const struct smc_intrusion_info *intrusion_find(
	const struct smc_shared_intrusion_target *target, smc_uptr_t pc)
{
	struct smc_ilist_const_iter iter;
	struct smc_ilist_const_iter end;

	end = smc_ilist_cend(&target->pc_list);
	for (iter = smc_ilist_cbegin(&target->pc_list);
	     !smc_ilist_const_iter_equal(&iter, &end);
	     smc_ilist_const_iter_next(&iter)) {
		const struct smc_intrusion_info *item =
			smc_ilist_const_iter_get(&iter);

		if (item->pc == pc)
			return item;
	}
	return NULL;
}

/** Проверяет наличие полного элемента @wanted в @target, включая state.
 * Порядок элементов значения не имеет. */
static bool intrusion_contains_info(
	const struct smc_shared_intrusion_target *target,
	const struct smc_intrusion_info *wanted)
{
	struct smc_ilist_const_iter iter;
	struct smc_ilist_const_iter end;

	end = smc_ilist_cend(&target->pc_list);
	for (iter = smc_ilist_cbegin(&target->pc_list);
	     !smc_ilist_const_iter_equal(&iter, &end);
	     smc_ilist_const_iter_next(&iter)) {
		const struct smc_intrusion_info *item =
			smc_ilist_const_iter_get(&iter);

		if (intrusion_info_equal(item, wanted))
			return true;
	}
	return false;
}

/** Проверяет связь intrusion-цели @base с @event. Memory/fence события всегда
 * пропускаются; остальные проверяются по compatible state каждого PC. */
static bool intrusion_related(const struct smc_target *base,
			      const struct smc_event *event)
{
	const struct smc_shared_intrusion_target *target =
		container_of(base, struct smc_shared_intrusion_target, base);
	struct smc_ilist_const_iter iter;
	struct smc_ilist_const_iter end;

	if (event->type == SMC_MEM_ACCESS_TYPE ||
	    event->type == SMC_SHARED_MEM_ACCESS_TYPE ||
	    event->type == SMC_FENCE_TYPE)
		return true;

	end = smc_ilist_cend(&target->pc_list);
	for (iter = smc_ilist_cbegin(&target->pc_list);
	     !smc_ilist_const_iter_equal(&iter, &end);
	     smc_ilist_const_iter_next(&iter)) {
		const struct smc_intrusion_info *item =
			smc_ilist_const_iter_get(&iter);

		if (smc_compatible_state_is_related(item->info, event))
			return true;
	}
	return false;
}

/** Фильтр monitoring-цели: @target не влияет на решение, а @event должен быть
 * memory/shared-memory/fence. Return: относится ли событие к анализу. */
static bool monitoring_related(const struct smc_target *target,
			       const struct smc_event *event)
{
	(void)target;
	return event->type == SMC_MEM_ACCESS_TYPE ||
		event->type == SMC_SHARED_MEM_ACCESS_TYPE ||
		event->type == SMC_FENCE_TYPE;
}

/** Полиморфно сравнивает @target с @other: collection равны по типу,
 * intrusion — как неупорядоченные множества PC/state, monitoring — по двум PC. */
static bool target_equals(const struct smc_target *target,
			  const struct smc_target *other)
{
	if (!other || target->type != other->type)
		return false;
	switch (target->type) {
	case SMC_SHARED_TARGET_COLLECTION_TYPE:
		return true;
	case SMC_SHARED_TARGET_INTRUSION_TYPE: {
		const struct smc_shared_intrusion_target *a = container_of(target,
			struct smc_shared_intrusion_target, base);
		const struct smc_shared_intrusion_target *b = container_of(other,
			struct smc_shared_intrusion_target, base);
		struct smc_ilist_const_iter iter;
		struct smc_ilist_const_iter end;

		if (smc_ilist_size(&a->pc_list) != smc_ilist_size(&b->pc_list))
			return false;
		end = smc_ilist_cend(&a->pc_list);
		for (iter = smc_ilist_cbegin(&a->pc_list);
		     !smc_ilist_const_iter_equal(&iter, &end);
		     smc_ilist_const_iter_next(&iter)) {
			const struct smc_intrusion_info *item =
				smc_ilist_const_iter_get(&iter);

			if (!intrusion_contains_info(b, item))
				return false;
		}
		return true;
	}
	case SMC_SHARED_TARGET_MONITORING_TYPE: {
		const struct smc_shared_monitoring_target *a = container_of(target,
			struct smc_shared_monitoring_target, base);
		const struct smc_shared_monitoring_target *b = container_of(other,
			struct smc_shared_monitoring_target, base);

		return a->first_pc == b->first_pc && a->second_pc == b->second_pc;
	}
	default:
		return target == other;
	}
}

/** Пытается добавить все элементы @other_base в intrusion-цель @base.
 * Проверяет тип, limit и дубликаты, глубоко копирует states; при любой ошибке
 * откатывает уже добавленные элементы и fitness. Return: успех транзакции. */
static bool intrusion_merge(struct smc_target *base,
			    const struct smc_target *other_base)
{
	struct smc_shared_intrusion_target *target;
	const struct smc_shared_intrusion_target *other;
	struct smc_ilist_const_iter iter;
	struct smc_ilist_const_iter end;
	smc_uptr_t old_size;
	int old_fitness;

	if (!other_base || other_base->type != SMC_SHARED_TARGET_INTRUSION_TYPE)
		return false;
	target = container_of(base, struct smc_shared_intrusion_target, base);
	other = container_of(other_base, struct smc_shared_intrusion_target, base);
	if (smc_ilist_size(&target->pc_list) + smc_ilist_size(&other->pc_list) >
	    target->list_limit)
		return false;

	end = smc_ilist_cend(&other->pc_list);
	for (iter = smc_ilist_cbegin(&other->pc_list);
	     !smc_ilist_const_iter_equal(&iter, &end);
	     smc_ilist_const_iter_next(&iter)) {
		const struct smc_intrusion_info *item =
			smc_ilist_const_iter_get(&iter);

		if (intrusion_contains_info(target, item))
			return false;
	}

	old_size = smc_ilist_size(&target->pc_list);
	old_fitness = target->base.raw_fitness;
	for (iter = smc_ilist_cbegin(&other->pc_list);
	     !smc_ilist_const_iter_equal(&iter, &end);
	     smc_ilist_const_iter_next(&iter)) {
		const struct smc_intrusion_info *item =
			smc_ilist_const_iter_get(&iter);

		if (!smc_shared_intrusion_target_add(target, item->pc, item->info)) {
			struct smc_intrusion_info added;

			while (smc_ilist_size(&target->pc_list) > old_size) {
				smc_ilist_pop_front(&target->pc_list, &added);
				smc_compatible_state_destroy(added.info);
			}
			smc_target_set_fitness(&target->base, old_fitness);
			return false;
		}
	}
	return true;
}

/** Глубоко копирует @target с флагами выделения @gfp. Intrusion копирует весь
 * PC/state-список и настройки; при частичной ошибке уничтожает копию. */
static struct smc_target *target_copy(const struct smc_target *target,
				      gfp_t gfp)
{
	switch (target->type) {
	case SMC_SHARED_TARGET_COLLECTION_TYPE:
		return smc_shared_collection_target_create(gfp);
	case SMC_SHARED_TARGET_INTRUSION_TYPE: {
		const struct smc_shared_intrusion_target *source = container_of(target,
			struct smc_shared_intrusion_target, base);
		struct smc_target *copy_base;
		struct smc_shared_intrusion_target *copy;
		struct smc_ilist_const_iter iter;
		struct smc_ilist_const_iter end;

		copy_base = smc_shared_intrusion_target_create_full(0, NULL,
			target->raw_fitness, source->list_limit,
			source->enable_interesting_check, gfp);
		if (!copy_base)
			return NULL;
		copy = container_of(copy_base, struct smc_shared_intrusion_target,
			base);
		end = smc_ilist_cend(&source->pc_list);
		for (iter = smc_ilist_cbegin(&source->pc_list);
		     !smc_ilist_const_iter_equal(&iter, &end);
		     smc_ilist_const_iter_next(&iter)) {
			const struct smc_intrusion_info *item =
				smc_ilist_const_iter_get(&iter);

			if (!smc_shared_intrusion_target_add(copy, item->pc,
				item->info)) {
				copy_base->ops->destroy(copy_base);
				return NULL;
			}
		}
		return copy_base;
	}
	case SMC_SHARED_TARGET_MONITORING_TYPE: {
		const struct smc_shared_monitoring_target *m = container_of(target,
			struct smc_shared_monitoring_target, base);

		return smc_shared_monitoring_target_create(m->first_pc,
			m->second_pc, target->raw_fitness, gfp);
	}
	default:
		return NULL;
	}
}

/** Return: содержит ли intrusion-цель @base хотя бы один ненулевой PC;
 * пустая или состоящая из нулевых адресов цель недостижима. */
static bool intrusion_feasible(const struct smc_target *base)
{
	const struct smc_shared_intrusion_target *target =
		container_of(base, struct smc_shared_intrusion_target, base);
	struct smc_ilist_const_iter iter;
	struct smc_ilist_const_iter end;

	end = smc_ilist_cend(&target->pc_list);
	for (iter = smc_ilist_cbegin(&target->pc_list);
	     !smc_ilist_const_iter_equal(&iter, &end);
	     smc_ilist_const_iter_next(&iter)) {
		const struct smc_intrusion_info *item =
			smc_ilist_const_iter_get(&iter);

		if (item->pc)
			return true;
	}
	return false;
}

/** Печатает fitness/размер/limit intrusion-цели @base и каждый её PC/state.
 * Функция предназначена для диагностики и пишет в kernel log. */
static void intrusion_print(const struct smc_target *base)
{
	const struct smc_shared_intrusion_target *target =
		container_of(base, struct smc_shared_intrusion_target, base);
	struct smc_ilist_const_iter iter;
	struct smc_ilist_const_iter end;

	pr_info("KTSAN SMC: intrusion target fitness=%d size=%lu limit=%u\n",
		base->raw_fitness, smc_ilist_size(&target->pc_list),
		target->list_limit);
	end = smc_ilist_cend(&target->pc_list);
	for (iter = smc_ilist_cbegin(&target->pc_list);
	     !smc_ilist_const_iter_equal(&iter, &end);
	     smc_ilist_const_iter_next(&iter)) {
		const struct smc_intrusion_info *item =
			smc_ilist_const_iter_get(&iter);

		pr_info("KTSAN SMC:   intrusion pc=%px state=%px\n",
			(void *)item->pc, item->info);
	}
}

/** Уничтожает @base. Для intrusion сначала освобождает каждый compatible state
 * и узлы списка, затем общую выделенную структуру цели. */
static void target_destroy(struct smc_target *base)
{
	if (base->type == SMC_SHARED_TARGET_INTRUSION_TYPE) {
		struct smc_shared_intrusion_target *target = container_of(base,
			struct smc_shared_intrusion_target, base);
		struct smc_intrusion_info item;

		while (smc_ilist_pop_front(&target->pc_list, &item))
			smc_compatible_state_destroy(item.info);
	}
	kfree(base);
}

static const struct smc_target_ops collection_ops = {
	.is_related = collection_related, .equals = target_equals,
	.copy = target_copy, .destroy = target_destroy,
};
static const struct smc_target_ops intrusion_ops = {
	.is_related = intrusion_related, .equals = target_equals,
	.merge = intrusion_merge, .copy = target_copy,
	.is_feasible = intrusion_feasible, .print = intrusion_print,
	.destroy = target_destroy,
};
static const struct smc_target_ops monitoring_ops = {
	.is_related = monitoring_related, .equals = target_equals,
	.copy = target_copy, .destroy = target_destroy,
};

/** Инициализирует общую часть @target значениями @type/@fitness и таблицей
 * виртуальных методов @ops; остановка при создании выключена. */
static void init_target(struct smc_target *target, enum smc_target_type type,
			const struct smc_target_ops *ops, int fitness)
{
	smc_target_init(target, type, fitness, false);
	target->ops = ops;
}

/** Создаёт collection-цель с аллокатором @gfp, максимальным fitness и collect.
 * Return: владеющий указатель на base либо NULL при нехватке памяти. */
struct smc_target *smc_shared_collection_target_create(gfp_t gfp)
{
	struct smc_shared_collection_target *target = kzalloc(sizeof(*target), gfp);

	if (!target)
		return NULL;
	init_target(&target->base, SMC_SHARED_TARGET_COLLECTION_TYPE,
		&collection_ops, SMC_MAX_FITNESS);
	target->collect = true;
	return &target->base;
}

/** Создаёт intrusion-цель: необязательный @pc/@info, исходный @fitness,
 * максимум @list_limit, фильтр @enable_interesting_check и аллокатор @gfp.
 * State при добавлении копируется; нулевой limit заменяется значением default. */
struct smc_target *smc_shared_intrusion_target_create_full(smc_uptr_t pc,
	struct smc_compatible_state *info, int fitness,
	unsigned int list_limit, bool enable_interesting_check, gfp_t gfp)
{
	struct smc_shared_intrusion_target *target = kzalloc(sizeof(*target), gfp);

	if (!target)
		return NULL;
	init_target(&target->base, SMC_SHARED_TARGET_INTRUSION_TYPE,
		&intrusion_ops, fitness);
	target->list_limit = list_limit ? list_limit :
		SMC_INTRUSION_LIST_LIMIT_DEFAULT;
	target->enable_interesting_check = enable_interesting_check;
	smc_ilist_init(&target->pc_list, sizeof(struct smc_intrusion_info),
		gfp, NULL);
	if (pc && !smc_shared_intrusion_target_add(target, pc, info)) {
		target_destroy(&target->base);
		return NULL;
	}
	return &target->base;
}

/** Упрощённо создаёт одноадресную intrusion-цель для @pc с @fitness и @gfp,
 * без compatible state/interesting-фильтра. Return: новая цель либо NULL. */
struct smc_target *smc_shared_intrusion_target_create(smc_uptr_t pc,
					       int fitness, gfp_t gfp)
{
	return smc_shared_intrusion_target_create_full(pc, NULL, fitness,
		SMC_INTRUSION_LIST_LIMIT_DEFAULT, false, gfp);
}

/** Добавляет @pc и глубокую копию @info в @target. Проверяет NULL, нулевой PC
 * и limit; при ошибке вставки освобождает копию. Неинтересный state увеличивает
 * raw fitness при включённом фильтре. Return: был ли элемент добавлен. */
bool smc_shared_intrusion_target_add(struct smc_shared_intrusion_target *target,
	smc_uptr_t pc, const struct smc_compatible_state *info)
{
	struct smc_intrusion_info item;

	if (!target || !pc || smc_ilist_size(&target->pc_list) >= target->list_limit)
		return false;
	item.pc = pc;
	item.info = info ? smc_compatible_state_copy(info) : NULL;
	if (info && !item.info)
		return false;
	if (smc_ilist_push_front(&target->pc_list, &item)) {
		smc_compatible_state_destroy(item.info);
		return false;
	}
	if (target->enable_interesting_check && item.info &&
	    !smc_compatible_state_is_interesting(item.info))
		smc_target_set_fitness(&target->base,
			target->base.raw_fitness + 1);
	return true;
}

/** Ищет в @target состояние адреса @pc. Return: заимствованный state либо NULL;
 * вызывающий код не должен освобождать возвращённый указатель. */
const struct smc_compatible_state *smc_shared_intrusion_target_get_state(
	const struct smc_shared_intrusion_target *target, smc_uptr_t pc)
{
	const struct smc_intrusion_info *item = target ?
		intrusion_find(target, pc) : NULL;

	return item ? item->info : NULL;
}

/** Return: первый PC внутреннего списка @target или 0 для NULL/пустой цели.
 * Порядок соответствует реализации списка и не является сортировкой адресов. */
smc_uptr_t smc_shared_intrusion_target_first_pc(
	const struct smc_shared_intrusion_target *target)
{
	struct smc_ilist_const_iter iter;
	const struct smc_intrusion_info *item;

	if (!target)
		return 0;
	iter = smc_ilist_cbegin(&target->pc_list);
	item = smc_ilist_const_iter_get(&iter);
	return item ? item->pc : 0;
}

/** Return: число PC/state-элементов в @target; для NULL возвращает ноль. */
unsigned int smc_shared_intrusion_target_size(
	const struct smc_shared_intrusion_target *target)
{
	return target ? smc_ilist_size(&target->pc_list) : 0;
}

/** Создаёт monitoring-цель для пары @first_pc/@second_pc с @fitness, используя
 * флаги @gfp. Return: новая принадлежащая вызывающему цель либо NULL. */
struct smc_target *smc_shared_monitoring_target_create(smc_uptr_t first_pc,
		smc_uptr_t second_pc, int fitness, gfp_t gfp)
{
	struct smc_shared_monitoring_target *target = kzalloc(sizeof(*target), gfp);

	if (!target)
		return NULL;
	init_target(&target->base, SMC_SHARED_TARGET_MONITORING_TYPE,
		&monitoring_ops, fitness);
	target->first_pc = first_pc;
	target->second_pc = second_pc;
	return &target->base;
}

/** Проверяет присутствие @pc в @target: весь intrusion-список, оба monitoring
 * адреса или любой PC для random-shared. NULL/прочие типы дают false. */
bool smc_watchpoint_target_has_pc(const struct smc_target *target,
				  smc_uptr_t pc)
{
	if (!target)
		return false;
	if (target->type == SMC_SHARED_TARGET_INTRUSION_TYPE)
		return intrusion_find(container_of(target,
			struct smc_shared_intrusion_target, base), pc) != NULL;
	if (target->type == SMC_SHARED_TARGET_MONITORING_TYPE) {
		const struct smc_shared_monitoring_target *m = container_of(target,
			struct smc_shared_monitoring_target, base);

		return m->first_pc == pc || m->second_pc == pc;
	}
	return target->type == SMC_RANDOM_SHARED_TARGET_TYPE;
}
