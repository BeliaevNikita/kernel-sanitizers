#include <linux/slab.h>

#include "c_smc_analysis.h"
#include "c_smc_waitlist.h"

/**
 * smc_dfs_waitlist_init - инициализировать очередь целей в режиме DFS.
 * @waitlist: заранее выделенная структура очереди.
 *
 * Создаёт внутренний список-стек указателей на цели. GFP_ATOMIC позволяет
 * позднее добавлять элементы из инструментированного атомарного контекста.
 */
void smc_dfs_waitlist_init(struct smc_dfs_waitlist *waitlist)
{
	smc_ilist_init(&waitlist->stack, sizeof(struct smc_target *),
		GFP_ATOMIC, NULL);
	waitlist->target_file_num = 0;
}

/**
 * smc_dfs_waitlist_destroy - уничтожить очередь и все оставшиеся в ней цели.
 * @waitlist: очередь DFS, ранее инициализированная этой подсистемой.
 *
 * Извлекает каждый указатель и вызывает виртуальный destroy цели. После
 * вызова сохранённые в очереди указатели использовать нельзя.
 */
void smc_dfs_waitlist_destroy(struct smc_dfs_waitlist *waitlist)
{
	struct smc_target *target;
	while (smc_ilist_pop_front(&waitlist->stack, &target))
		if (target && target->ops && target->ops->destroy)
			target->ops->destroy(target);
}

/**
 * smc_dfs_waitlist_get_next - забрать следующую DFS-цель.
 * @waitlist: очередь, из которой удаляется верхний элемент стека.
 *
 * Return: переданная вызывающему сторона цель либо NULL для пустой очереди.
 * Владение возвращённой целью переходит вызывающему коду.
 */
struct smc_target *smc_dfs_waitlist_get_next(struct smc_dfs_waitlist *waitlist)
{
	struct smc_target *target = NULL;
	smc_ilist_pop_front(&waitlist->stack, &target);
	return target;
}

/**
 * smc_dfs_waitlist_add - добавить уникальную цель в начало DFS-стека.
 * @waitlist: очередь назначения.
 * @target: новая цель; функция не освобождает её при отказе.
 *
 * Перед вставкой сравнивает цель со всеми ожидающими целями через их
 * полиморфный equals. Return: true при передаче владения очереди, false при
 * дубликате или ошибке выделения памяти.
 */
bool smc_dfs_waitlist_add(struct smc_dfs_waitlist *waitlist,
			  struct smc_target *target)
{
	struct smc_ilist_const_iter iter, end;
	for (iter = smc_ilist_cbegin(&waitlist->stack),
	     end = smc_ilist_cend(&waitlist->stack);
	     !smc_ilist_const_iter_equal(&iter, &end);
	     smc_ilist_const_iter_next(&iter)) {
		struct smc_target *const *queued = smc_ilist_const_iter_get(&iter);
		if (smc_target_equals(*queued, target))
			return false;
	}
	return smc_ilist_push_front(&waitlist->stack, &target) == 0;
}

/**
 * smc_dfs_waitlist_size - получить число ожидающих DFS-целей.
 * @waitlist: исследуемая очередь.
 * Return: текущее число элементов внутреннего стека.
 */
unsigned int smc_dfs_waitlist_size(const struct smc_dfs_waitlist *waitlist)
{
	return smc_ilist_size(&waitlist->stack);
}

void smc_target_difference_waitlist_init(
	struct smc_target_difference_waitlist *waitlist)
{
	unsigned int i;

	memset(waitlist, 0, sizeof(*waitlist));
	for (i = 0; i < SMC_WAITLIST_KEYS; i++)
		smc_dfs_waitlist_init(&waitlist->buckets[i]);
}

void smc_target_difference_waitlist_destroy(
	struct smc_target_difference_waitlist *waitlist)
{
	unsigned int i;

	for (i = 0; i < SMC_WAITLIST_KEYS; i++)
		smc_dfs_waitlist_destroy(&waitlist->buckets[i]);
}

int smc_target_difference_waitlist_get_key(
	const struct smc_target_difference_waitlist *waitlist,
	const struct smc_target *target)
{
	(void)waitlist;
	if (!target)
		return 0;
	return min_t(unsigned int, target->fitness, SMC_WAITLIST_KEYS - 1);
}

static bool smc_target_difference_find(
	struct smc_target_difference_waitlist *waitlist,
	struct smc_target *target, unsigned int *bucket_out,
	struct smc_ilist_iter *iter_out)
{
	unsigned int bucket;

	for (bucket = 0; bucket < SMC_WAITLIST_KEYS; bucket++) {
		struct smc_ilist_iter iter =
			smc_ilist_begin(&waitlist->buckets[bucket].stack);
		struct smc_ilist_iter end =
			smc_ilist_end(&waitlist->buckets[bucket].stack);

		while (!smc_ilist_iter_equal(&iter, &end)) {
			struct smc_target **queued = smc_ilist_iter_get(&iter);

			if (smc_target_equals(*queued, target)) {
				*bucket_out = bucket;
				*iter_out = iter;
				return true;
			}
			smc_ilist_iter_next(&iter);
		}
	}
	return false;
}

static bool smc_target_difference_waitlist_add(
	struct smc_target_difference_waitlist *waitlist,
	struct smc_target *target)
{
	struct smc_ilist_iter duplicate_iter;
	unsigned int duplicate_bucket;
	unsigned int bucket;

	bucket = smc_target_difference_waitlist_get_key(waitlist, target);
	if (smc_target_difference_find(waitlist, target, &duplicate_bucket,
				       &duplicate_iter)) {
		struct smc_target **queued = smc_ilist_iter_get(&duplicate_iter);
		struct smc_target *existing = *queued;

		if (target->raw_fitness < existing->raw_fitness) {
			unsigned int improved_bucket;
			int old_raw_fitness = existing->raw_fitness;

			smc_target_set_fitness(existing, target->raw_fitness);
			improved_bucket = smc_target_difference_waitlist_get_key(
				waitlist, existing);
			if (improved_bucket != duplicate_bucket) {
				if (!smc_ilist_push_front(
					    &waitlist->buckets[improved_bucket].stack,
					    &existing))
					smc_ilist_iter_remove(&duplicate_iter);
				else
					smc_target_set_fitness(existing,
						old_raw_fitness);
			}
		}
		return false;
	}
	if (smc_ilist_push_front(&waitlist->buckets[bucket].stack, &target))
		return false;
	waitlist->queued[bucket]++;
	return true;
}

static struct smc_target *smc_target_difference_waitlist_get_next(
	struct smc_target_difference_waitlist *waitlist)
{
	struct smc_target *target;
	unsigned int bucket;

	for (bucket = 0; bucket < SMC_WAITLIST_KEYS; bucket++) {
		target = smc_dfs_waitlist_get_next(&waitlist->buckets[bucket]);
		if (target) {
			waitlist->selected[bucket]++;
			return target;
		}
	}
	return NULL;
}

static unsigned int smc_target_difference_waitlist_size(
	const struct smc_target_difference_waitlist *waitlist)
{
	unsigned int bucket;
	unsigned int size = 0;

	for (bucket = 0; bucket < SMC_WAITLIST_KEYS; bucket++)
		size += smc_dfs_waitlist_size(&waitlist->buckets[bucket]);
	return size;
}

/**
 * smc_waitlist_init - инициализировать универсальную очередь целей.
 * @waitlist: структура-обёртка очереди.
 * @type: выбранная стратегия обхода; сейчас реализована только DFS.
 *
 * Обнуляет union и подготавливает DFS-представление.
 */
void smc_waitlist_init(struct smc_waitlist *waitlist,
		       enum smc_waitlist_type type)
{
	memset(waitlist, 0, sizeof(*waitlist));
	waitlist->type = type;
	if (type == SMC_WAITLIST_TARGET_DIFFERENCE)
		smc_target_difference_waitlist_init(
			&waitlist->data.target_difference);
	else
		smc_dfs_waitlist_init(&waitlist->data.dfs);
}

/**
 * smc_waitlist_destroy - освободить содержимое универсальной очереди.
 * @waitlist: очередь и принадлежащие ей ещё не выбранные цели.
 */
void smc_waitlist_destroy(struct smc_waitlist *waitlist)
{
	if (waitlist->type == SMC_WAITLIST_TARGET_DIFFERENCE)
		smc_target_difference_waitlist_destroy(
			&waitlist->data.target_difference);
	else
		smc_dfs_waitlist_destroy(&waitlist->data.dfs);
}

/**
 * smc_waitlist_get_next - извлечь следующую цель выбранной стратегии.
 * @waitlist: универсальная очередь.
 * Return: цель с переданным вызывающему владением либо NULL.
 */
struct smc_target *smc_waitlist_get_next(struct smc_waitlist *waitlist)
{
	if (waitlist->type == SMC_WAITLIST_TARGET_DIFFERENCE)
		return smc_target_difference_waitlist_get_next(
			&waitlist->data.target_difference);
	return smc_dfs_waitlist_get_next(&waitlist->data.dfs);
}

/**
 * smc_waitlist_add - поставить цель в универсальную очередь.
 * @waitlist: очередь назначения.
 * @target: цель, владение которой переходит очереди только при успехе.
 * Return: true при вставке, false при дубликате или нехватке памяти.
 */
bool smc_waitlist_add(struct smc_waitlist *waitlist, struct smc_target *target)
{
	if (waitlist->type == SMC_WAITLIST_TARGET_DIFFERENCE)
		return smc_target_difference_waitlist_add(
			&waitlist->data.target_difference, target);
	return smc_dfs_waitlist_add(&waitlist->data.dfs, target);
}

/**
 * smc_waitlist_size - узнать число ожидающих целей.
 * @waitlist: универсальная очередь.
 * Return: число целей, ещё не извлечённых алгоритмом.
 */
unsigned int smc_waitlist_size(const struct smc_waitlist *waitlist)
{
	if (waitlist->type == SMC_WAITLIST_TARGET_DIFFERENCE)
		return smc_target_difference_waitlist_size(
			&waitlist->data.target_difference);
	return smc_dfs_waitlist_size(&waitlist->data.dfs);
}

void smc_waitlist_print_and_reset_statistics(struct smc_waitlist *waitlist)
{
	struct smc_target_difference_waitlist *fitness;
	unsigned int bucket;

	if (!waitlist || waitlist->type != SMC_WAITLIST_TARGET_DIFFERENCE)
		return;
	fitness = &waitlist->data.target_difference;
	for (bucket = 0; bucket < SMC_WAITLIST_KEYS; bucket++) {
		if (fitness->queued[bucket] || fitness->selected[bucket])
			pr_info("KTSAN SMC fitness: bucket=%u queued=%llu selected=%llu pending=%u\n",
				bucket, fitness->queued[bucket],
				fitness->selected[bucket],
				smc_dfs_waitlist_size(&fitness->buckets[bucket]));
		fitness->queued[bucket] = 0;
		fitness->selected[bucket] = 0;
	}
}
