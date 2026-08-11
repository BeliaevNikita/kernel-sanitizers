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
	smc_dfs_waitlist_init(&waitlist->data.dfs);
}

/**
 * smc_waitlist_destroy - освободить содержимое универсальной очереди.
 * @waitlist: очередь и принадлежащие ей ещё не выбранные цели.
 */
void smc_waitlist_destroy(struct smc_waitlist *waitlist)
{
	smc_dfs_waitlist_destroy(&waitlist->data.dfs);
}

/**
 * smc_waitlist_get_next - извлечь следующую цель выбранной стратегии.
 * @waitlist: универсальная очередь.
 * Return: цель с переданным вызывающему владением либо NULL.
 */
struct smc_target *smc_waitlist_get_next(struct smc_waitlist *waitlist)
{
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
	return smc_dfs_waitlist_add(&waitlist->data.dfs, target);
}

/**
 * smc_waitlist_size - узнать число ожидающих целей.
 * @waitlist: универсальная очередь.
 * Return: число целей, ещё не извлечённых алгоритмом.
 */
unsigned int smc_waitlist_size(const struct smc_waitlist *waitlist)
{
	return smc_dfs_waitlist_size(&waitlist->data.dfs);
}
