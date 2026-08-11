#include <linux/slab.h>

#include "c_smc_analysis.h"
#include "c_smc_watchpoint.h"

/**
 * smc_global_state_reset - сбросить общее состояние перед новой итерацией.
 * @state: базовая часть состояния конкретного анализа; может быть NULL.
 *
 * Диспетчер выбирает реализацию по type. Память объекта сохраняется, поэтому
 * состояние можно использовать в следующей итерации с той же конфигурацией.
 */
void smc_global_state_reset(struct smc_global_state *state)
{
	if (!state)
		return;

	switch (state->type) {
	case SMC_WATCHPOINT_GLOBAL_STATE_TYPE:
		smc_watchpoint_global_state_reset(container_of(state,
			struct smc_watchpoint_global_state, base));
		break;
	default:
		break;
	}
}

/**
 * smc_global_state_print - напечатать общее состояние анализа.
 * @state: базовая часть состояния; NULL безопасно игнорируется.
 *
 * Для анализа-обёртки специализированный print также печатает inner state.
 */
void smc_global_state_print(const struct smc_global_state *state)
{
	if (!state)
		return;

	switch (state->type) {
	case SMC_WATCHPOINT_GLOBAL_STATE_TYPE:
		smc_watchpoint_global_state_print(container_of(state,
			const struct smc_watchpoint_global_state, base));
		break;
	default:
		break;
	}
}

/**
 * smc_global_state_destroy - уничтожить динамически созданное состояние.
 * @state: состояние, владение которым передано функции; NULL допустим.
 *
 * Сначала освобождает ресурсы конкретного типа и рекурсивные inner states,
 * затем сам объект. Эту функцию нельзя вызывать для встроенного внешнего
 * состояния WatchpointAnalysis: для него вызывается только типовой destroy.
 */
void smc_global_state_destroy(struct smc_global_state *state)
{
	bool heap_allocated;

	if (!state)
		return;
	heap_allocated = state->heap_allocated;

	switch (state->type) {
	case SMC_WATCHPOINT_GLOBAL_STATE_TYPE:
		smc_watchpoint_global_state_destroy(container_of(state,
			struct smc_watchpoint_global_state, base));
		break;
	default:
		break;
	}
	if (heap_allocated)
		kfree(state);
}
