// SPDX-License-Identifier: GPL-2.0
#include <linux/slab.h>

#include "c_smc_analysis.h"
#include "c_smc_watchpoint.h"

/** Печатает @state через реализацию, выбранную по типу; NULL игнорируется. */
void smc_local_state_print(const struct smc_local_state *state)
{
	if (!state)
		return;
	if (state->type == SMC_WP_LOCAL_STATE_TYPE)
		smc_watchpoint_local_state_print(container_of(state,
			const struct smc_watchpoint_local_state, base));
}

/**
 * Получает compatible state для @state с учётом @global_state. Watchpoint сам
 * снимок не создаёт и передаёт запрос паре вложенных local/global states.
 * Return: новый объект с владением вызывающей стороны либо NULL.
 */
struct smc_compatible_state *
smc_local_state_get_compatible_state(const struct smc_local_state *state,
				     struct smc_global_state *global_state)
{
	const struct smc_watchpoint_local_state *local;
	struct smc_watchpoint_global_state *global;

	if (!state || !global_state || state->type != SMC_WP_LOCAL_STATE_TYPE ||
	    global_state->type != SMC_WATCHPOINT_GLOBAL_STATE_TYPE)
		return NULL;
	local = container_of(state,
		const struct smc_watchpoint_local_state, base);
	global = container_of(global_state,
		struct smc_watchpoint_global_state, base);
	return local->inner && global->inner ?
		smc_local_state_get_compatible_state(local->inner, global->inner) :
		NULL;
}

/** Сбрасывает зависящие от итерации поля @state, сохраняя сам объект. */
void smc_local_state_reset(struct smc_local_state *state)
{
	if (state && state->type == SMC_WP_LOCAL_STATE_TYPE)
		smc_watchpoint_local_state_reset(container_of(state,
			struct smc_watchpoint_local_state, base));
}

/** Освобождает ресурсы и сам динамически выделенный объект @state. */
void smc_local_state_destroy(struct smc_local_state *state)
{
	if (!state)
		return;
	if (state->type == SMC_WP_LOCAL_STATE_TYPE)
		smc_watchpoint_local_state_destroy(container_of(state,
			struct smc_watchpoint_local_state, base));
	kfree(state);
}
