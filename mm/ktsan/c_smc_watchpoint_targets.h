#ifndef C_SMC_WATCHPOINT_TARGETS_H
#define C_SMC_WATCHPOINT_TARGETS_H

#include "c_smc_analysis.h"

#define SMC_INTRUSION_LIST_LIMIT_DEFAULT 1

struct smc_intrusion_info {
	smc_uptr_t pc;
	struct smc_compatible_state *info;
};

struct smc_shared_collection_target {
	struct smc_target base;
	bool collect;
};

struct smc_shared_intrusion_target {
	struct smc_target base;
	unsigned int list_limit;
	bool enable_interesting_check;
	struct smc_ilist pc_list;
};

struct smc_shared_monitoring_target {
	struct smc_target base;
	smc_uptr_t first_pc;
	smc_uptr_t second_pc;
};

struct smc_target *smc_shared_collection_target_create(gfp_t gfp);
struct smc_target *smc_shared_intrusion_target_create(smc_uptr_t pc,
					       int fitness, gfp_t gfp);
struct smc_target *smc_shared_intrusion_target_create_full(smc_uptr_t pc,
	struct smc_compatible_state *info, int fitness,
	unsigned int list_limit, bool enable_interesting_check, gfp_t gfp);
bool smc_shared_intrusion_target_add(struct smc_shared_intrusion_target *target,
	smc_uptr_t pc, const struct smc_compatible_state *info);
const struct smc_compatible_state *smc_shared_intrusion_target_get_state(
	const struct smc_shared_intrusion_target *target, smc_uptr_t pc);
smc_uptr_t smc_shared_intrusion_target_first_pc(
	const struct smc_shared_intrusion_target *target);
unsigned int smc_shared_intrusion_target_size(
	const struct smc_shared_intrusion_target *target);
struct smc_target *smc_shared_monitoring_target_create(smc_uptr_t first_pc,
		smc_uptr_t second_pc, int fitness, gfp_t gfp);
bool smc_watchpoint_target_has_pc(const struct smc_target *target,
				  smc_uptr_t pc);

#endif
