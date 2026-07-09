#ifndef C_SMC_WAITLIST_H
#define C_SMC_WAITLIST_H

#include <linux/types.h>

#include "c_smc_data.h"

#define SMC_WAITLIST_KEYS 10
#define SMC_TARGET_TYPES 10
#define SMC_GAMETE_LIMIT 10000

struct file;
struct smc_serializer;
struct smc_target;

enum smc_waitlist_type {
	SMC_WAITLIST_DFS,
	SMC_WAITLIST_TARGET_DIFFERENCE,
};

enum smc_reached_set_type {
	SMC_REACHED_SET_DEFAULT,
};

struct smc_partitioned_waitlist {
	struct smc_waitlist *waitlists[SMC_WAITLIST_KEYS];
};

struct smc_dfs_waitlist {
	struct smc_ilist stack;
	unsigned int target_file_num;
};

struct smc_target_difference_waitlist {
	struct smc_partitioned_waitlist partitioned;
};

struct smc_default_reached {
	struct smc_ilist *cmap[SMC_TARGET_TYPES];
	struct smc_ilist gset;
	struct smc_ilist iteration_targets;
	struct smc_waitlist *waitlist;
	int cross_infeasible_targets;
	int cross_feasible_targets;
	int cross_null_targets;
	bool first_only;
};

union smc_waitlist_data {
	struct smc_dfs_waitlist dfs;
	struct smc_target_difference_waitlist target_difference;
};

struct smc_waitlist {
	enum smc_waitlist_type type;
	union smc_waitlist_data data;
};

union smc_reached_set_data {
	struct smc_default_reached default_reached;
};

struct smc_reached_set {
	enum smc_reached_set_type type;
	union smc_reached_set_data data;
};

void smc_waitlist_init(struct smc_waitlist *waitlist,
		       enum smc_waitlist_type type);
void smc_waitlist_destroy(struct smc_waitlist *waitlist);
struct smc_target *smc_waitlist_get_next(struct smc_waitlist *waitlist);
bool smc_waitlist_add(struct smc_waitlist *waitlist,
		      struct smc_target *target);
unsigned int smc_waitlist_size(const struct smc_waitlist *waitlist);
void smc_waitlist_serialize(const struct smc_waitlist *waitlist,
			    struct smc_serializer *ser);
int smc_waitlist_serialize_wrapper(const struct smc_waitlist *waitlist,
				   const char *dir_name);

void smc_reached_set_init(struct smc_reached_set *reached_set,
			  enum smc_reached_set_type type);
void smc_reached_set_destroy(struct smc_reached_set *reached_set);
bool smc_reached_set_add_iteration_target(struct smc_reached_set *reached_set,
					  struct smc_target *target);
void smc_reached_set_move_iteration_targets(
	struct smc_reached_set *reached_set);
struct smc_waitlist *
smc_reached_set_move_and_reset_waitlist(struct smc_reached_set *reached_set);
struct smc_target *smc_reached_set_get_next(
	struct smc_reached_set *reached_set);
int smc_reached_set_get_waitlist_size(
	const struct smc_reached_set *reached_set);
unsigned int smc_reached_set_size(const struct smc_reached_set *reached_set);
int smc_reached_set_get_target_size(
	const struct smc_reached_set *reached_set);
void smc_reached_set_reset(struct smc_reached_set *reached_set);
void smc_reached_set_print_statistics(
	const struct smc_reached_set *reached_set);
void smc_reached_set_serialize(const struct smc_reached_set *reached_set,
			       struct smc_serializer *ser);
int smc_reached_set_serialize_wrapper(
	const struct smc_reached_set *reached_set, const char *dir_name);
void smc_reached_set_add_targets_from_file(struct smc_reached_set *reached_set,
					   struct file *file);
void smc_reached_set_add_targets_from_serializer(
	struct smc_reached_set *reached_set, struct smc_serializer *ser);
bool smc_reached_set_try_to_add_complete_target(
	struct smc_reached_set *reached_set, struct smc_target *target);

void smc_partitioned_waitlist_init(
	struct smc_partitioned_waitlist *waitlist,
	enum smc_waitlist_type type);
void smc_partitioned_waitlist_destroy(
	struct smc_partitioned_waitlist *waitlist);
struct smc_target *smc_partitioned_waitlist_get_next(
	struct smc_partitioned_waitlist *waitlist);
bool smc_partitioned_waitlist_add(
	struct smc_partitioned_waitlist *waitlist, struct smc_target *target);
unsigned int smc_partitioned_waitlist_size(
	const struct smc_partitioned_waitlist *waitlist);
void smc_partitioned_waitlist_serialize(
	const struct smc_partitioned_waitlist *waitlist,
	struct smc_serializer *ser);
int smc_partitioned_waitlist_serialize_wrapper(
	const struct smc_partitioned_waitlist *waitlist, const char *dir_name);
int smc_partitioned_waitlist_get_key(
	const struct smc_partitioned_waitlist *waitlist,
	const struct smc_target *target);

void smc_dfs_waitlist_init(struct smc_dfs_waitlist *waitlist);
void smc_dfs_waitlist_destroy(struct smc_dfs_waitlist *waitlist);
struct smc_target *smc_dfs_waitlist_get_next(
	struct smc_dfs_waitlist *waitlist);
bool smc_dfs_waitlist_add(struct smc_dfs_waitlist *waitlist,
			  struct smc_target *target);
unsigned int smc_dfs_waitlist_size(const struct smc_dfs_waitlist *waitlist);
void smc_dfs_waitlist_serialize(const struct smc_dfs_waitlist *waitlist,
				struct smc_serializer *ser);
int smc_dfs_waitlist_serialize_wrapper(
	const struct smc_dfs_waitlist *waitlist, const char *dir_name);

void smc_target_difference_waitlist_init(
	struct smc_target_difference_waitlist *waitlist);
void smc_target_difference_waitlist_destroy(
	struct smc_target_difference_waitlist *waitlist);
int smc_target_difference_waitlist_get_key(
	const struct smc_target_difference_waitlist *waitlist,
	const struct smc_target *target);

void smc_default_reached_init(struct smc_default_reached *reached,
			      bool first_only);
void smc_default_reached_destroy(struct smc_default_reached *reached);
void smc_default_reached_reset(struct smc_default_reached *reached);
void smc_default_reached_reset_gset(struct smc_default_reached *reached);
void smc_default_reached_reset_iteration_targets(
	struct smc_default_reached *reached);
void smc_default_reached_move_iteration_targets(
	struct smc_default_reached *reached);
struct smc_waitlist *
smc_default_reached_move_and_reset_waitlist(
	struct smc_default_reached *reached);
struct smc_target *smc_default_reached_get_next(
	struct smc_default_reached *reached);
bool smc_default_reached_add_iteration_target(
	struct smc_default_reached *reached, struct smc_target *target);
int smc_default_reached_get_waitlist_size(
	const struct smc_default_reached *reached);
unsigned int smc_default_reached_size(
	const struct smc_default_reached *reached);
int smc_default_reached_get_target_size(
	const struct smc_default_reached *reached);
void smc_default_reached_print_statistics(
	const struct smc_default_reached *reached);
void smc_default_reached_serialize(
	const struct smc_default_reached *reached, struct smc_serializer *ser);
int smc_default_reached_serialize_wrapper(
	const struct smc_default_reached *reached, const char *dir_name);
void smc_default_reached_add_targets_from_file(
	struct smc_default_reached *reached, struct file *file);
void smc_default_reached_add_targets_from_serializer(
	struct smc_default_reached *reached, struct smc_serializer *ser);
bool smc_default_reached_try_to_add_complete_target(
	struct smc_default_reached *reached, struct smc_target *target);
bool smc_default_reached_try_to_add_target(
	struct smc_default_reached *reached, struct smc_target *target);
bool smc_default_reached_add_complete_target(
	struct smc_default_reached *reached, struct smc_target *target);
bool smc_default_reached_contains_gamete(
	const struct smc_default_reached *reached,
	const struct smc_target *target);
bool smc_default_reached_contains_target(
	const struct smc_default_reached *reached,
	const struct smc_target *target);
bool smc_default_reached_merge_target(
	struct smc_default_reached *reached, struct smc_target *target);
void smc_default_reached_try_to_add_crossovered_target(
	struct smc_default_reached *reached, struct smc_target *target);

#endif /* C_SMC_WAITLIST_H */
