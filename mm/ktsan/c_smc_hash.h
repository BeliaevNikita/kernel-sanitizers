
#ifndef SMC_HASH_C_H
#define SMC_HASH_C_H

#include <linux/string.h>
#include <linux/types.h>

#ifndef SMC_HASH_UPTR
#define SMC_HASH_UPTR unsigned long
#endif

typedef SMC_HASH_UPTR smc_hash_uptr_t;

#define SMC_COVERAGE_BITS (1UL << 16)
#define SMC_COVERAGE_PRIME_MOD 65371UL
#define SMC_BITS_PER_WORD (sizeof(smc_hash_uptr_t) * 8)
#define SMC_COVERAGE_WORDS (SMC_COVERAGE_BITS / SMC_BITS_PER_WORD)

struct smc_bitmap {
	smc_hash_uptr_t map[SMC_COVERAGE_WORDS];
};

struct smc_coverage {
	struct smc_bitmap current_bitmap;
	struct smc_bitmap total;
};

static inline void smc_hash_add(smc_hash_uptr_t *hash,
				smc_hash_uptr_t data)
{
	if (data)
		*hash = 31 * (*hash) + data;
}

static inline smc_hash_uptr_t
smc_hash_shared_access(smc_hash_uptr_t old_pc,
		       smc_hash_uptr_t cur_pc,
		       smc_hash_uptr_t analysis_hash)
{
	smc_hash_uptr_t hash = 0;

	smc_hash_add(&hash, old_pc);
	smc_hash_add(&hash, cur_pc);
	smc_hash_add(&hash, analysis_hash);

	return hash;
}

static inline void smc_bitmap_reset(struct smc_bitmap *bitmap)
{
	memset(bitmap->map, 0, sizeof(bitmap->map));
}

static inline void smc_coverage_init(struct smc_coverage *coverage)
{
	smc_bitmap_reset(&coverage->current_bitmap);
	smc_bitmap_reset(&coverage->total);
}

static inline bool smc_bitmap_add_value(struct smc_bitmap *bitmap,
					smc_hash_uptr_t value)
{
	smc_hash_uptr_t idx = value % SMC_COVERAGE_BITS;
	smc_hash_uptr_t word_idx = idx / SMC_BITS_PER_WORD;
	smc_hash_uptr_t bit_idx = idx % SMC_BITS_PER_WORD;
	smc_hash_uptr_t old_word = bitmap->map[word_idx];
	smc_hash_uptr_t new_word = old_word | ((smc_hash_uptr_t)1 << bit_idx);

	bitmap->map[word_idx] = new_word;
	return new_word != old_word;
}

static inline bool smc_bitmap_add_value_mod_prime(struct smc_bitmap *bitmap,
						  smc_hash_uptr_t value)
{
	return smc_bitmap_add_value(bitmap, value % SMC_COVERAGE_PRIME_MOD);
}

static inline bool smc_bitmap_get(const struct smc_bitmap *bitmap,
				  smc_hash_uptr_t idx)
{
	smc_hash_uptr_t word_idx;
	smc_hash_uptr_t bit_idx;

	if (idx >= SMC_COVERAGE_BITS)
		return false;

	word_idx = idx / SMC_BITS_PER_WORD;
	bit_idx = idx % SMC_BITS_PER_WORD;

	return (bitmap->map[word_idx] & ((smc_hash_uptr_t)1 << bit_idx)) != 0;
}

static inline bool smc_bitmap_copy_from(struct smc_bitmap *dst,
					const struct smc_bitmap *src)
{
	bool has_new_bit = false;
	size_t i;

	for (i = 0; i < SMC_COVERAGE_WORDS; i++) {
		smc_hash_uptr_t old_word = dst->map[i];
		smc_hash_uptr_t new_word = old_word | src->map[i];

		if (new_word != old_word)
			has_new_bit = true;

		dst->map[i] = new_word;
	}

	return has_new_bit;
}

static inline unsigned int
smc_bitmap_count_bits(const struct smc_bitmap *bitmap)
{
	unsigned int result = 0;
	size_t i;

	for (i = 0; i < SMC_COVERAGE_WORDS; i++) {
		smc_hash_uptr_t word = bitmap->map[i];

		while (word) {
			result += (unsigned int)(word & 1);
			word >>= 1;
		}
	}

	return result;
}

static inline void smc_coverage_reset_current(struct smc_coverage *coverage)
{
	smc_bitmap_reset(&coverage->current_bitmap);
}

static inline bool smc_coverage_add_hash(struct smc_coverage *coverage,
					 smc_hash_uptr_t hash)
{
	if (!hash)
		return false;

	return smc_bitmap_add_value(&coverage->current_bitmap, hash);
}

static inline bool
smc_coverage_add_shared_access(struct smc_coverage *coverage,
			       smc_hash_uptr_t old_pc,
			       smc_hash_uptr_t cur_pc,
			       smc_hash_uptr_t analysis_hash)
{
	smc_hash_uptr_t hash;

	hash = smc_hash_shared_access(old_pc, cur_pc, analysis_hash);
	return smc_coverage_add_hash(coverage, hash);
}

static inline bool smc_coverage_save_current(struct smc_coverage *coverage)
{
	return smc_bitmap_copy_from(&coverage->total,
				    &coverage->current_bitmap);
}

static inline unsigned int
smc_coverage_current_size(const struct smc_coverage *coverage)
{
	return smc_bitmap_count_bits(&coverage->current_bitmap);
}

static inline unsigned int
smc_coverage_total_size(const struct smc_coverage *coverage)
{
	return smc_bitmap_count_bits(&coverage->total);
}

#endif
