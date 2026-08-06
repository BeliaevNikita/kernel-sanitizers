#ifndef C_SMC_DATA_H
#define C_SMC_DATA_H

#include <linux/errno.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

/*
 * These containers are used by the KTSAN runtime itself and are protected by
 * the SMC runtime lock.  list_empty() expands to READ_ONCE(), which is routed
 * through ktsan_atomic64_load() in this tree and would recursively re-enter
 * RaceHunter.  A plain load is the correct primitive while holding that lock.
 */
static inline bool smc_list_empty(const struct list_head *head)
{
	return head->next == head;
}

typedef unsigned long smc_uptr_t;

typedef bool (*smc_data_equal_fn)(const void *a, const void *b);

struct smc_ilist_node {
	struct list_head node;
	unsigned long long data_align;
	unsigned char data[];
};

struct smc_ilist {
	struct list_head head;
	size_t elem_size;
	smc_uptr_t size;
	gfp_t gfp;
	smc_data_equal_fn equal;
};

struct smc_ilist_iter {
	struct smc_ilist *list;
	struct smc_ilist_node *pos;
};

struct smc_ilist_const_iter {
	const struct smc_ilist *list;
	const struct smc_ilist_node *pos;
};

struct smc_map_entry {
	struct list_head node;
	unsigned long long data_align;
	unsigned char data[];
};

struct smc_map {
	struct list_head entries;
	size_t key_size;
	size_t value_size;
	size_t value_offset;
	smc_uptr_t size;
	gfp_t gfp;
	smc_data_equal_fn key_equal;
};

static inline size_t smc_align_size(size_t size, size_t align)
{
	return (size + align - 1) & ~(align - 1);
}

static inline bool smc_data_equal(const void *a, const void *b, size_t size,
				  smc_data_equal_fn equal)
{
	if (equal)
		return equal(a, b);

	return memcmp(a, b, size) == 0;
}

static inline void smc_ilist_init(struct smc_ilist *list, size_t elem_size,
				  gfp_t gfp, smc_data_equal_fn equal)
{
	INIT_LIST_HEAD(&list->head);
	list->elem_size = elem_size;
	list->size = 0;
	list->gfp = gfp;
	list->equal = equal;
}

static inline struct smc_ilist_node *
smc_ilist_alloc_node(const struct smc_ilist *list, const void *data)
{
	struct smc_ilist_node *node;

	node = kmalloc(sizeof(*node) + list->elem_size, list->gfp);
	if (!node)
		return NULL;

	memcpy(node->data, data, list->elem_size);
	return node;
}

static inline int smc_ilist_push_front(struct smc_ilist *list,
				       const void *data)
{
	struct smc_ilist_node *node;

	node = smc_ilist_alloc_node(list, data);
	if (!node)
		return -ENOMEM;

	list_add(&node->node, &list->head);
	list->size++;
	return 0;
}

static inline int smc_ilist_push_back(struct smc_ilist *list,
				      const void *data)
{
	struct smc_ilist_node *node;

	node = smc_ilist_alloc_node(list, data);
	if (!node)
		return -ENOMEM;

	list_add_tail(&node->node, &list->head);
	list->size++;
	return 0;
}

static inline bool smc_ilist_pop_front(struct smc_ilist *list, void *out)
{
	struct smc_ilist_node *node;

	if (smc_list_empty(&list->head))
		return false;

	node = list_first_entry(&list->head, struct smc_ilist_node, node);
	if (out)
		memcpy(out, node->data, list->elem_size);

	list_del(&node->node);
	kfree(node);
	list->size--;
	return true;
}

static inline bool smc_ilist_pop_back(struct smc_ilist *list, void *out)
{
	struct smc_ilist_node *node;

	if (smc_list_empty(&list->head))
		return false;

	node = list_last_entry(&list->head, struct smc_ilist_node, node);
	if (out)
		memcpy(out, node->data, list->elem_size);

	list_del(&node->node);
	kfree(node);
	list->size--;
	return true;
}

static inline void smc_ilist_clear(struct smc_ilist *list)
{
	struct smc_ilist_node *node;
	struct smc_ilist_node *tmp;

	list_for_each_entry_safe(node, tmp, &list->head, node) {
		list_del(&node->node);
		kfree(node);
	}

	list->size = 0;
}

static inline bool smc_ilist_contains(const struct smc_ilist *list,
				      const void *data)
{
	const struct smc_ilist_node *node;

	list_for_each_entry(node, &list->head, node) {
		if (smc_data_equal(node->data, data, list->elem_size,
				   list->equal))
			return true;
	}

	return false;
}

static inline bool smc_ilist_replace(struct smc_ilist *list,
				     const void *old_data,
				     const void *new_data)
{
	struct smc_ilist_node *node;

	list_for_each_entry(node, &list->head, node) {
		if (smc_data_equal(node->data, old_data, list->elem_size,
				   list->equal)) {
			memcpy(node->data, new_data, list->elem_size);
			return true;
		}
	}

	return false;
}

static inline smc_uptr_t smc_ilist_size(const struct smc_ilist *list)
{
	return list->size;
}

static inline bool smc_ilist_empty(const struct smc_ilist *list)
{
	return smc_list_empty(&list->head);
}

static inline struct smc_ilist_iter
smc_ilist_begin(struct smc_ilist *list)
{
	struct smc_ilist_iter iter;

	iter.list = list;
	iter.pos = smc_list_empty(&list->head) ? NULL :
		list_first_entry(&list->head, struct smc_ilist_node, node);
	return iter;
}

static inline struct smc_ilist_iter
smc_ilist_end(struct smc_ilist *list)
{
	struct smc_ilist_iter iter;

	iter.list = list;
	iter.pos = NULL;
	return iter;
}

static inline struct smc_ilist_const_iter
smc_ilist_cbegin(const struct smc_ilist *list)
{
	struct smc_ilist_const_iter iter;

	iter.list = list;
	iter.pos = smc_list_empty(&list->head) ? NULL :
		list_first_entry(&list->head, struct smc_ilist_node, node);
	return iter;
}

static inline struct smc_ilist_const_iter
smc_ilist_cend(const struct smc_ilist *list)
{
	struct smc_ilist_const_iter iter;

	iter.list = list;
	iter.pos = NULL;
	return iter;
}

static inline bool smc_ilist_iter_equal(const struct smc_ilist_iter *a,
					const struct smc_ilist_iter *b)
{
	return a->list == b->list && a->pos == b->pos;
}

static inline bool
smc_ilist_const_iter_equal(const struct smc_ilist_const_iter *a,
			   const struct smc_ilist_const_iter *b)
{
	return a->list == b->list && a->pos == b->pos;
}

static inline void *smc_ilist_iter_get(const struct smc_ilist_iter *iter)
{
	return iter->pos ? iter->pos->data : NULL;
}

static inline const void *
smc_ilist_const_iter_get(const struct smc_ilist_const_iter *iter)
{
	return iter->pos ? iter->pos->data : NULL;
}

static inline void smc_ilist_iter_next(struct smc_ilist_iter *iter)
{
	struct list_head *next;

	if (!iter->pos)
		return;

	next = iter->pos->node.next;
	iter->pos = next == &iter->list->head ? NULL :
		list_entry(next, struct smc_ilist_node, node);
}

static inline void smc_ilist_const_iter_next(
	struct smc_ilist_const_iter *iter)
{
	struct list_head *next;

	if (!iter->pos)
		return;

	next = iter->pos->node.next;
	iter->pos = next == &iter->list->head ? NULL :
		list_entry(next, struct smc_ilist_node, node);
}

static inline void smc_ilist_iter_prev(struct smc_ilist_iter *iter)
{
	struct list_head *prev;

	if (!iter->pos) {
		iter->pos = smc_list_empty(&iter->list->head) ? NULL :
			list_last_entry(&iter->list->head,
					struct smc_ilist_node, node);
		return;
	}

	prev = iter->pos->node.prev;
	iter->pos = prev == &iter->list->head ? NULL :
		list_entry(prev, struct smc_ilist_node, node);
}

static inline void smc_ilist_iter_remove(struct smc_ilist_iter *iter)
{
	struct smc_ilist_node *old;
	struct list_head *next;

	if (!iter->pos)
		return;

	old = iter->pos;
	next = old->node.next;
	iter->pos = next == &iter->list->head ? NULL :
		list_entry(next, struct smc_ilist_node, node);
	list_del(&old->node);
	kfree(old);
	iter->list->size--;
}

static inline int smc_ilist_copy(struct smc_ilist *dst,
				 const struct smc_ilist *src)
{
	const struct smc_ilist_node *node;
	int ret;

	smc_ilist_clear(dst);

	list_for_each_entry(node, &src->head, node) {
		ret = smc_ilist_push_back(dst, node->data);
		if (ret) {
			smc_ilist_clear(dst);
			return ret;
		}
	}

	return 0;
}

static inline bool smc_ilist_equal(const struct smc_ilist *a,
				   const struct smc_ilist *b)
{
	struct smc_ilist_const_iter ia;
	struct smc_ilist_const_iter ib;

	if (a->elem_size != b->elem_size || a->size != b->size)
		return false;

	ia = smc_ilist_cbegin(a);
	ib = smc_ilist_cbegin(b);

	while (ia.pos && ib.pos) {
		if (!smc_data_equal(ia.pos->data, ib.pos->data, a->elem_size,
				    a->equal))
			return false;
		smc_ilist_const_iter_next(&ia);
		smc_ilist_const_iter_next(&ib);
	}

	return ia.pos == NULL && ib.pos == NULL;
}

static inline void smc_map_init(struct smc_map *map, size_t key_size,
				size_t value_size, gfp_t gfp,
				smc_data_equal_fn key_equal)
{
	INIT_LIST_HEAD(&map->entries);
	map->key_size = key_size;
	map->value_size = value_size;
	map->value_offset = smc_align_size(key_size, sizeof(unsigned long long));
	map->size = 0;
	map->gfp = gfp;
	map->key_equal = key_equal;
}

static inline void smc_map_clear(struct smc_map *map)
{
	struct smc_map_entry *entry;
	struct smc_map_entry *tmp;

	list_for_each_entry_safe(entry, tmp, &map->entries, node) {
		list_del(&entry->node);
		kfree(entry);
	}

	map->size = 0;
}

static inline void *smc_map_entry_key(const struct smc_map_entry *entry)
{
	return (void *)entry->data;
}

static inline void *smc_map_entry_value(const struct smc_map *map,
					const struct smc_map_entry *entry)
{
	return (void *)(entry->data + map->value_offset);
}

static inline void *smc_map_find(struct smc_map *map, const void *key)
{
	struct smc_map_entry *entry;

	list_for_each_entry(entry, &map->entries, node) {
		if (smc_data_equal(smc_map_entry_key(entry), key,
				   map->key_size, map->key_equal))
			return smc_map_entry_value(map, entry);
	}

	return NULL;
}

static inline const void *smc_map_find_const(const struct smc_map *map,
					     const void *key)
{
	const struct smc_map_entry *entry;

	list_for_each_entry(entry, &map->entries, node) {
		if (smc_data_equal(smc_map_entry_key(entry), key,
				   map->key_size, map->key_equal))
			return smc_map_entry_value(map, entry);
	}

	return NULL;
}

static inline void *smc_map_insert(struct smc_map *map, const void *key,
				   const void *value)
{
	struct smc_map_entry *entry;
	void *old_value;
	size_t size;

	old_value = smc_map_find(map, key);
	if (old_value)
		return old_value;

	size = sizeof(*entry) + map->value_offset + map->value_size;
	entry = kmalloc(size, map->gfp);
	if (!entry)
		return NULL;

	memcpy(smc_map_entry_key(entry), key, map->key_size);
	memcpy(smc_map_entry_value(map, entry), value, map->value_size);
	list_add_tail(&entry->node, &map->entries);
	map->size++;

	return smc_map_entry_value(map, entry);
}

static inline bool smc_map_contains(const struct smc_map *map,
				    const void *key)
{
	return smc_map_find_const(map, key) != NULL;
}

static inline smc_uptr_t smc_map_size(const struct smc_map *map)
{
	return map->size;
}

static inline bool smc_map_empty(const struct smc_map *map)
{
	return list_empty(&map->entries);
}

static inline void smc_add_to_hash(smc_uptr_t *res, smc_uptr_t data)
{
	if (data)
		*res = 31 * (*res) + data;
}

#endif /* C_SMC_DATA_H */
