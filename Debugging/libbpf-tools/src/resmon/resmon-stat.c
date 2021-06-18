// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <json-c/linkhash.h>

#include "resmon.h"

static void resmon_stat_entry_free(struct lh_entry *e)
{
	if (!e->k_is_constant)
		free(lh_entry_k(e));
	free(lh_entry_v(e));
}

static uint64_t resmon_stat_fnv_1(const void *ptr, size_t len)
{
	const uint8_t *buf = ptr;
	uint64_t hash = 0xcbf29ce484222325ULL;
	for (size_t i = 0; i < len; i++) {
		hash = hash * 0x100000001b3ULL;
		hash = hash ^ buf[i];
	}
	return hash;
}

struct resmon_stat_key {};

static struct resmon_stat_key *
resmon_stat_key_copy(const struct resmon_stat_key *key, size_t size)
{
	struct resmon_stat_key *copy = malloc(size);
	if (copy == NULL)
		return NULL;

	memcpy(copy, key, size);
	return copy;
}

#define RESMON_STAT_KEY_HASH_FN(name, type)				\
	static unsigned long name(const void *k)			\
	{								\
		return resmon_stat_fnv_1(k, sizeof(type));		\
	}

#define RESMON_STAT_KEY_EQ_FN(name, type)				\
	static int name(const void *k1, const void *k2)			\
	{								\
		return memcmp(k1, k2, sizeof(type)) == 0;		\
	}

struct resmon_stat_ralue_key {
	struct resmon_stat_key base;
	uint8_t protocol;
	uint8_t prefix_len;
	uint16_t virtual_router;
	struct resmon_stat_dip dip;
};

static struct resmon_stat_ralue_key
resmon_stat_ralue_key(uint8_t protocol,
		      uint8_t prefix_len,
		      uint16_t virtual_router,
		      struct resmon_stat_dip dip)
{
	return (struct resmon_stat_ralue_key) {
		.protocol = protocol,
		.prefix_len = prefix_len,
		.virtual_router = virtual_router,
		.dip = dip,
	};
}

RESMON_STAT_KEY_HASH_FN(resmon_stat_ralue_hash, struct resmon_stat_ralue_key);
RESMON_STAT_KEY_EQ_FN(resmon_stat_ralue_eq, struct resmon_stat_ralue_key);

struct resmon_stat_ptar_key {
	struct resmon_stat_key base;
	struct resmon_stat_tcam_region_info tcam_region_info;
};

static struct resmon_stat_ptar_key
resmon_stat_ptar_key(struct resmon_stat_tcam_region_info tcam_region_info)
{
	return (struct resmon_stat_ptar_key) {
		.tcam_region_info = tcam_region_info,
	};
}

RESMON_STAT_KEY_HASH_FN(resmon_stat_ptar_hash, struct resmon_stat_ptar_key);
RESMON_STAT_KEY_EQ_FN(resmon_stat_ptar_eq, struct resmon_stat_ptar_key);

struct resmon_stat_ptce3_key {
	struct resmon_stat_key base;
	struct resmon_stat_tcam_region_info tcam_region_info;
	struct resmon_stat_flex2_key_blocks flex2_key_blocks;
	uint8_t delta_mask;
	uint8_t delta_value;
	uint16_t delta_start;
	uint8_t erp_id;
};

static struct resmon_stat_ptce3_key
resmon_stat_ptce3_key(struct resmon_stat_tcam_region_info tcam_region_info,
		      const struct resmon_stat_flex2_key_blocks *key_blocks,
		      uint8_t delta_mask,
		      uint8_t delta_value,
		      uint16_t delta_start,
		      uint8_t erp_id)
{
	return (struct resmon_stat_ptce3_key) {
		.tcam_region_info = tcam_region_info,
		.flex2_key_blocks = *key_blocks,
		.delta_mask = delta_mask,
		.delta_value = delta_value,
		.delta_start = delta_start,
		.erp_id = erp_id,
	};
}

RESMON_STAT_KEY_HASH_FN(resmon_stat_ptce3_hash, struct resmon_stat_ptce3_key);
RESMON_STAT_KEY_EQ_FN(resmon_stat_ptce3_eq, struct resmon_stat_ptce3_key);

struct resmon_stat_kvdl_key {
	struct resmon_stat_key base;
	uint32_t index;
};

static struct resmon_stat_kvdl_key
resmon_stat_kvdl_key(uint32_t index)
{
	return (struct resmon_stat_kvdl_key) {
		.index = index,
	};
}

RESMON_STAT_KEY_HASH_FN(resmon_stat_kvdl_hash, struct resmon_stat_kvdl_key);
RESMON_STAT_KEY_EQ_FN(resmon_stat_kvdl_eq, struct resmon_stat_kvdl_key);

struct resmon_stat {
	struct resmon_stat_counters counters;
	struct lh_table *ralue;
	struct lh_table *ptar;
	struct lh_table *ptce3;
	struct lh_table *kvdl;
};

static struct resmon_stat_kvd_alloc *
resmon_stat_kvd_alloc_copy(struct resmon_stat_kvd_alloc kvd_alloc)
{
	struct resmon_stat_kvd_alloc *copy = malloc(sizeof(*copy));
	if (copy == NULL)
		return NULL;

	*copy = kvd_alloc;
	return copy;
}

struct resmon_stat *resmon_stat_create(void)
{
	struct resmon_stat *stat = malloc(sizeof(*stat));
	if (stat == NULL)
		return NULL;

	struct lh_table *ralue_tab = lh_table_new(1, resmon_stat_entry_free,
						  resmon_stat_ralue_hash,
						  resmon_stat_ralue_eq);
	if (ralue_tab == NULL)
		goto free_stat;

	struct lh_table *ptar_tab = lh_table_new(1, resmon_stat_entry_free,
						 resmon_stat_ptar_hash,
						 resmon_stat_ptar_eq);
	if (ptar_tab == NULL)
		goto free_ralue_tab;

	struct lh_table *ptce3_tab = lh_table_new(1, resmon_stat_entry_free,
						  resmon_stat_ptce3_hash,
						  resmon_stat_ptce3_eq);
	if (ptce3_tab == NULL)
		goto free_ptar_tab;

	struct lh_table *kvdl_tab = lh_table_new(1, resmon_stat_entry_free,
						 resmon_stat_kvdl_hash,
						 resmon_stat_kvdl_eq);
	if (kvdl_tab == NULL)
		goto free_ptce3_tab;

	*stat = (struct resmon_stat){
		.ralue = ralue_tab,
		.ptar = ptar_tab,
		.ptce3 = ptce3_tab,
		.kvdl = kvdl_tab,
	};
	return stat;

free_ptce3_tab:
	lh_table_free(ptce3_tab);
free_ptar_tab:
	lh_table_free(ptar_tab);
free_ralue_tab:
	lh_table_free(ralue_tab);
free_stat:
	free(stat);
	return NULL;
}

void resmon_stat_destroy(struct resmon_stat *stat)
{
	lh_table_free(stat->kvdl);
	lh_table_free(stat->ptce3);
	lh_table_free(stat->ptar);
	lh_table_free(stat->ralue);
	free(stat);
}

struct resmon_stat_counters resmon_stat_counters(struct resmon_stat *stat)
{
	return stat->counters;
}

static void resmon_stat_counter_inc(struct resmon_stat *stat,
				    struct resmon_stat_kvd_alloc kvd_alloc)
{
	stat->counters.values[kvd_alloc.counter] += kvd_alloc.slots;
}

static void resmon_stat_counter_dec(struct resmon_stat *stat,
				    struct resmon_stat_kvd_alloc kvd_alloc)
{
	stat->counters.values[kvd_alloc.counter] -= kvd_alloc.slots;
}

static int resmon_stat_lh_get(struct lh_table *tab,
			      const struct resmon_stat_key *orig_key,
			      struct resmon_stat_kvd_alloc *ret_kvd_alloc)
{
	long hash = tab->hash_fn(orig_key);
	struct lh_entry *e = lh_table_lookup_entry_w_hash(tab, orig_key, hash);
	if (e == NULL)
		return -1;

	const struct resmon_stat_kvd_alloc *kvd_alloc = e->v;
	*ret_kvd_alloc = *kvd_alloc;
	return 0;
}

static int resmon_stat_lh_update(struct resmon_stat *stat,
				 struct lh_table *tab,
				 const struct resmon_stat_key *orig_key,
				 size_t orig_key_size,
				 struct resmon_stat_kvd_alloc orig_kvd_alloc)
{
	long hash = tab->hash_fn(orig_key);
	struct lh_entry *e = lh_table_lookup_entry_w_hash(tab, orig_key, hash);
	if (e != NULL)
		return 0;

	struct resmon_stat_key *key =
		resmon_stat_key_copy(orig_key, orig_key_size);
	if (key == NULL)
		return -ENOMEM;

	struct resmon_stat_kvd_alloc *kvd_alloc =
		resmon_stat_kvd_alloc_copy(orig_kvd_alloc);
	if (kvd_alloc == NULL)
		goto free_key;

	int rc = lh_table_insert_w_hash(tab, key, kvd_alloc, hash, 0);
	if (rc)
		goto free_kvd_alloc;

	resmon_stat_counter_inc(stat, *kvd_alloc);
	return 0;

free_kvd_alloc:
	free(kvd_alloc);
free_key:
	free(key);
	return -1;
}

static int resmon_stat_lh_delete(struct resmon_stat *stat,
				 struct lh_table *tab,
				 const struct resmon_stat_key *orig_key)
{
	long hash = tab->hash_fn(orig_key);
	struct lh_entry *e = lh_table_lookup_entry_w_hash(tab, orig_key, hash);
	if (e == NULL)
		return -1;

	const struct resmon_stat_kvd_alloc *vp = e->v;
	struct resmon_stat_kvd_alloc kvd_alloc = *vp;
	int rc = lh_table_delete_entry(tab, e);
	assert(rc == 0);

	resmon_stat_counter_dec(stat, kvd_alloc);
	return 0;
}

int resmon_stat_ralue_update(struct resmon_stat *stat,
			     uint8_t protocol,
			     uint8_t prefix_len,
			     uint16_t virtual_router,
			     struct resmon_stat_dip dip,
			     struct resmon_stat_kvd_alloc kvd_alloc)
{
	struct resmon_stat_ralue_key key =
		resmon_stat_ralue_key(protocol, prefix_len, virtual_router,
				      dip);
	return resmon_stat_lh_update(stat, stat->ralue,
				     &key.base, sizeof(key), kvd_alloc);
}

int resmon_stat_ralue_delete(struct resmon_stat *stat,
			     uint8_t protocol,
			     uint8_t prefix_len,
			     uint16_t virtual_router,
			     struct resmon_stat_dip dip)
{
	struct resmon_stat_ralue_key key =
		resmon_stat_ralue_key(protocol, prefix_len, virtual_router,
				      dip);
	return resmon_stat_lh_delete(stat, stat->ralue, &key.base);
}

int resmon_stat_ptar_alloc(struct resmon_stat *stat,
			   struct resmon_stat_tcam_region_info tcam_region_info,
			   struct resmon_stat_kvd_alloc kvd_alloc)
{
	struct resmon_stat_ptar_key key =
		resmon_stat_ptar_key(tcam_region_info);
	return resmon_stat_lh_update(stat, stat->ptar,
				     &key.base, sizeof(key), kvd_alloc);
}

int resmon_stat_ptar_free(struct resmon_stat *stat,
			  struct resmon_stat_tcam_region_info tcam_region_info)
{
	struct resmon_stat_ptar_key key =
		resmon_stat_ptar_key(tcam_region_info);
	return resmon_stat_lh_delete(stat, stat->ptar, &key.base);
}

int resmon_stat_ptar_get(struct resmon_stat *stat,
			 struct resmon_stat_tcam_region_info tcam_region_info,
			 struct resmon_stat_kvd_alloc *ret_kvd_alloc)
{
	struct resmon_stat_ptar_key key =
		resmon_stat_ptar_key(tcam_region_info);
	return resmon_stat_lh_get(stat->ptar, &key.base, ret_kvd_alloc);
}

int
resmon_stat_ptce3_alloc(struct resmon_stat *stat,
			struct resmon_stat_tcam_region_info tcam_region_info,
			const struct resmon_stat_flex2_key_blocks *key_blocks,
			uint8_t delta_mask,
			uint8_t delta_value,
			uint16_t delta_start,
			uint8_t erp_id,
			struct resmon_stat_kvd_alloc kvd_alloc)
{
	struct resmon_stat_ptce3_key key =
		resmon_stat_ptce3_key(tcam_region_info, key_blocks, delta_mask,
				      delta_value, delta_start, erp_id);
	return resmon_stat_lh_update(stat, stat->ptce3,
				     &key.base, sizeof(key), kvd_alloc);
}

int
resmon_stat_ptce3_free(struct resmon_stat *stat,
		       struct resmon_stat_tcam_region_info tcam_region_info,
		       const struct resmon_stat_flex2_key_blocks *key_blocks,
		       uint8_t delta_mask,
		       uint8_t delta_value,
		       uint16_t delta_start,
		       uint8_t erp_id)
{
	struct resmon_stat_ptce3_key key =
		resmon_stat_ptce3_key(tcam_region_info, key_blocks, delta_mask,
				      delta_value, delta_start, erp_id);
	return resmon_stat_lh_delete(stat, stat->ptce3, &key.base);
}

static int resmon_stat_kvdl_alloc_1(struct resmon_stat *stat,
				    uint32_t index,
				    struct resmon_stat_kvd_alloc kvd_alloc)
{
	struct resmon_stat_kvdl_key key = resmon_stat_kvdl_key(index);
	return resmon_stat_lh_update(stat, stat->kvdl,
				     &key.base, sizeof(key), kvd_alloc);
}

static int resmon_stat_kvdl_free_1(struct resmon_stat *stat,
				   uint32_t index)
{
	struct resmon_stat_kvdl_key key = resmon_stat_kvdl_key(index);
	return resmon_stat_lh_delete(stat, stat->kvdl, &key.base);
}

int resmon_stat_kvdl_alloc(struct resmon_stat *stat,
			   uint32_t index,
			   struct resmon_stat_kvd_alloc kvd_alloc)
{
	uint32_t i = 0;
	int rc;

	for (i = 0; i < kvd_alloc.slots; i++) {
		struct resmon_stat_kvd_alloc kvd_alloc_1 = {
			.slots = 1,
			.counter = kvd_alloc.counter,
		};
		rc = resmon_stat_kvdl_alloc_1(stat, index + i, kvd_alloc_1);
		if (rc != 0)
			goto unroll;
	}

	return 0;

unroll:
	while (i-- > 0)
		resmon_stat_kvdl_free_1(stat, index + i);
	return rc;
}

int resmon_stat_kvdl_free(struct resmon_stat *stat,
			  uint32_t index,
			  uint32_t slots)
{
	uint32_t i = 0;
	int rc = 0;

	for (i = 0; i < slots; i++) {
		int rc_1 = resmon_stat_kvdl_free_1(stat, index + i);
		if (rc_1 != 0)
			rc = rc_1;
	}

	return rc;
}
