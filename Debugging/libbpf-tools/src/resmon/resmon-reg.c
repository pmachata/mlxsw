// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <assert.h>
#include <endian.h>
#include <stdbool.h>
#include <stdint.h>

#include "resmon.h"

typedef struct {
	uint16_t value;
} uint16_be_t;

typedef struct {
	uint32_t value;
} uint32_be_t;

static inline uint16_t uint16_be_toh(uint16_be_t be)
{
	return be16toh(be.value);
}

static inline uint32_t uint32_be_toh(uint32_be_t be)
{
	return be32toh(be.value);
}

struct resmon_reg_emad_tl {
	int type;
	int length;
};

struct resmon_reg_op_tlv {
	uint16_be_t type_len;
	uint8_t status;
	uint8_t resv2;
	uint16_be_t reg_id;
	uint8_t r_method;
	uint8_t resv3;
	uint64_t tid;
};

struct resmon_reg_reg_tlv_head {
	uint16_be_t type_len;
	uint16_t reserved;
};

/* EMAD TLV Types */
enum {
	MLXSW_EMAD_TLV_TYPE_END,
	MLXSW_EMAD_TLV_TYPE_OP,
	MLXSW_EMAD_TLV_TYPE_STRING,
	MLXSW_EMAD_TLV_TYPE_REG,
};

enum mlxsw_reg_ralxx_protocol {
	MLXSW_REG_RALXX_PROTOCOL_IPV4,
	MLXSW_REG_RALXX_PROTOCOL_IPV6,
};

enum mlxsw_reg_ralue_op {
	/* Read operation. If entry doesn't exist, the operation fails. */
	MLXSW_REG_RALUE_OP_QUERY_READ = 0,
	/* Clear on read operation. Used to read entry and
	 * clear Activity bit.
	 */
	MLXSW_REG_RALUE_OP_QUERY_CLEAR = 1,
	/* Write operation. Used to write a new entry to the table. All RW
	 * fields are written for new entry. Activity bit is set
	 * for new entries.
	 */
	MLXSW_REG_RALUE_OP_WRITE_WRITE = 0,
	/* Update operation. Used to update an existing route entry and
	 * only update the RW fields that are detailed in the field
	 * op_u_mask. If entry doesn't exist, the operation fails.
	 */
	MLXSW_REG_RALUE_OP_WRITE_UPDATE = 1,
	/* Clear activity. The Activity bit (the field a) is cleared
	 * for the entry.
	 */
	MLXSW_REG_RALUE_OP_WRITE_CLEAR = 2,
	/* Delete operation. Used to delete an existing entry. If entry
	 * doesn't exist, the operation fails.
	 */
	MLXSW_REG_RALUE_OP_WRITE_DELETE = 3,
};

enum mlxsw_reg_ptar_op {
	/* allocate a TCAM region */
	MLXSW_REG_PTAR_OP_ALLOC,
	/* resize a TCAM region */
	MLXSW_REG_PTAR_OP_RESIZE,
	/* deallocate TCAM region */
	MLXSW_REG_PTAR_OP_FREE,
	/* test allocation */
	MLXSW_REG_PTAR_OP_TEST,
};

enum mlxsw_reg_ptar_key_type {
	MLXSW_REG_PTAR_KEY_TYPE_FLEX = 0x50, /* Spetrum */
	MLXSW_REG_PTAR_KEY_TYPE_FLEX2 = 0x51, /* Spectrum-2 */
};

enum mlxsw_reg_ptce3_op {
	/* Write operation. Used to write a new entry to the table.
	 * All R/W fields are relevant for new entry. Activity bit is set
	 * for new entries. Write with v = 0 will delete the entry. Must
	 * not be used if an entry exists.
	 */
	 MLXSW_REG_PTCE3_OP_WRITE_WRITE = 0,
	 /* Update operation */
	 MLXSW_REG_PTCE3_OP_WRITE_UPDATE = 1,
	 /* Read operation */
	 MLXSW_REG_PTCE3_OP_QUERY_READ = 0,
};

struct resmon_reg_ralue {
	uint8_t __protocol;
	uint8_t __op;
	uint16_be_t resv1;

#define resmon_reg_ralue_protocol(reg)	((reg)->__protocol & 0x0f)
#define resmon_reg_ralue_op(reg) (((reg)->__op & 0x70) >> 4)

	uint16_be_t __virtual_router;
	uint16_be_t resv2;

#define resmon_reg_ralue_virtual_router(reg) \
	(uint16_be_toh((reg)->__virtual_router))

	uint16_be_t resv3;
	uint8_t resv4;
	uint8_t prefix_len;

	union {
		uint8_t dip6[16];
		struct {
			uint8_t resv5[12];
			uint8_t dip4[4];
		};
	};
};

struct resmon_reg_ptar {
	uint8_t __op_e;
	uint8_t action_set_type;
	uint8_t resv1;
	uint8_t key_type;

#define resmon_reg_ptar_op(reg) ((reg)->__op_e >> 4)

	uint16_be_t resv2;
	uint16_be_t __region_size;

	uint16_be_t resv3;
	uint16_be_t __region_id;

	uint16_be_t resv4;
	uint8_t __dup_opt;
	uint8_t __packet_rate;

	uint8_t tcam_region_info[16];
	uint8_t flexible_keys[16];
};

struct resmon_reg_ptce3 {
	uint8_t __v_a;
	uint8_t __op;
	uint8_t resv1;
	uint8_t __dup;

#define resmon_reg_ptce3_v(reg) ((reg)->__v_a >> 7)
#define resmon_reg_ptce3_op(reg) (((reg)->__op >> 4) & 7)

	uint32_be_t __priority;

	uint32_be_t resv2;

	uint32_be_t resv3;

	uint8_t tcam_region_info[16];

	uint8_t flex2_key_blocks[96];

	uint16_be_t resv4;
	uint8_t resv5;
	uint8_t __erp_id;

#define resmon_reg_ptce3_erp_id(reg) ((reg)->__erp_id & 0xf)

	uint16_be_t resv6;
	uint16_be_t __delta_start;

#define resmon_reg_ptce3_delta_start(reg) \
	(uint16_be_toh((reg)->__delta_start) & 0x3ff)

	uint8_t resv7;
	uint8_t delta_mask;
	uint8_t resv8;
	uint8_t delta_value;
};

struct resmon_reg_pefa {
	uint32_be_t __pind_index;

#define resmon_reg_pefa_index(reg) \
	(uint32_be_toh((reg)->__pind_index) & 0xffffff)
};

struct resmon_reg_iedr_record {
	uint8_t type;
	uint8_t resv1;
	uint16_be_t __size;

#define resmon_reg_iedr_record_size(rec) (uint16_be_toh((rec)->__size))

	uint32_be_t __index_start;

#define resmon_reg_iedr_record_index_start(rec) \
	(uint32_be_toh((rec)->__index_start) & 0xffffff)
};

struct resmon_reg_iedr {
	uint8_t __bg;
	uint8_t resv1;
	uint8_t resv2;
	uint8_t num_rec;

	uint32_be_t resv3;

	uint32_be_t resv4;

	uint32_be_t resv5;

	struct resmon_reg_iedr_record records[64];
};

static struct resmon_reg_emad_tl
resmon_reg_emad_decode_tl(uint16_be_t type_len_be)
{
	uint16_t type_len = uint16_be_toh(type_len_be);

	return (struct resmon_reg_emad_tl){
		.type = type_len >> 11,
		.length = type_len & 0x7ff,
	};
}

#define RESMON_REG_PULL(size, payload, payload_len)			\
	({								\
		if (payload_len < size)					\
			goto oob;					\
		__typeof(payload) __ret = payload;			\
		payload += size;					\
		payload_len -= size;					\
		(const void *) __ret;					\
	})

#define RESMON_REG_READ(size, payload, payload_len)			\
	({								\
		__typeof(payload) __payload = payload;			\
		__typeof(payload_len) __payload_len = payload_len;	\
		RESMON_REG_PULL(size, __payload, __payload_len);	\
	})

static enum resmon_reg_process_result
resmon_reg_handle_ralue(struct resmon_stat *stat, const uint8_t *payload,
			size_t payload_len)
{
	const struct resmon_reg_ralue *reg =
		RESMON_REG_READ(sizeof(*reg), payload, payload_len);

	uint8_t protocol = resmon_reg_ralue_protocol(reg);
	uint8_t prefix_len = reg->prefix_len;
	uint16_t virtual_router = resmon_reg_ralue_virtual_router(reg);
	struct resmon_stat_dip dip = {};

	bool ipv6 = protocol == MLXSW_REG_RALXX_PROTOCOL_IPV6;
	if (ipv6)
		memcpy(dip.dip, reg->dip6, sizeof(reg->dip6));
	else
		memcpy(dip.dip, reg->dip4, sizeof(reg->dip4));

	if (resmon_reg_ralue_op(reg) == MLXSW_REG_RALUE_OP_WRITE_DELETE) {
		int rc = resmon_stat_ralue_delete(stat, protocol, prefix_len,
						  virtual_router, dip);
		return rc ? resmon_reg_process_delete_failed
			  : resmon_reg_process_ok;
	}

	struct resmon_stat_kvd_alloc kvda = {
		.slots = prefix_len <= 64 ? 1 : 2,
		.counter = ipv6 ? RESMON_COUNTER_LPM_IPV6
				: RESMON_COUNTER_LPM_IPV4,
	};
	int rc = resmon_stat_ralue_update(stat, protocol, prefix_len,
					  virtual_router, dip, kvda);
	return rc ? resmon_reg_process_insert_failed
		  : resmon_reg_process_ok;

oob:
	return resmon_reg_process_truncated_payload;
}

static struct resmon_stat_kvd_alloc
resmon_reg_ptar_get_kvd_alloc(const struct resmon_reg_ptar *reg)
{
	size_t nkeys = 0;
	for (size_t i = 0; i < sizeof(reg->flexible_keys); i++)
		if (reg->flexible_keys[i])
			nkeys++;

	return (struct resmon_stat_kvd_alloc) {
		.slots = nkeys >= 12 ? 4 :
			 nkeys >= 4  ? 2 : 1,
		.counter = RESMON_COUNTER_ATCAM,
	};
}

static enum resmon_reg_process_result
resmon_reg_handle_ptar(struct resmon_stat *stat, const uint8_t *payload,
		       size_t payload_len)
{
	const struct resmon_reg_ptar *reg =
		RESMON_REG_READ(sizeof(*reg), payload, payload_len);

	switch (reg->key_type) {
	case MLXSW_REG_PTAR_KEY_TYPE_FLEX:
	case MLXSW_REG_PTAR_KEY_TYPE_FLEX2:
		break;
	default:
		return resmon_reg_process_ok;
	}

	struct resmon_stat_tcam_region_info tcam_region_info;
	memcpy(tcam_region_info.tcam_region_info, reg->tcam_region_info,
	       sizeof(tcam_region_info.tcam_region_info));

	int rc;
	switch (resmon_reg_ptar_op(reg)) {
		struct resmon_stat_kvd_alloc kvd_alloc;
	case MLXSW_REG_PTAR_OP_RESIZE:
	case MLXSW_REG_PTAR_OP_TEST:
	default:
		return resmon_reg_process_ok;
	case MLXSW_REG_PTAR_OP_ALLOC:
		kvd_alloc = resmon_reg_ptar_get_kvd_alloc(reg);
		rc = resmon_stat_ptar_alloc(stat, tcam_region_info, kvd_alloc);
		if (rc != 0)
			return resmon_reg_process_insert_failed;
		break;
	case MLXSW_REG_PTAR_OP_FREE:
		rc = resmon_stat_ptar_free(stat, tcam_region_info);
		if (rc != 0)
			return resmon_reg_process_delete_failed;
		break;
	}

	return resmon_reg_process_ok;

oob:
	return resmon_reg_process_truncated_payload;
}

static enum resmon_reg_process_result
resmon_reg_handle_ptce3(struct resmon_stat *stat, const uint8_t *payload,
			size_t payload_len)
{
	int rc;
	const struct resmon_reg_ptce3 *reg =
		RESMON_REG_READ(sizeof(*reg), payload, payload_len);

	switch (resmon_reg_ptce3_op(reg)) {
	case MLXSW_REG_PTCE3_OP_WRITE_WRITE:
	case MLXSW_REG_PTCE3_OP_WRITE_UPDATE:
		break;
	default:
		return resmon_reg_process_ok;
	}

	struct resmon_stat_tcam_region_info tcam_region_info;
	memcpy(tcam_region_info.tcam_region_info, reg->tcam_region_info,
	       sizeof(tcam_region_info.tcam_region_info));

	struct resmon_stat_flex2_key_blocks key_blocks;
	memcpy(key_blocks.flex2_key_blocks, reg->flex2_key_blocks,
	       sizeof(key_blocks.flex2_key_blocks));

	if (resmon_reg_ptce3_v(reg)) {
		struct resmon_stat_kvd_alloc kvd_alloc;
		rc = resmon_stat_ptar_get(stat, tcam_region_info, &kvd_alloc);
		if (rc != 0)
			return resmon_reg_process_insert_failed;

		rc = resmon_stat_ptce3_alloc(stat, tcam_region_info,
					     &key_blocks, reg->delta_mask,
					     reg->delta_value,
					     resmon_reg_ptce3_delta_start(reg),
					     resmon_reg_ptce3_erp_id(reg),
					     kvd_alloc);
		if (rc != 0)
			return resmon_reg_process_insert_failed;
	} else {
		rc = resmon_stat_ptce3_free(stat, tcam_region_info,
					    &key_blocks, reg->delta_mask,
					    reg->delta_value,
					    resmon_reg_ptce3_delta_start(reg),
					    resmon_reg_ptce3_erp_id(reg));
		if (rc != 0)
			return resmon_reg_process_delete_failed;
	}

	return resmon_reg_process_ok;

oob:
	return resmon_reg_process_truncated_payload;
}

static enum resmon_reg_process_result
resmon_reg_handle_pefa(struct resmon_stat *stat, const uint8_t *payload,
		       size_t payload_len)
{
	const struct resmon_reg_pefa *reg =
		RESMON_REG_READ(sizeof(*reg), payload, payload_len);

	struct resmon_stat_kvd_alloc kvd_alloc = {
		.slots = 1,
		.counter = RESMON_COUNTER_ACTSET,
	};

	int rc = resmon_stat_kvdl_alloc(stat, resmon_reg_pefa_index(reg),
					kvd_alloc);
	if (rc != 0)
		return resmon_reg_process_insert_failed;

	return resmon_reg_process_ok;

oob:
	return resmon_reg_process_truncated_payload;
}

static int resmon_reg_handle_iedr_record(struct resmon_stat *stat,
					 struct resmon_reg_iedr_record record)
{
	uint32_t index = resmon_reg_iedr_record_index_start(&record);
	uint32_t size = resmon_reg_iedr_record_size(&record);
	return resmon_stat_kvdl_free(stat, index, size);
}

static enum resmon_reg_process_result
resmon_reg_handle_iedr(struct resmon_stat *stat, const uint8_t *payload,
		       size_t payload_len)
{
	const struct resmon_reg_iedr *reg =
		RESMON_REG_READ(sizeof(*reg), payload, payload_len);
	enum resmon_reg_process_result res = resmon_reg_process_ok;

	if (reg->num_rec > ARRAY_SIZE(reg->records))
		return resmon_reg_process_inconsistent_register;

	for (size_t i = 0; i < reg->num_rec; i++) {
		int rc = resmon_reg_handle_iedr_record(stat, reg->records[i]);
		if (rc != 0)
			res = resmon_reg_process_delete_failed;
	}

	return res;

oob:
	return resmon_reg_process_truncated_payload;
}

enum resmon_reg_process_result resmon_reg_process_emad(struct resmon_stat *stat,
						       const uint8_t *buf,
						       size_t len)
{
	struct resmon_reg_emad_tl tl;

	const struct resmon_reg_op_tlv *op_tlv =
		RESMON_REG_READ(sizeof(*op_tlv), buf, len);
	tl = resmon_reg_emad_decode_tl(op_tlv->type_len);

	RESMON_REG_PULL(tl.length * 4, buf, len);
	const struct resmon_reg_reg_tlv_head *reg_tlv =
		RESMON_REG_READ(sizeof(*reg_tlv), buf, len);
	tl = resmon_reg_emad_decode_tl(reg_tlv->type_len);

	/* Skip over the TLV if it is in fact a STRING TLV. */
	if (tl.type == MLXSW_EMAD_TLV_TYPE_STRING) {
		RESMON_REG_PULL(tl.length * 4, buf, len);
		reg_tlv = RESMON_REG_READ(sizeof(*reg_tlv), buf, len);
		tl = resmon_reg_emad_decode_tl(reg_tlv->type_len);
	}

	if (tl.type != MLXSW_EMAD_TLV_TYPE_REG)
		return resmon_reg_process_no_register;

	/* Get to the register payload. */
	RESMON_REG_PULL(sizeof(*reg_tlv), buf, len);

	switch (uint16_be_toh(op_tlv->reg_id)) {
	case 0x8013: /* MLXSW_REG_RALUE_ID */
		return resmon_reg_handle_ralue(stat, buf, len);
	case 0x3006: /* MLXSW_REG_PTAR_ID */
		return resmon_reg_handle_ptar(stat, buf, len);
	case 0x3027: /* MLXSW_REG_PTCE3_ID */
		return resmon_reg_handle_ptce3(stat, buf, len);
	case 0x300F: /* MLXSW_REG_PEFA_ID */
		return resmon_reg_handle_pefa(stat, buf, len);
	case 0x3804: /* MLXSW_REG_IEDR_ID */
		return resmon_reg_handle_iedr(stat, buf, len);
	}

	return resmon_reg_process_unknown_register;

oob:
	return resmon_reg_process_truncated_payload;
}

const char *resmon_reg_process_result_str(enum resmon_reg_process_result res)
{
	switch (res) {
	case resmon_reg_process_ok:
		return "OK";
	case resmon_reg_process_delete_failed:
		return "Delete failed";
	case resmon_reg_process_insert_failed:
		return "Insert failed";
	case resmon_reg_process_truncated_payload:
		return "EMAD malformed: Payload truncated";
	case resmon_reg_process_no_register:
		return "EMAD malformed: No register";
	case resmon_reg_process_unknown_register:
		return "EMAD malformed: Unknown register";
	case resmon_reg_process_inconsistent_register:
		return "EMAD malformed: Inconsistent register";
	}

	assert(false);
}
