// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include <errno.h>
#include <stdlib.h>

#include "resmon.h"

struct resmon_back_hw {
	struct resmon_back base;
	struct resmon_dl *dl;
};

static struct resmon_back *resmon_back_hw_init(void)
{
	struct resmon_back_hw *back;
	struct resmon_dl *dl;

	back = malloc(sizeof(*back));
	if (back == NULL)
		return NULL;

	dl = resmon_dl_create();
	if (dl == NULL) {
		fprintf(stderr, "Failed to open netlink socket\n");
		goto free_back;
	}

	*back = (struct resmon_back_hw) {
		.base.cls = &resmon_back_cls_hw,
		.dl = dl,
	};

	return &back->base;

free_back:
	free(back);
	return NULL;
}

static void resmon_back_hw_fini(struct resmon_back *base)
{
	struct resmon_back_hw *back =
		container_of(base, struct resmon_back_hw, base);

	resmon_dl_destroy(back->dl);
	free(back);
}

static int resmon_back_hw_get_capacity(struct resmon_back *base,
				       uint64_t *capacity,
				       char **error)
{
	struct resmon_back_hw *back =
		container_of(base, struct resmon_back_hw, base);

	return resmon_dl_get_kvd_size(back->dl, capacity, error);
}

const struct resmon_back_cls resmon_back_cls_hw = {
	.init = resmon_back_hw_init,
	.fini = resmon_back_hw_fini,
	.get_capacity = resmon_back_hw_get_capacity,
};

struct resmon_back_mock {
	struct resmon_back base;
};

static struct resmon_back *resmon_back_mock_init(void)
{
	struct resmon_back_mock *back;

	back = malloc(sizeof(*back));
	if (back == NULL)
		return NULL;

	*back = (struct resmon_back_mock) {
		.base.cls = &resmon_back_cls_mock,
	};

	return &back->base;
}

static void resmon_back_mock_fini(struct resmon_back *back)
{
	free(back);
}

static int resmon_back_mock_get_capacity(struct resmon_back *back,
					 uint64_t *capacity,
					 char **error)
{
	*capacity = 10000;
	return 0;
}

static int resmon_back_mock_emad_decode_payload(uint8_t *dec, const char *enc,
						size_t dec_len)
{
	for (size_t i = 0; i < dec_len; i++) {
		char buf[3] = {enc[2 * i], enc[2 * i + 1], '\0'};
		char *endptr = NULL;
		long byte;

		errno = 0;
		byte = strtol(buf, &endptr, 16);
		if (errno || *endptr != '\0')
			return -1;
		dec[i] = byte;
	}
	return 0;
}

static void resmon_back_mock_handle_emad(struct resmon_stat *stat,
					 struct resmon_sock *peer,
					 struct json_object *params_obj,
					 struct json_object *id)
{
	struct json_object *obj;
	size_t dec_payload_len;
	uint8_t *dec_payload;
	const char *payload;
	size_t payload_len;
	char *error;
	int rc;

	rc = resmon_jrpc_dissect_params_emad(params_obj, &payload,
					     &payload_len, &error);
	if (rc != 0) {
		resmon_d_respond_invalid_params(peer, id, error);
		free(error);
		return;
	}

	if (payload_len % 2 != 0) {
		resmon_d_respond_invalid_params(peer, id,
				    "EMAD payload has an odd length");
		return;
	}

	dec_payload_len = payload_len / 2;
	dec_payload = malloc(dec_payload_len);
	if (dec_payload == NULL)
		goto err_respond_memerr;

	rc = resmon_back_mock_emad_decode_payload(dec_payload, payload,
						  dec_payload_len);
	if (rc != 0) {
		resmon_d_respond_invalid_params(peer, id,
				    "EMAD payload expected in hexdump format");
		goto out;
	}


	rc = resmon_reg_process_emad(stat, dec_payload, dec_payload_len, &error);
	if (rc != 0) {
		resmon_d_respond_error(peer, id, resmon_jrpc_e_reg_process_emad,
				       "EMAD processing error", error);
		free(error);
		goto out;
	}

	obj = resmon_jrpc_new_object(id);
	if (obj == NULL)
		return;
	if (json_object_object_add(obj, "result", NULL))
		goto err_free_dec_payload;

	resmon_jrpc_send(peer, obj);
	json_object_put(obj);

out:
	free(dec_payload);
	return;

err_free_dec_payload:
	free(dec_payload);
	json_object_put(obj);
err_respond_memerr:
	resmon_d_respond_memerr(peer, id);
}

static bool resmon_back_mock_handle_method(struct resmon_back *back,
					   struct resmon_stat *stat,
					   const char *method,
					   struct resmon_sock *peer,
					   struct json_object *params_obj,
					   struct json_object *id)
{
	if (strcmp(method, "emad") == 0) {
		resmon_back_mock_handle_emad(stat, peer, params_obj, id);
		return true;
	} else {
		return false;
	}
}

const struct resmon_back_cls resmon_back_cls_mock = {
	.init = resmon_back_mock_init,
	.fini = resmon_back_mock_fini,
	.get_capacity = resmon_back_mock_get_capacity,
	.handle_method = resmon_back_mock_handle_method,
};
