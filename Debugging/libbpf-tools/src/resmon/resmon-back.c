// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <errno.h>
#include <stdlib.h>
#include <syslog.h>
#include <json-c/json_object.h>

#include "resmon.h"
#include "resmon.skel.h"
#include "../trace_helpers.h"

struct resmon_back_hw {
	struct resmon_back base;
	struct resmon_bpf *bpf_obj;
	struct ring_buffer *ringbuf;
	struct resmon_stat *stat;
};

static int resmon_back_libbpf_print_fn(enum libbpf_print_level level,
				       const char *format,
				       va_list args)
{
	if ((int)level > env.verbosity)
		return 0;

	int prio = 0;
	switch (level) {
        case LIBBPF_WARN:
		prio = LOG_WARNING;
		break;
        case LIBBPF_INFO:
		prio = LOG_INFO;
		break;
        case LIBBPF_DEBUG:
		prio = LOG_DEBUG;
		break;
	}

	vsyslog(prio, format, args);
	return 0;
}

static int resmon_back_hw_rb_sample_cb(void *ctx, void *data, size_t len)
{
	struct resmon_back_hw *back = ctx;
	fprintf(stderr, "process_sample len %zd\n", len); // xxx
	enum resmon_reg_process_result res =
		resmon_reg_process_emad(back->stat, data, len);
	if (res != resmon_reg_process_ok) {
		const char *reason = resmon_reg_process_result_str(res);
		syslog(LOG_ERR, "EMAD processing error: %s", reason);
	}
	return 0;
}

static struct resmon_back *resmon_back_hw_init(void)
{
	int rc;

	struct resmon_back_hw *back = malloc(sizeof(*back));
	if (back == NULL)
		return NULL;

	libbpf_set_print(resmon_back_libbpf_print_fn);

	rc = bump_memlock_rlimit();
	if (rc != 0) {
		fprintf(stderr, "Failed to increase rlimit: %d\n", rc);
		goto free_back;
	}

	struct resmon_bpf *bpf_obj = resmon_bpf__open();
	if (bpf_obj == NULL) {
		fprintf(stderr, "Failed to open the resmon BPF object\n");
		goto free_back;
	}

	rc = resmon_bpf__load(bpf_obj);
	if (rc != 0) {
		fprintf(stderr, "Failed to load the resmon BPF object\n");
		goto destroy_bpf;
	}

	struct ring_buffer *ringbuf =
		ring_buffer__new(bpf_map__fd(bpf_obj->maps.ringbuf),
				 resmon_back_hw_rb_sample_cb, back, NULL);
	if (ringbuf == NULL)
		goto destroy_bpf;

	rc = resmon_bpf__attach(bpf_obj);
	if (rc != 0) {
		fprintf(stderr, "Failed to attach BPF program\n");
		goto free_ringbuf;
	}

	*back = (struct resmon_back_hw) {
		.base.cls = &resmon_back_cls_hw,
		.bpf_obj = bpf_obj,
		.ringbuf = ringbuf,
	};

	return &back->base;

free_ringbuf:
	ring_buffer__free(ringbuf);
destroy_bpf:
	resmon_bpf__destroy(bpf_obj);
free_back:
	free(back);
	return NULL;
}

static void resmon_back_hw_fini(struct resmon_back *base)
{
	struct resmon_back_hw *back =
		container_of(base, struct resmon_back_hw, base);

	resmon_bpf__detach(back->bpf_obj);
	ring_buffer__free(back->ringbuf);
	resmon_bpf__destroy(back->bpf_obj);
	free(back);
}

static int resmon_back_hw_pollfd(struct resmon_back *base)
{
	struct resmon_back_hw *back =
		container_of(base, struct resmon_back_hw, base);

	return ring_buffer__epoll_fd(back->ringbuf);
}

static int resmon_back_hw_activity(struct resmon_back *base,
				   struct resmon_stat *stat)
{
	struct resmon_back_hw *back =
		container_of(base, struct resmon_back_hw, base);

	back->stat = stat;
	int n = ring_buffer__consume(back->ringbuf);
	back->stat = NULL;
	if (n < 0)
		return -1;
	return 0;
}

const struct resmon_back_cls resmon_back_cls_hw = {
	.init = resmon_back_hw_init,
	.fini = resmon_back_hw_fini,
	.pollfd = resmon_back_hw_pollfd,
	.activity = resmon_back_hw_activity,
};

struct resmon_back_mock {
	struct resmon_back base;
};

static struct resmon_back *resmon_back_mock_init(void)
{
	struct resmon_back_mock *back = malloc(sizeof(*back));
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

static int resmon_back_mock_pollfd(struct resmon_back *base)
{
	return -1;
}

static int resmon_back_mock_emad_decode_payload(uint8_t *dec, const char *enc,
						size_t dec_len)
{
	for (size_t i = 0; i < dec_len; i++) {
		char buf[3] = {enc[2 * i], enc[2 * i + 1], '\0'};
		char *endptr = NULL;
		errno = 0;
		long byte = strtol(buf, &endptr, 16);
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
	int rc;

	const char *payload;
	size_t payload_len;
	char *error;
	rc = resmon_jrpc_dissect_params_emad(params_obj, &payload,
					     &payload_len, &error);
	if (rc != 0) {
		resmon_d_respond_invalid_params(peer, error);
		free(error);
		return;
	}

	if (payload_len % 2 != 0) {
		resmon_d_respond_invalid_params(peer,
				    "EMAD payload has an odd length");
		return;
	}

	size_t dec_payload_len = payload_len / 2;
	uint8_t *dec_payload = malloc(dec_payload_len);
	if (dec_payload == NULL)
		goto respond_memerr;

	rc = resmon_back_mock_emad_decode_payload(dec_payload, payload,
						  dec_payload_len);
	if (rc != 0) {
		resmon_d_respond_invalid_params(peer,
				    "EMAD payload expected in hexdump format");
		goto out;
	}


	enum resmon_reg_process_result res =
		resmon_reg_process_emad(stat, dec_payload, dec_payload_len);
	if (res != resmon_reg_process_ok) {
		const char *reason = resmon_reg_process_result_str(res);
		resmon_d_respond_error(peer, id, res,
				       "EMAD processing error", reason);
		goto out;
	}

	struct json_object *obj = resmon_jrpc_new_object(id);
	if (obj == NULL)
		return;
	if (json_object_object_add(obj, "result", NULL))
		goto free_dec_payload;
	resmon_jrpc_take_send(peer, obj);

out:
	free(dec_payload);
	return;

free_dec_payload:
	free(dec_payload);
	json_object_put(obj);
respond_memerr:
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
	.pollfd = resmon_back_mock_pollfd,
	.handle_method = resmon_back_mock_handle_method,
};
