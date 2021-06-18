// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>

#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include <json-c/json_util.h>

#include "resmon.h"

static bool resmon_c_validate_id(struct json_object *id_obj, int expect_id)
{
	int64_t id = json_object_get_int64(id_obj);
	return id == expect_id;
}

static void resmon_c_handle_response_error(struct json_object *error_obj)
{
	int64_t code;
	const char *message;
	struct json_object *data;
	char *error;
	int err = resmon_jrpc_dissect_error(error_obj, &code, &message, &data,
					    &error);
	if (err) {
		fprintf(stderr, "Invalid error object: %s\n", error);
		free(error);
		return;
	}

	if (data != NULL)
		fprintf(stderr, "Error %" PRId64 ": %s (%s)\n", code, message,
			json_object_to_json_string(data));
	else
		fprintf(stderr, "Error %" PRId64 ": %s\n", code, message);
}

static bool resmon_c_handle_response(struct json_object *j, int expect_id,
				     enum json_type result_type,
				     struct json_object **ret_result)
{
	struct json_object *id;
	struct json_object *result;
	bool is_error;
	char *error;
	int err = resmon_jrpc_dissect_response(j, &id, &result, &is_error,
					       &error);
	if (err) {
		fprintf(stderr, "Invalid response object: %s\n", error);
		free(error);
		return false;
	}

	if (!resmon_c_validate_id(id, expect_id)) {
		fprintf(stderr, "Unknown response ID: %s\n",
			json_object_to_json_string(id));
		return false;
	}

	if (is_error) {
		resmon_c_handle_response_error(result);
		return false;
	}

	if (json_object_get_type(result) != result_type) {
		fprintf(stderr, "Unexpected result type: %s expected, got %s\n",
			json_type_to_name(json_object_get_type(result)),
			json_type_to_name(result_type));
		return false;
	}

	*ret_result = json_object_get(result);
	return true;
}

static struct json_object *resmon_c_send_request(struct json_object *request)
{
	struct json_object *response_obj = NULL;
	int err = -1;

	struct resmon_sock cli;
	struct resmon_sock peer;
	err = resmon_sock_open_c(&cli, &peer);
	if (err < 0) {
		fprintf(stderr, "Failed to open a socket: %m\n");
		return NULL;
	}

	err = resmon_jrpc_take_send(&peer, json_object_get(request));
	if (err < 0) {
		fprintf(stderr, "Failed to send the RPC message: %m\n");
		goto close_fd;
	}

	char *response;
	err = resmon_sock_recv(&cli, &peer, &response);
	if (err < 0) {
		fprintf(stderr, "Failed to receive an RPC response\n");
		goto close_fd;
	}

	response_obj = json_tokener_parse(response);
	if (response_obj == NULL) {
		fprintf(stderr, "Failed to parse RPC response as JSON.\n");
		goto free_response;
	}

free_response:
	free(response);
close_fd:
	resmon_sock_close_c(&cli);
	return response_obj;
}

int resmon_c_ping(void)
{
	int err;

	const int id = 1;
	struct json_object *request = resmon_jrpc_new_request(id, "ping");
	if (request == NULL)
		return -1;

	srand(time(NULL));
	const int r = rand();
	if (resmon_jrpc_object_take_add(request, "params",
					json_object_new_int(r))) {
		fprintf(stderr, "Failed to form a request object.\n");
		err = -1;
		goto put_request;
	}

	struct json_object *response = resmon_c_send_request(request);
	if (response == NULL) {
		err = -1;
		goto put_request;
	}

	struct json_object *result;
	if (!resmon_c_handle_response(response, id, json_type_int, &result)) {
		err = -1;
		goto put_response;
	}

	const int nr = json_object_get_int(result);
	if (nr != r) {
		fprintf(stderr, "Unexpected ping response: sent %d, got %d.\n",
			r, nr);
		err = -1;
		goto put_result;
	}

	if (env.verbosity > 0)
		fprintf(stderr, "resmond is alive\n");
	err = 0;

put_result:
	json_object_put(result);
put_response:
	json_object_put(response);
put_request:
	json_object_put(request);
	return err;
}

int resmon_c_stop(void)
{
	int err;

	const int id = 1;
	struct json_object *request = resmon_jrpc_new_request(id, "quit");
	if (request == NULL)
		return -1;

	struct json_object *response = resmon_c_send_request(request);
	if (response == NULL) {
		err = -1;
		goto put_request;
	}

	struct json_object *result;
	if (!resmon_c_handle_response(response, id, json_type_boolean, &result)) {
		err = -1;
		goto put_response;
	}

	if (json_object_get_boolean(result)) {
		if (env.verbosity > 0)
			fprintf(stderr, "resmond will stop\n");
		err = 0;
	} else {
		if (env.verbosity > 0)
			fprintf(stderr, "resmond refuses to stop\n");
		err = -1;
	}


	json_object_put(result);
put_response:
	json_object_put(response);
put_request:
	json_object_put(request);
	return err;
}

static void resmon_c_emad_help(void)
{
	fprintf(stderr,
		"Usage: resmon emad [hex | raw] string PAYLOAD\n"
		"\n"
	);
}

static int resmon_c_emad_jrpc(const char *payload, size_t payload_len)
{
	int err;

	const int id = 1;
	struct json_object *request = resmon_jrpc_new_request(id, "emad");
	if (request == NULL)
		return -1;

	struct json_object *params_obj = json_object_new_object();
	if (params_obj == NULL) {
		err = -ENOMEM;
		goto put_request;
	}

	struct json_object *payload_obj =
		json_object_new_string_len(payload, payload_len);
	if (payload_obj == NULL) {
		err = -ENOMEM;
		goto put_params_obj;
	}

	if (json_object_object_add(params_obj, "payload", payload_obj)) {
		err = -ENOMEM;
		goto put_payload_obj;
	}
	payload_obj = NULL;

	if (json_object_object_add(request, "params", params_obj)) {
		err = -1;
		goto put_params_obj;
	}
	params_obj = NULL;

	struct json_object *response = resmon_c_send_request(request);
	if (response == NULL) {
		err = -1;
		goto put_request;
	}

	struct json_object *result;
	if (!resmon_c_handle_response(response, id, json_type_null, &result)) {
		err = -1;
		goto put_response;
	}

	if (env.verbosity > 0)
		fprintf(stderr, "resmond took the EMAD\n");

	json_object_put(result);
put_response:
	json_object_put(response);
put_payload_obj:
	json_object_put(payload_obj);
put_params_obj:
	json_object_put(params_obj);
put_request:
	json_object_put(request);
	return err;
}

int resmon_c_emad(int argc, char **argv)
{
	int rc = 0;
	char *payload = NULL;
	size_t payload_len;
	enum {
		mode_hex,
		mode_raw,
	} mode = mode_hex;

	while (argc > 0) {
		if (strcmp(*argv, "raw") == 0) {
			mode = mode_raw;
		} else if (strcmp(*argv, "hex") == 0) {
			mode = mode_hex;
		} else if (strcmp(*argv, "string") == 0) {
			NEXT_ARG();
			payload = strdup(*argv);
			if (payload == NULL) {
				fprintf(stderr, "Failed to strdup: %m\n");
				rc = -1;
				goto out;
			}
			payload_len = strlen(payload);
			NEXT_ARG_FWD();
			break;
		} else if (strcmp(*argv, "help") == 0) {
			resmon_c_emad_help();
			goto out;
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			rc = -1;
			goto out;
		}
		continue;

incomplete_command:
		fprintf(stderr, "Command line is not complete. Try option \"help\"\n");
		rc = -1;
		goto out;
	}

	if (payload == NULL) {
		fprintf(stderr, "EMAD payload not given.\n");
		rc = -1;
		goto out;
	}

	if (mode == mode_raw) {
		char *enc_payload = malloc(payload_len * 2 + 1);
		if (enc_payload == NULL) {
			fprintf(stderr, "Failed to allocate buffer for decoded payload: %m\n");
			rc = -1;
			goto out;
		}

		for (size_t i = 0; i < payload_len; i++)
			sprintf(&enc_payload[2 * i], "%02x", payload[i]);
		free(payload);
		payload = enc_payload;
		payload_len = payload_len * 2;
	}

	rc = resmon_c_emad_jrpc(payload, payload_len);

out:
	free(payload);
	return rc;
}

static void resmon_c_stats_print(struct resmon_jrpc_counter *counters,
				 size_t num_counters)
{
	fprintf(stderr, "%-30s%s\n", "Resource", "Usage");

	for (size_t i = 0; i < num_counters; i++)
		fprintf(stderr, "%-30s%" PRId64 "\n",
			counters[i].descr, counters[i].value);
}

int resmon_c_stats(void)
{
	int err = 0;

	const int id = 1;
	struct json_object *request = resmon_jrpc_new_request(id, "stats");
	if (request == NULL)
		return -1;

	struct json_object *response = resmon_c_send_request(request);
	if (response == NULL) {
		err = -1;
		goto put_request;
	}

	struct json_object *result;
	if (!resmon_c_handle_response(response, id, json_type_object,
				      &result)) {
		err = -1;
		goto put_response;
	}

	struct resmon_jrpc_counter *counters;
	size_t num_counters;
	char *error;
	err = resmon_jrpc_dissect_stats(result, &counters, &num_counters,
					&error);
	if (err != 0) {
		fprintf(stderr, "Invalid counters object: %s\n", error);
		free(error);
		goto put_result;
	}

	resmon_c_stats_print(counters, num_counters);

	free(counters);
put_result:
	json_object_put(result);
put_response:
	json_object_put(response);
put_request:
	json_object_put(request);
	return err;
}
