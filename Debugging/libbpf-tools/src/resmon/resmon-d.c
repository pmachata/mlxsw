// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>

#include "resmon.h"

static bool should_quit;

static void resmon_d_quit(void)
{
	if (env.verbosity > 0)
		fprintf(stderr, "Quitting\n");
	should_quit = true;
}

static void resmon_d_handle_signal(int sig)
{
	resmon_d_quit();
}

static int resmon_d_setup_signals(void)
{
	if (signal(SIGINT, resmon_d_handle_signal) == SIG_ERR) {
		fprintf(stderr, "Failed to set up SIGINT handling: %m\n");
		return -1;
	}
	if (signal(SIGQUIT, resmon_d_handle_signal) == SIG_ERR) {
		fprintf(stderr, "Failed to set up SIGQUIT handling: %m\n");
		return -1;
	}
	if (signal(SIGTERM, resmon_d_handle_signal) == SIG_ERR) {
		fprintf(stderr, "Failed to set up SIGTERM handling: %m\n");
		return -1;
	}
	return 0;
}

void resmon_d_respond_error(struct resmon_sock *ctl,
			    struct json_object *id, int code,
			    const char *message, const char *data)
{
	resmon_jrpc_take_send(ctl,
		resmon_jrpc_new_error(id, code, message, data));
}

static void resmon_d_respond_invalid(struct resmon_sock *ctl, const char *data)
{
	resmon_jrpc_take_send(ctl,
		resmon_jrpc_new_error(NULL, -32600, "Invalid Request", data));
}

static void resmon_d_respond_method_nf(struct resmon_sock *peer,
				       struct json_object *id,
				       const char *method)
{
	resmon_jrpc_take_send(peer,
		resmon_jrpc_new_error(id, -32601, "Method not found", method));
}

void resmon_d_respond_invalid_params(struct resmon_sock *ctl, const char *data)
{
	resmon_jrpc_take_send(ctl,
		resmon_jrpc_new_error(NULL, -32602, "Invalid params", data));
}

static void resmon_d_respond_interr(struct resmon_sock *peer,
				    struct json_object *id,
				    const char *data)
{
	resmon_jrpc_take_send(peer,
		resmon_jrpc_new_error(id, -32603, "Internal error", data));
}

void resmon_d_respond_memerr(struct resmon_sock *peer, struct json_object *id)
{
	resmon_d_respond_interr(peer, id, "Memory allocation issue");
}

static void resmon_d_handle_ping(struct resmon_sock *peer,
				 struct json_object *params_obj,
				 struct json_object *id)
{
	struct json_object *obj = resmon_jrpc_new_object(id);
	if (obj == NULL)
		return;

	if (resmon_jrpc_object_take_add(obj, "result",
					json_object_get(params_obj)))
		goto put_obj;

	resmon_jrpc_take_send(peer, obj);
	return;

put_obj:
	json_object_put(obj);
	resmon_d_respond_memerr(peer, id);
}

static void resmon_d_handle_quit(struct resmon_sock *peer,
				 struct json_object *params_obj,
				 struct json_object *id)
{
	resmon_d_quit();

	char *error;
	int rc = resmon_jrpc_dissect_params_empty(params_obj, &error);
	if (rc) {
		resmon_d_respond_invalid_params(peer, error);
		free(error);
		return;
	}

	struct json_object *obj = resmon_jrpc_new_object(id);
	if (obj == NULL)
		return;

	if (resmon_jrpc_object_take_add(obj, "result",
					json_object_new_boolean(true)))
		goto put_obj;

	resmon_jrpc_take_send(peer, obj);
	return;

put_obj:
	json_object_put(obj);
	resmon_d_respond_memerr(peer, id);
}

static const char *const resmon_d_counter_descriptions[] = {
	RESMON_COUNTERS(RESMON_COUNTER_EXPAND_AS_DESC)
};

static int resmon_d_stats_attach_counter(struct json_object *counters_obj,
					 int counter, int64_t value)
{
	int rc;
	struct json_object *counter_obj = json_object_new_object();
	if (counter_obj == NULL)
		return -1;

	rc = resmon_jrpc_object_take_add(counter_obj, "id",
					 json_object_new_int(counter));
	if (rc)
		goto put_counter_obj;

	const char *descr = resmon_d_counter_descriptions[counter];
	rc = resmon_jrpc_object_take_add(counter_obj, "descr",
					 json_object_new_string(descr));

	if (rc)
		goto put_counter_obj;

	rc = resmon_jrpc_object_take_add(counter_obj, "value",
					 json_object_new_int64(value));
	if (rc)
		goto put_counter_obj;

	rc = json_object_array_add(counters_obj, counter_obj);
	if (rc)
		goto put_counter_obj;

	return 0;

put_counter_obj:
	json_object_put(counter_obj);
	return -1;
}

static void resmon_d_handle_stats(struct resmon_stat *stat,
				  struct resmon_sock *peer,
				  struct json_object *params_obj,
				  struct json_object *id)
{
	/* The response is as follows:
	 *
	 * {
	 *     "id": ...,
	 *     "result": {
	 *         "counters": [
	 *             {
	 *                 "id": counter number as per enum resmon_counter,
	 *                 "description": string with human-readable descr.,
	 *                 "value": integer, value of the counter
	 *             },
	 *             ....
	 *         ]
	 *     }
	 * }
	 */

	char *error;
	int rc = resmon_jrpc_dissect_params_empty(params_obj, &error);
	if (rc) {
		resmon_d_respond_invalid_params(peer, error);
		free(error);
		return;
	}

	struct json_object *obj = resmon_jrpc_new_object(id);
	if (obj == NULL)
		return;

	struct json_object *result_obj = json_object_new_object();
	if (result_obj == NULL)
		goto put_obj;

	struct json_object *counters_obj = json_object_new_array();
	if (counters_obj == NULL)
		goto put_result_obj;

	struct resmon_stat_counters counters = resmon_stat_counters(stat);
	for (int i = 0; i < ARRAY_SIZE(counters.values); i++) {
		int rc = resmon_d_stats_attach_counter(counters_obj, i,
						       counters.values[i]);
		if (rc)
			goto put_counters_obj;
	}

	if (resmon_jrpc_object_take_add(result_obj, "counters",
					counters_obj))
		goto put_result_obj;

	if (resmon_jrpc_object_take_add(obj, "result",
					result_obj))
		goto put_obj;

	resmon_jrpc_take_send(peer, obj);
	return;

put_counters_obj:
	json_object_put(counters_obj);
put_result_obj:
	json_object_put(result_obj);
put_obj:
	json_object_put(obj);
	resmon_d_respond_memerr(peer, id);
}

static void resmon_d_handle_method(struct resmon_back *back,
				   struct resmon_stat *stat,
				   struct resmon_sock *peer,
				   const char *method,
				   struct json_object *params_obj,
				   struct json_object *id)
{
	if (strcmp(method, "quit") == 0)
		return resmon_d_handle_quit(peer, params_obj, id);
	else if (strcmp(method, "ping") == 0)
		return resmon_d_handle_ping(peer, params_obj, id);
	else if (strcmp(method, "stats") == 0)
		return resmon_d_handle_stats(stat, peer, params_obj, id);
	else
		return resmon_d_respond_method_nf(peer, id, method);
}

static int resmon_d_ctl_activity(struct resmon_back *back,
				 struct resmon_stat *stat,
				 struct resmon_sock *ctl)
{
	int err;

	struct resmon_sock peer;
	char *request = NULL;
	err = resmon_sock_recv(ctl, &peer, &request);
	if (err < 0)
		return err;

	// xxx
	fprintf(stderr, "activity: '%s'\n", request);

	struct json_object *request_obj = json_tokener_parse(request);
	if (request_obj == NULL) {
		resmon_d_respond_invalid(&peer, NULL);
		goto free_req;
	}

	struct json_object *id;
	const char *method;
	struct json_object *params;
	char *error;
	err = resmon_jrpc_dissect_request(request_obj, &id, &method, &params,
					  &error);
	if (err) {
		resmon_d_respond_invalid(&peer, error);
		free(error);
		goto put_req_obj;
	}

	resmon_d_handle_method(back, stat, &peer, method, params, id);

put_req_obj:
	json_object_put(request_obj);
free_req:
	free(request);
	return 0;
}

static int resmon_d_loop(struct resmon_back *back, struct resmon_stat *stat)
{
	int err;

	err = resmon_d_setup_signals();
	if (err < 0)
		return -1;

	struct resmon_sock ctl;
	err = resmon_sock_open_d(&ctl);
	if (err)
		return err;

	if (env.verbosity > 0)
		fprintf(stderr, "Listening on %s\n", ctl.sa.sun_path);

	enum {
		pollfd_ctl,
	};

	struct pollfd pollfds[] = {
		[pollfd_ctl] = {
			.fd = ctl.fd,
			.events = POLLIN,
		},
	};

	while (!should_quit) {
		int nfds = poll(pollfds, ARRAY_SIZE(pollfds), -1);
		if (nfds < 0 && errno != EINTR) {
			fprintf(stderr, "Failed to poll: %m\n");
			err = nfds;
			goto out;
		}
		if (nfds == 0)
			continue;
		for (size_t i = 0; i < ARRAY_SIZE(pollfds); i++) {
			struct pollfd *pollfd = &pollfds[i];

			if (pollfd->revents & (POLLERR | POLLHUP |
					       POLLNVAL)) {
				fprintf(stderr,
					"Problem on pollfd %zd: %m\n", i);
				err = -1;
				goto out;
			}
			if (pollfd->revents & POLLIN) {
				switch (i) {
				case pollfd_ctl:
					err = resmon_d_ctl_activity(back, stat,
								    &ctl);
					if (err != 0)
						goto out;
					break;
				}
			}
		}
	}

out:
	resmon_sock_close_d(&ctl);
	return err;
}

static int resmon_d_do_start(const struct resmon_back_cls *back_cls)
{
	int err = 0;

	struct resmon_stat *stat = resmon_stat_create();
	if (stat == NULL)
		return -1;

	struct resmon_back *back = back_cls->init();
	if (back == NULL)
		goto destroy_stat;

	openlog("resmon", LOG_PID | LOG_CONS, LOG_USER);

	err = resmon_d_loop(back, stat);

	closelog();
	back_cls->fini(back);
destroy_stat:
	resmon_stat_destroy(stat);
	return err;
}

static void resmon_d_start_help(void)
{
	fprintf(stderr,
		"Usage: resmon start [mode mock]\n"
		"\n"
	);
}

int resmon_d_start(int argc, char **argv)
{
	enum {
		mode_mock
	} mode = mode_mock;

	while (argc > 0) {
		if (strcmp(*argv, "mode") == 0) {
			NEXT_ARG();
			if (strcmp(*argv, "mock") == 0) {
				mode = mode_mock;
			} else {
				fprintf(stderr, "Unrecognized mode: %s\n", *argv);
				return -1;
			}
			NEXT_ARG_FWD();
			break;
		} else if (strcmp(*argv, "help") == 0) {
			resmon_d_start_help();
			return 0;
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			return -1;
		}
		continue;

incomplete_command:
		fprintf(stderr, "Command line is not complete. Try option \"help\"\n");
		return -1;
	}

	const struct resmon_back_cls *back_cls;
	switch (mode) {
	case mode_mock:
		back_cls = &resmon_back_cls_mock;
		break;
	}

	return resmon_d_do_start(back_cls);
}
