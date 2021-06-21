/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef RESMON_H
#define RESMON_H

#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/un.h>
#include <json-c/json_object.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

#define NEXT_ARG() do { argv++; if (--argc <= 0) goto incomplete_command; } while (0)
#define NEXT_ARG_OK() (argc - 1 > 0)
#define NEXT_ARG_FWD() do { argv++; argc--; } while (0)
#define PREV_ARG() do { argv--; argc++; } while (0)

/* resmon.c */

extern struct resmon_env {
	int verbosity;
} env;

/* resmon-sock.c */

struct resmon_sock {
	int fd;
	struct sockaddr_un sa;
	socklen_t len;
};

int resmon_sock_open_d(struct resmon_sock *ctl);
void resmon_sock_close_d(struct resmon_sock *ctl);
int resmon_sock_open_c(struct resmon_sock *cli,
		       struct resmon_sock *peer);
void resmon_sock_close_c(struct resmon_sock *cli);

int resmon_sock_recv(struct resmon_sock *sock,
		     struct resmon_sock *peer,
		     char **bufp);

/* resmon-jrpc.c */

struct json_object *resmon_jrpc_new_object(struct json_object *id);
struct json_object *resmon_jrpc_new_request(int id, const char *method);
struct json_object *resmon_jrpc_new_error(struct json_object *id,
					  int code,
					  const char *message,
					  const char *data);

int resmon_jrpc_dissect_request(struct json_object *obj,
				struct json_object **id,
				const char **method,
				struct json_object **params,
				char **error);
int resmon_jrpc_dissect_response(struct json_object *obj,
				 struct json_object **id,
				 struct json_object **result,
				 bool *is_error,
				 char **error);
int resmon_jrpc_dissect_error(struct json_object *obj,
			      int64_t *code,
			      const char **message,
			      struct json_object **data,
			      char **error);
int resmon_jrpc_dissect_params_empty(struct json_object *obj,
				     char **error);

struct resmon_jrpc_counter {
	const char *descr;
	int64_t value;
};
int resmon_jrpc_dissect_stats(struct json_object *obj,
			      struct resmon_jrpc_counter **counters,
			      size_t *num_counters,
			      char **error);

int resmon_jrpc_object_take_add(struct json_object *obj,
				const char *key, struct json_object *val_obj);

int resmon_jrpc_take_send(struct resmon_sock *sock, struct json_object *obj);

/* resmon-c.c */

int resmon_c_ping(int argc, char **argv);
int resmon_c_stop(int argc, char **argv);
int resmon_c_stats(int argc, char **argv);

/* resmon-stat.c */

#define RESMON_COUNTER_EXPAND_AS_ENUM(NAME, DESCRIPTION) \
	RESMON_COUNTER_ ## NAME,
#define RESMON_COUNTER_EXPAND_AS_DESC(NAME, DESCRIPTION) \
	DESCRIPTION,
#define EXPAND_AS_PLUS1(...) + 1

#define RESMON_COUNTERS(X)

enum { resmon_counter_count = 0 RESMON_COUNTERS(EXPAND_AS_PLUS1) };

struct resmon_stat;

struct resmon_stat_counters {
	int64_t values[resmon_counter_count];
};

struct resmon_stat *resmon_stat_create(void);
void resmon_stat_destroy(struct resmon_stat *stat);
struct resmon_stat_counters resmon_stat_counters(struct resmon_stat *stat);

/* resmon-back.c */

struct resmon_back {
	const struct resmon_back_cls *cls;
};

struct resmon_back_cls {
	struct resmon_back *(*init)(void);
	void (*fini)(struct resmon_back *back);

};

extern const struct resmon_back_cls resmon_back_cls_mock;

/* resmon-d.c */

int resmon_d_start(int argc, char **argv);

void resmon_d_respond_error(struct resmon_sock *ctl,
			    struct json_object *id, int code,
			    const char *message, const char *data);
void resmon_d_respond_invalid_params(struct resmon_sock *ctl, const char *data);
void resmon_d_respond_memerr(struct resmon_sock *peer, struct json_object *id);

#endif /* RESMON_H */
