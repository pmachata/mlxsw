// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <linux/types.h>

#include "resmon.h"

static struct sockaddr_un resmon_ctl_sockaddr(void)
{
	return (struct sockaddr_un) {
		.sun_family = AF_LOCAL,
		.sun_path = "/var/run/resmon.ctl",
	};
}

static struct sockaddr_un resmon_cli_sockaddr(void)
{
	static struct sockaddr_un sa = {};
	if (sa.sun_family == AF_UNSPEC) {
		snprintf(sa.sun_path, sizeof(sa.sun_path),
			 "/var/run/resmon.cli.%d", getpid());
		sa.sun_family = AF_LOCAL;
	}
	return sa;
}

static int resmon_sock_open(struct sockaddr_un sa,
			    struct resmon_sock *sock)
{
	*sock = (struct resmon_sock) { .fd = -1 };

	int fd = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "Failed to create control socket: %m\n");
		return -1;
	}

	unlink(sa.sun_path);

	int err = bind(fd, (struct sockaddr *) &sa, sizeof(sa));
	if (err < 0) {
		fprintf(stderr, "Failed to bind control socket: %m\n");
		goto close_fd;
	}

	*sock = (struct resmon_sock) {
		.fd = fd,
		.sa = sa,
		.len = sizeof(sa),
	};
	return 0;

close_fd:
	close(fd);
	return err;
}

static void resmon_sock_close(struct resmon_sock *sock)
{
	close(sock->fd);
	unlink(sock->sa.sun_path);
}

int resmon_sock_open_d(struct resmon_sock *ctl)
{
	return resmon_sock_open(resmon_ctl_sockaddr(), ctl);
}

void resmon_sock_close_d(struct resmon_sock *ctl)
{
	resmon_sock_close(ctl);
}

int resmon_sock_open_c(struct resmon_sock *cli,
		       struct resmon_sock *peer)
{
	int err = resmon_sock_open(resmon_cli_sockaddr(), cli);
	if (err)
		return err;

	*peer = (struct resmon_sock) {
		.fd = cli->fd,
		.sa = resmon_ctl_sockaddr(),
		.len = sizeof(peer->sa),
	};
	err = connect(cli->fd, (struct sockaddr *) &peer->sa, peer->len);
	if (err != 0) {
		fprintf(stderr, "Failed to connect to %s: %m\n",
			peer->sa.sun_path);
		goto close_cli;
	}

	return 0;

close_cli:
	resmon_sock_close_c(cli);
	return -1;

}

void resmon_sock_close_c(struct resmon_sock *cli)
{
	resmon_sock_close(cli);
}

int resmon_sock_recv(struct resmon_sock *sock, struct resmon_sock *peer,
		     char **bufp)
{
	int err;

	*bufp = NULL;
	*peer = (struct resmon_sock) {
		.fd = sock->fd,
		.len = sizeof(peer->sa),
	};
	ssize_t msgsz = recvfrom(sock->fd, NULL, 0, MSG_PEEK | MSG_TRUNC,
				 (struct sockaddr *) &peer->sa, &peer->len);
	if (msgsz < 0) {
		fprintf(stderr, "Failed to receive data on control socket: %m\n");
		return -1;
	}

	char *buf = calloc(1, msgsz + 1);
	if (buf == NULL) {
		fprintf(stderr, "Failed to allocate control message buffer: %m\n");
		return -1;
	}

	ssize_t n = recv(sock->fd, buf, msgsz, 0);
	if (n < 0) {
		fprintf(stderr, "Failed to receive data on control socket: %m\n");
		err = -1;
		goto out;
	}
	buf[n] = '\0';

	*bufp = buf;
	buf = NULL;
	err = 0;

out:
	free(buf);
	return err;
}
