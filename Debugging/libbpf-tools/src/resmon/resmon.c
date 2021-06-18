// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <argp.h>
#include <stdio.h>

#include "resmon.h"

struct resmon_env env = {
	.verbosity = 0,
	.bpffs = "/sys/fs/bpf",
};
const char *program_version = "resmon 0.0";
const char *program_bug_address = "<mlxsw@nvidia.com>";

static int resmon_help(void);

static int resmon_common_args(int argc, char **argv,
			      int (*and_then)(int argc, char **argv))
{
	while (argc) {
		if (strcmp(*argv, "help") == 0) {
			return resmon_help();
		} else {
			break;
		}
	}

	return and_then(argc, argv);
}

static int resmon_common_args_only_check(int argc, char **argv)
{
	return argc == 0 ? 0 : -1;
}

static int resmon_common_args_only(int argc, char **argv,
				   int (*and_then)(void))
{
	int err = resmon_common_args(argc, argv,
				     resmon_common_args_only_check);
	if (err)
		return err;
	return and_then();
}

static int resmon_cmd_start(int argc, char **argv)
{
	return resmon_d_start(argc, argv);
}

static int resmon_cmd_stop(int argc, char **argv)
{
	return resmon_common_args_only(argc, argv, resmon_c_stop);
}

static int resmon_cmd_ping(int argc, char **argv)
{
	return resmon_common_args_only(argc, argv, resmon_c_ping);
}

static int resmon_cmd_emad(int argc, char **argv)
{
	return resmon_c_emad(argc, argv);
}

static int resmon_cmd_stats(int argc, char **argv)
{
	return resmon_common_args_only(argc, argv, resmon_c_stats);
}

static int resmon_cmd(int argc, char **argv)
{
	if (!argc || strcmp(*argv, "help") == 0)
		return resmon_help();
	else if (strcmp(*argv, "start") == 0)
		return resmon_cmd_start(argc - 1, argv + 1);
	else if (strcmp(*argv, "stop") == 0)
		return resmon_cmd_stop(argc - 1, argv + 1);
	else if (strcmp(*argv, "ping") == 0)
		return resmon_cmd_ping(argc - 1, argv + 1);
	else if (strcmp(*argv, "emad") == 0)
		return resmon_cmd_emad(argc - 1, argv + 1);
	else if (strcmp(*argv, "stats") == 0)
		return resmon_cmd_stats(argc - 1, argv + 1);

	fprintf(stderr, "Unknown command \"%s\"\n", *argv);
	return -EINVAL;
}

static int resmon_help(void)
{
	puts("Monitor resource usage in a Spectrum switch.\n"
	     "\n"
	     "Usage: resmon [OPTIONS] { COMMAND | help }\n"
	     "where  OPTIONS := [ -h | --help | -q | --quiet | -v | --verbose |\n"
	     "			  -V | --version | --bpffs <PATH> ]\n"
	     "	     COMMAND := { start | stop | ping | stats }\n"
	     );
	return 0;
}

enum {
	resmon_opt_bpffs,
};

int main(int argc, char **argv)
{
	static const struct option long_options[] = {
		{ "help",	no_argument,	   NULL, 'h' },
		{ "quiet",	no_argument,	   NULL, 'q' },
		{ "verbose",	no_argument,	   NULL, 'v' },
		{ "Version",	no_argument,	   NULL, 'V' },
		{ "bpffs",	required_argument, NULL, resmon_opt_bpffs },
		{ NULL, 0, NULL, 0 }
	};
	int opt;

	while ((opt = getopt_long(argc, argv, "hqvV",
				  long_options, NULL)) >= 0) {
		switch (opt) {
		case 'V':
			printf("mlxsw resource monitoring tool, %s\n", program_version);
			return 0;
		case 'h':
			resmon_help();
			return 0;
		case 'v':
			env.verbosity++;
			break;
		case 'q':
			env.verbosity--;
			break;
		case resmon_opt_bpffs:
			env.bpffs = optarg;
			break;
		default:
			fprintf(stderr, "Unknown option.\n");
			resmon_help();
			return 1;
		}
	}

	argc -= optind;
	argv += optind;

	return resmon_cmd(argc, argv);
}
