// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <argp.h>
#include <stdio.h>

#include "resmon.h"

struct resmon_env env = {
	.verbosity = 0,
};
const char *program_version = "resmon 0.0";
const char *program_bug_address = "<mlxsw@nvidia.com>";

static int resmon_help(void)
{
	puts("Monitor resource usage in a Spectrum switch.\n"
	     "\n"
	     "Usage: resmon [OPTIONS] { COMMAND | help }\n"
	     "where  OPTIONS := [ -h | --help | -q | --quiet | -v | --verbose |\n"
	     "			  -V | --version ]\n"
	     "	     COMMAND := { start | stop }\n"
	     );
	return 0;
}

static int resmon_cmd(int argc, char **argv)
{
	if (!argc || strcmp(*argv, "help") == 0) {
		return resmon_help();
	} else if (strcmp(*argv, "start") == 0) {
		NEXT_ARG_FWD();
		return resmon_d_start(argc, argv);
	} else if (strcmp(*argv, "stop") == 0) {
		NEXT_ARG_FWD();
		return resmon_c_stop(argc, argv);
	}

	fprintf(stderr, "Unknown command \"%s\"\n", *argv);
	return -EINVAL;
}

int main(int argc, char **argv)
{
	static const struct option long_options[] = {
		{ "help",	no_argument,	   NULL, 'h' },
		{ "quiet",	no_argument,	   NULL, 'q' },
		{ "verbose",	no_argument,	   NULL, 'v' },
		{ "version",	no_argument,	   NULL, 'V' },
		{ NULL, 0, NULL, 0 }
	};
	int opt;

	while ((opt = getopt_long(argc, argv, "hqvV",
				  long_options, NULL)) >= 0) {
		switch (opt) {
		case 'V':
			printf("mlxsw resource monitoring tool, %s\n",
			       program_version);
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
