// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <stdlib.h>

#include "resmon.h"

struct resmon_stat {
	struct resmon_stat_counters counters;
};

struct resmon_stat *resmon_stat_create(void)
{
	struct resmon_stat *stat = malloc(sizeof(*stat));
	return stat;
}

void resmon_stat_destroy(struct resmon_stat *stat)
{
	free(stat);
}

struct resmon_stat_counters resmon_stat_counters(struct resmon_stat *stat)
{
	return stat->counters;
}
