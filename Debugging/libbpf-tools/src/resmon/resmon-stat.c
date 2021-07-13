// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include <stdlib.h>

#include "resmon.h"

struct resmon_stat {
	struct resmon_stat_counters counters;
};

struct resmon_stat *resmon_stat_create(void)
{
	struct resmon_stat *stat;

	stat = malloc(sizeof(*stat));
	if (stat == NULL)
		return NULL;

	*stat = (struct resmon_stat){
	};
	return stat;
}

void resmon_stat_destroy(struct resmon_stat *stat)
{
	free(stat);
}

struct resmon_stat_counters resmon_stat_counters(struct resmon_stat *stat)
{
	struct resmon_stat_counters counters = stat->counters;

	for (size_t i = 0; i < resmon_counter_count; i++)
		counters.total += counters.values[i];

	return counters;
}
