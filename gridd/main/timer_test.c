/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <stdio.h>
#include <sys/time.h>

#include <glib.h>

#include <metautils.h>

#include "./srvtimer.h"
#include "./srvstats.h"

#define STATPREFIX "stat."

#define NEWSTAT(N,V,F) do \
{\
	assert(srvstat_set (N,V));\
	srvtimer_register_regular (N, stat_increment, NULL, N, F);\
} while (0)

void
stat_increment(gpointer u)
{
	double v = 0.0;
	char *n = (char *) u;

	if (srvstat_get(n, &v)) {
		v += 0.1;
		fprintf(stdout, "<%s> %s -> %f\r\n", __FUNCTION__, n, v);
		assert(srvstat_set(n, v));
	}
	else
		fprintf(stdout, "<%s> %s not found\r\n", __FUNCTION__, n);
}

static volatile int mayContinue = 1;

int
main(int argc, char **args)
{
	guint64 ticks = 0;

	(void)argc;
	(void)args;
	log4c_init();
	srvstat_init();
	srvtimer_init();

	NEWSTAT(STATPREFIX "1", 1000.0, 1);
	NEWSTAT(STATPREFIX "2", 2000.0, 2);
	NEWSTAT(STATPREFIX "4", 4000.0, 4);

	while (mayContinue) {
		struct timeval tv = { 1, 0 };
		select(0, NULL, NULL, NULL, &tv);
		srvtimer_fire(++ticks);
	}

	srvstat_flush();

	srvtimer_fini();
	srvstat_fini();
}
