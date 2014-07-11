#include <assert.h>
#include <stdio.h>
#include <sys/time.h>

#include <metautils/lib/metautils.h>

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

