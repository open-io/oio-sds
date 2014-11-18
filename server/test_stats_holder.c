#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "test"
#endif

#include "metautils/lib/metautils.h"
#include "server/stats_holder.h"
#include <glib.h>

static void
test_rrd (void)
{
	struct grid_single_rrd_s *rrd = grid_single_rrd_create(2, 60);
	grid_single_rrd_push(rrd, 3, 0);
	grid_single_rrd_push(rrd, 1000, 0);
	grid_single_rrd_push(rrd, 2, 0);
	grid_single_rrd_destroy(rrd);
}

int
main (int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/server/rrd", test_rrd);
	return g_test_run();
}

