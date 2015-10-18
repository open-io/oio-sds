#include <glib.h>
#include "metautils/lib/metautils.h"
#include "gridcluster.h"
int
main (int argc, char **argv)
{
	HC_PROC_INIT(argv, GRID_LOGLVL_INFO);
	GString *tmp = g_string_new("");
	for (;;) {
		g_string_set_size (tmp, 0);
		g_string_append_printf (tmp, "%f", oio_sys_cpu_idle ());
		for (int i=1; i<argc ;++i)
			g_string_append_printf (tmp, " %f", oio_sys_io_idle (argv[i]));
		g_print ("%s\n", tmp->str);
		g_usleep (500 * G_TIME_SPAN_MILLISECOND);
	}
	g_string_free (tmp, TRUE);
	return 0;
}

