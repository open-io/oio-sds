#include <glib.h>
#define GQ()                    g_quark_from_static_string(G_LOG_DOMAIN)
#define NEWERROR(CODE, FMT,...) g_error_new(GQ(), (CODE), FMT, ##__VA_ARGS__)

int
main (int argc, char **argv)
{
	(void) argc, (void) argv;
	GError *err = NEWERROR(400, "It works!");
	g_error_free(err);
	return 0;
}

