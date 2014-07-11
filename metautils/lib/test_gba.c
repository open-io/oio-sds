#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metautils.url"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <glib.h>

#include "./metautils.h"

static void
_dummy_gba(GByteArray *gba, guint v, register guint len)
{
	g_byte_array_set_size(gba, 0);
	for (register guint i=0; i<len ;++i)
		gba = g_byte_array_append(gba, (guint8*)&v, sizeof(v));
}

#define COUNT 65536

static void
test_gba_cmp(void)
{
	GByteArray *a = g_byte_array_new();
	GByteArray *b = g_byte_array_new();

	guint v = 0;
	for (register guint i=0; i<COUNT ;++i) {
		_dummy_gba(a, v++, 4);
		_dummy_gba(b, v++, 4);
		g_assert(0 != metautils_gba_cmp(a, b));
	}
	for (register guint i=0; i<COUNT ;++i) {
		_dummy_gba(a, v++, 4);
		_dummy_gba(b, v++, 5);
		g_assert(0 != metautils_gba_cmp(a, b));
	}
	for (register guint i=0; i<COUNT ;++i) {
		_dummy_gba(a, v, 4);
		_dummy_gba(b, v, 5);
		v++;
		g_assert(0 != metautils_gba_cmp(a, b));
	}
	for (register guint i=0; i<COUNT ;++i) {
		_dummy_gba(a, v, 4);
		_dummy_gba(b, v, 4);
		v++;
		g_assert(0 == metautils_gba_cmp(a, b));
	}
	for (register guint i=0; i<COUNT ;++i) {
		_dummy_gba(a, v, 4);
		v++;
		g_assert(0 == metautils_gba_cmp(a, a));
	}

	g_byte_array_free(a, TRUE);
	g_byte_array_free(b, TRUE);
}

int
main(int argc, char **argv)
{
	HC_PROC_INIT(argv, GRID_LOGLVL_TRACE2);
	g_test_init (&argc, &argv, NULL);
	g_test_add_func("/metautils/gba/cmp", test_gba_cmp);
	return g_test_run();
}

