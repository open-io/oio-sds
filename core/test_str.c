/*
OpenIO SDS metautils
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/
#include <string.h>
#include <glib.h>
#include "oio_core.h"
#include "internals.h"

static void
test_autocontainer (void)
{
	struct oio_str_autocontainer_config_s cfg = {
		.src_size = 0, .src_offset = 0, .dst_bits = 17
	};
	
	guint64 nb0 = 0, nb8 = 0;
	for (unsigned int i0=0; i0<256 ;i0++) {
		for (unsigned int i1=0; i1<256 ;i1++) {
			for (unsigned int i2=0; i2<256 ;i2++) {
				guint8 bin[] = {i0, i1, i2, 0, 0};
				gchar dst[65];

				const char *s = oio_str_autocontainer_hash (bin, sizeof(bin), dst, &cfg);
				g_assert (s != NULL);
				gchar last = s[strlen(s)-1];
				g_assert (last == '0' || last == '8');
				if (last == '0') ++nb0; else ++nb8;
			}
		}
	}
	g_assert (nb0 == nb8);
}

int
main(int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);
	oio_log_lazy_init ();
	oio_log_init_level(GRID_LOGLVL_INFO);
	g_log_set_default_handler(oio_log_stderr, NULL);

	g_test_add_func("/core/autocontainer", test_autocontainer);
	return g_test_run();
}

