/*
OpenIO SDS core library
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
#include <stdlib.h>

#include <glib.h>

#include "oio_core.h"
#include "internals.h"
#include "oio_sds.h"

static void
_strfreev (char **tab)
{
	for (char **p=tab; *p ;++p)
		free (*p), *p = NULL;
	free (tab);
}

int
main (int argc UNUSED, char **argv UNUSED)
{
	char **tab = oio_sds_get_compile_options ();
	g_print ("COMPILE-TIME OPTIONS\n");
	for (char **p=tab; *p && *(p+1) ;p+=2)
		g_print ("\t%s = %s\n", *p, *(p+1));
	_strfreev (tab);

	g_print ("RUNTIME OPTIONS\n");
	GHashTable *live_config = oio_cfg_parse ();
	GHashTableIter iter;
	gpointer k, v;
	g_hash_table_iter_init(&iter, live_config);
	while (g_hash_table_iter_next(&iter, &k, &v))
		g_print("\t%s = %s\n", (gchar*)k, (gchar*)v);
	g_hash_table_destroy (live_config);

	return 0;
}

