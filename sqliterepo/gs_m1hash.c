/*
OpenIO SDS sqliterepo
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#include <metautils/lib/metautils.h>
#include <sqliterepo/sqlx_remote.h>
#include "hash.h"

/** TODO manage namespaces */

int
main(int argc, char **argv)
{
	if (argc < 2 || 1 != (argc % 2)) {
		g_printerr("Usage: %s (NAME TYPE)...\n", argv[0]);
		return 0;
	}

	for (int i=1; i<argc-1 ;i+=2) {
		struct sqlx_name_s n = {
			.base = argv[i],
			.type = argv[i+1],
			.ns = "",
		};
		struct hashstr_s *h = sqliterepo_hash_name(&n);
		g_print("%s.%s %s.%s\n", n.base, n.type, hashstr_str(h), n.type);
		g_free(h);
	}
	return 0;
}

