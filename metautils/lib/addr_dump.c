/*
OpenIO SDS metautils
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

#include "metautils.h"

int
main(int argc, char **args)
{
	gchar str[256], hexa[1024];
	struct addr_info_s addr;
	int i;

	for (i=1; i<argc ; i++) {
		memset(&addr, 0, sizeof(addr));
		if (grid_string_to_addrinfo(args[i], NULL, &addr)) {
			memset(str, 0, sizeof(str));
			addr_info_to_string(&addr, str, sizeof(str));
			memset(hexa, 0, sizeof(hexa));
			oio_str_bin2hex(&addr, sizeof(addr), hexa, sizeof(hexa));
			g_print("%s %s\n", str, hexa);
		}
	}

	return 0;
}

