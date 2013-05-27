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

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.metautils"
#endif

#include <string.h>

#include <glib.h>

#include "./metatypes.h"
#include "./metautils.h"
#include "./resolv.h"

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
			buffer2str(&addr, sizeof(addr), hexa, sizeof(hexa));
			g_print("%s %s\n", str, hexa);
		}
	}

	return 0;
}

