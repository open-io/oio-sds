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

#include <glib.h>
#include "../metautils/lib/hashstr.h"
#include "./hash.h"

int
main(int argc, char **argv)
{
	int i;
	for (i=1; i<argc ;i++) {
		hashstr_t *h = sqliterepo_hash_name(argv[i], "meta1");
		g_print("%s meta1 %s.meta1 %s\n", argv[i], argv[i],
				hashstr_str(h));
		g_free(h);
	}
	return 0;
}

