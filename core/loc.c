/*
OpenIO SDS load-balancing
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS

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

#include <core/oioloc.h>

#include "internals.h"

oio_location_t
location_from_dotted_string(const char *dotted)
{
	gchar **toks = g_strsplit(dotted, ".", OIO_LB_LOC_LEVELS);
	oio_location_t location = 0;
	int ntoks = 0;
	// according to g_strsplit documentation, toks cannot be NULL
	for (gchar **tok = toks; *tok; tok++, ntoks++) {
		location = (location << OIO_LB_BITS_PER_LOC_LEVEL) |
				(djb_hash_str0(*tok) & 0xFFFF);
	}
	g_strfreev(toks);
	return location;
}

#if __SIZEOF_LONG__ == 8
#define _loc_clz(l0,l1)  __builtin_clzl(loc0 ^ loc1)
#elif __SIZEOF_LONG_LONG__ == 8
#define _loc_clz(l0,l1)  __builtin_clzll(loc0 ^ loc1)
#else
#define _loc_clz(l0,l1)  __builtin_clz(loc0 ^ loc1)
#endif

enum oio_loc_proximity_level_e
oio_location_proximity(const oio_location_t loc0, const oio_location_t loc1)
{
	static const enum oio_loc_proximity_level_e app[64] = {
		[0 ... 7] = OIO_LOC_PROX_NONE,     /* the region differs */
		[8 ... 15] = OIO_LOC_PROX_REGION,  /* the room differs */
		[16 ... 31] = OIO_LOC_PROX_ROOM,   /* the rack differs */
		[32 ... 47] = OIO_LOC_PROX_RACK,   /* the host differs */
		[48 ... 63] = OIO_LOC_PROX_HOST,   /* the volume differs */
	};
	return app[_loc_clz(loc0, loc1)];
}

guint
oio_location_distance(const oio_location_t loc0, const oio_location_t loc1)
{
	static const enum oio_loc_proximity_level_e app[64] = {
		[0 ... 7] = OIO_LOC_DIST_FARAWAY,  /* the region differs */
		[8 ... 15] = OIO_LOC_DIST_REGION,  /* the room differs */
		[16 ... 31] = OIO_LOC_DIST_ROOM,   /* the rack differs */
		[32 ... 47] = OIO_LOC_DIST_RACK,   /* the host differs */
		[48 ... 63] = OIO_LOC_DIST_HOST,   /* the volume differs */
	};
	return loc0 == loc1 ? OIO_LOC_DIST_VOLUME : app[_loc_clz(loc0, loc1)];
}

unsigned int
oio_location_common_bits(enum oio_loc_proximity_level_e level)
{
	switch (level) {
		case OIO_LOC_PROX_NONE:
			return 0;
		case OIO_LOC_PROX_REGION:
			return 8;
		case OIO_LOC_PROX_ROOM:
			return 16;
		case OIO_LOC_PROX_RACK:
			return 32;
		case OIO_LOC_PROX_HOST:
			return 48;
		default:
			return 64;
	}
}

oio_location_t
oio_location_mask_after(oio_location_t location,
		enum oio_loc_proximity_level_e level)
{
	const unsigned int shift = 64 - oio_location_common_bits(level);
	if (likely(shift == 0))
		return location;
	return (location >> shift) << shift;
}
