/*
OpenIO SDS core library
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

#ifndef OIO_SDS__core_oioloc_h
# define OIO_SDS__core_oioloc_h 1

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OIO_LOC_FORMAT "016" G_GINT64_MODIFIER "X"
#define OIO_LB_LOC_LEVELS 4
#define OIO_LB_BITS_PER_LOC_LEVEL (sizeof(oio_location_t)*8/OIO_LB_LOC_LEVELS)

typedef guint64 oio_location_t;

enum oio_loc_proximity_level_e {
	OIO_LOC_PROX_NONE = 0,
	OIO_LOC_PROX_REGION = 1,
	OIO_LOC_PROX_ROOM = 2,
	OIO_LOC_PROX_RACK = 3,
	OIO_LOC_PROX_HOST = 4,
	OIO_LOC_PROX_VOLUME = 5,
};

enum oio_loc_distance_level_e {
	OIO_LOC_DIST_FARAWAY = 5,
	OIO_LOC_DIST_REGION = 4,
	OIO_LOC_DIST_ROOM = 3,
	OIO_LOC_DIST_RACK = 2,
	OIO_LOC_DIST_HOST = 1,
	OIO_LOC_DIST_VOLUME = 0,
};

/* What is the least location level that both given locations share? */
enum oio_loc_proximity_level_e oio_location_proximity(
		const oio_location_t loc0, const oio_location_t loc1);

/* What is the distance level between both locations? */
enum oio_loc_distance_level_e oio_location_distance(
		const oio_location_t loc0, const oio_location_t loc1);

/* Make a 32bit identifier from a 64bit location.
 * Level is the number of blocks of 16 least significant bits
 * to discard. */
guint32 key_from_loc_level(oio_location_t location, int level);

/* Take djb2 hash of each part of the '.'-separated string,
 * keep the 16 (or 8) LSB of each hash to build a 64 integer. */
oio_location_t location_from_dotted_string(const char *dotted);

/* Returns the number of bits in the mask corresponding to the
 * proximity level */
unsigned int oio_location_common_bits(enum oio_loc_proximity_level_e level);

/* Zeroes all the bits that are not in the mask corresponding to
 * the proximity level. I.e. gives the first location in the
 * proximity segment.*/
oio_location_t oio_location_mask_after(oio_location_t location,
		enum oio_loc_proximity_level_e level);

#ifdef __cplusplus
}
#endif

#endif  /* OIO_SDS__core_oioloc_h */
