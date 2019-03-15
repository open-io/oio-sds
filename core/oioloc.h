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

/* Make a 32bit identifier from a 64bit location.
 * Level is the number of blocks of 16 least significant bits
 * to discard. */
guint32 key_from_loc_level(oio_location_t location, int level);

/* Take djb2 hash of each part of the '.'-separated string,
 * keep the 16 (or 8) LSB of each hash to build a 64 integer. */
oio_location_t location_from_dotted_string(const char *dotted);

#ifdef __cplusplus
}
#endif

#endif  /* OIO_SDS__core_oioloc_h */
