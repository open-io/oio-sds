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

#ifndef OIO_SDS__core__oioext_h
# define OIO_SDS__core__oioext_h 1

#ifdef __cplusplus
extern "C" {
#endif

# include <glib.h>

/** Shuffles the single linked list. The original <src> MUST NOT be reused. */
GSList * oio_ext_gslist_shuffle(GSList *src);

/** Shuffles <array> in place. <len> is the len of the array. <len> must be
 * greater than 1. */
void oio_ext_array_shuffle (gpointer *array, gsize len);

/** Sorts 'src' in place, placing first the items with a FALSE predicate
 * then the items with a TRUE predicate */
void oio_ext_array_partition (gpointer *array, gsize len,
		gboolean (*predicate)(gconstpointer));

/** Forward declaration from the json-c. It helps us avoiding an incude. */
struct json_object;

struct oio_ext_json_mapping_s {
	const char *name;
	struct json_object **out;
	int type;
	unsigned int mandatory;
};

/** In one call, extract all the fields described in <tab> from the JSON
 * object j. */
GError * oio_ext_extract_json (struct json_object *j,
		struct oio_ext_json_mapping_s *tab);

/** Set a thread-local variable with a copy of the given request id. */
void oio_ext_set_reqid (const char *reqid);

/** Calls oio_ext_set_reqid() with a randomly generated string */
void oio_ext_set_random_reqid (void);

/** Get a request-id stored in the thread-local, or NULL if not set */
const char * oio_ext_get_reqid (void);

#ifdef __cplusplus
}
#endif
#endif /*OIO_SDS__core__oioext_h*/
