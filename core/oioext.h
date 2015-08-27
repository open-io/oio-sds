/*
OpenIO SDS oio core 
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
# include <glib.h>

/** Shuffles the single linked list. The original <src> MUST NOT be reused. */
GSList * oio_ext_gslist_shuffle(GSList *src);

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
void oio_local_set_reqid (const char *reqid);

/** Calls oio_local_set_reqid() with a randomly generated string */
void oio_local_set_random_reqid (void);

/** Get a request-id stored in the thread-local, or NULL if not set */
const char * oio_local_get_reqid (void);

void oio_local_set_value (const char *k, const char *v);
const char* oio_local_get_value (const char *k);

#endif /*OIO_SDS__core__oioext_h*/
