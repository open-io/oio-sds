/*
OpenIO SDS core library
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#ifndef OIO_SDS__metautils__lib__oio_url_ext_h
# define OIO_SDS__metautils__lib__oio_url_ext_h 1

/**
 * This file provides and API dependent from the GLib, with non essential features.
 * Typically, this file is not destined to be included in external apps using the
 * C SDK.
 */
#include <glib.h>
#include <core/url_internals.h>

void oio_url_to_json (GString *out, struct oio_url_s *u);

struct oio_requri_s
{
	gchar *path;
	gchar *query;
	gchar *fragment;

	gchar **query_tokens;
};

gboolean oio_requri_parse (const char *packed, struct oio_requri_s *ruri);

void oio_requri_clear (struct oio_requri_s *ruri);

/**
 * Compute the ID of the chunk at the specified position for the specified
 * storage policy.
 *
 * @param u the URL
 * @param position the position of the chunk, simple ("1") or composed ("1.1")
 * @param policy the name of the storage policy
 * @param out an output buffer
 * @param outsize size of the output buffer. In case the ID is longer than the
 *                buffer, it will be truncated.
 */
GError *oio_url_compute_chunk_id(struct oio_url_s *u, const char *position,
		const char *policy, char *out, size_t outsize);

#endif /*OIO_SDS__metautils__lib__oio_url_ext_h*/
