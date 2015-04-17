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

#ifndef OIO_SDS__metautils__lib__hc_url_h
# define OIO_SDS__metautils__lib__hc_url_h 1

/**
 * @defgroup client_url
 * @ingroup client
 */

enum hc_url_field_e
{
	HCURL_NS=1,
	HCURL_NSPHYS,
	HCURL_NSVIRT,
	HCURL_REFERENCE,
	HCURL_PATH,
	HCURL_OPTIONS,
	HCURL_VERSION,
	HCURL_SNAPSHOT,

	HCURL_WHOLE,
	HCURL_HEXID,
	HCURL_SNAPORVERS, /**< Snapshot or version */
};

#define HCURL_LATEST_VERSION "LAST"

struct hc_url_s;

/** Calls hc_url_empty() then parse the given string. */
struct hc_url_s * hc_url_init(const char *url);

/** Builds an empty URL */
struct hc_url_s * hc_url_empty(void);

struct hc_url_s* hc_url_dup(struct hc_url_s *u);

void hc_url_clean(struct hc_url_s *u);

static inline void
hc_url_pclean(struct hc_url_s **pu)
{
	if (!pu)
		return;
	hc_url_clean(*pu);
	pu = NULL;
}

struct hc_url_s* hc_url_set(struct hc_url_s *u,
		enum hc_url_field_e f, const char *v);

const char * hc_url_get(struct hc_url_s *u, enum hc_url_field_e f);

int hc_url_has(struct hc_url_s *u, enum hc_url_field_e f);

const guint8* hc_url_get_id(struct hc_url_s *u);

/** Returns the value of the given option. */
const gchar* hc_url_get_option_value(struct hc_url_s *u,
		const gchar *option_name);

/** Return the names of all the options registered. Free the result
 * with g_strfreev(). 'u' cannot be NULL. */
gchar ** hc_url_get_option_names(struct hc_url_s *u);

/** Sets a new options in the URL. 'u' and 'k' cannot be NULL. If 'v' is
 * NULL then an empty string will be saved. */
void hc_url_set_option (struct hc_url_s *u,  const gchar *k, const gchar *v);

size_t hc_url_get_id_size(struct hc_url_s *u);

/** @} */

#endif /*OIO_SDS__metautils__lib__hc_url_h*/
