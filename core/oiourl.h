/*
OpenIO SDS core library
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

#ifndef OIO_SDS__core__oiourl_h
# define OIO_SDS__core__oiourl_h 1

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OIOURL_DEFAULT_TYPE    ""

enum oio_url_field_e
{
	OIOURL_NS=1,
	OIOURL_ACCOUNT,
	OIOURL_USER,
	OIOURL_TYPE,
	OIOURL_PATH,

	OIOURL_VERSION,

	OIOURL_WHOLE, /* read-only */

	OIOURL_HEXID,     /* read-write */
	OIOURL_CONTENTID, /* read-write */
};

#define OIOURL_LATEST_VERSION "LAST"

struct oio_url_s;

struct oio_url_s * oio_url_init(const char *url);

/** Builds an empty URL */
struct oio_url_s * oio_url_empty(void);

struct oio_url_s* oio_url_dup(const struct oio_url_s *u);

void oio_url_clean(struct oio_url_s *u);

void oio_url_cleanv (struct oio_url_s **tab);

void oio_url_pclean(struct oio_url_s **pu);

struct oio_url_s* oio_url_set(struct oio_url_s *u,
		enum oio_url_field_e f, const char *v);

const char * oio_url_get(struct oio_url_s *u, enum oio_url_field_e f);

int oio_url_has(const struct oio_url_s *u, enum oio_url_field_e f);

/* <id> must be oio_url_get_id_size() bytes long */
void oio_url_set_id(struct oio_url_s *u, const void *id);

/* the returned value points to an array of oio_url_get_id_size() bytes long. */
const void* oio_url_get_id(struct oio_url_s *u);

/* returns the number of bytes */
size_t oio_url_get_id_size(struct oio_url_s *u);

/** Returns wether all the mandatory components for a path are present */
int oio_url_has_fq_path (const struct oio_url_s *u);

/** Returns wether all the mandatory components for a container are present */
int oio_url_has_fq_container (const struct oio_url_s *u);

#ifdef __cplusplus
}
#endif
#endif /*OIO_SDS__core__oiourl_h*/
