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

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

#define HCURL_DEFAULT_ACCOUNT ""
#define HCURL_DEFAULT_TYPE    ""

#define hc_url_field_e          oio_url_field_e
#define hc_url_s                oio_url_s
#define hc_url_init             oio_url_init
#define hc_url_empty            oio_url_empty
#define hc_url_oldinit          oio_url_oldinit
#define hc_url_dup              oio_url_dup
#define hc_url_clean            oio_url_clean
#define hc_url_cleanv           oio_url_cleanv
#define hc_url_pclean           oio_url_pclean
#define hc_url_has              oio_url_has
#define hc_url_has_fq_path      oio_url_has_fq_path
#define hc_url_has_fq_container oio_url_has_fq_container
#define hc_url_set              oio_url_set
#define hc_url_set_id           oio_url_set_id
#define hc_url_set_option       oio_url_set_option
#define hc_url_set_oldns        oio_url_set_oldns
#define hc_url_get              oio_url_get
#define hc_url_get_id           oio_url_get_id
#define hc_url_get_id_size      oio_url_get_id_size
#define hc_url_get_option_value oio_url_get_option_value

#define HCURL_NS      OIOURL_NS
#define HCURL_ACCOUNT OIOURL_ACCOUNT
#define HCURL_USER    OIOURL_USER
#define HCURL_TYPE    OIOURL_TYPE
#define HCURL_PATH    OIOURL_PATH
#define HCURL_VERSION OIOURL_VERSION
#define HCURL_WHOLE   OIOURL_WHOLE
#define HCURL_HEXID   OIOURL_HEXID

enum oio_url_field_e
{
	OIOURL_NS=1,
	OIOURL_ACCOUNT,
	OIOURL_USER,
	OIOURL_TYPE,
	OIOURL_PATH,

	OIOURL_VERSION,

	OIOURL_WHOLE, /* read-only */
	OIOURL_HEXID, /* read-write */
};

#define HCURL_LATEST_VERSION "LAST"

struct oio_url_s;

/** Calls oio_url_empty() then parse the given string. */
struct oio_url_s * oio_url_oldinit(const char *url);

struct oio_url_s * oio_url_init(const char *url);

/** Builds an empty URL */
struct oio_url_s * oio_url_empty(void);

struct oio_url_s* oio_url_dup(struct oio_url_s *u);

void oio_url_clean(struct oio_url_s *u);

void oio_url_cleanv (struct oio_url_s **tab);

void oio_url_pclean(struct oio_url_s **pu);

struct oio_url_s* oio_url_set(struct oio_url_s *u,
		enum oio_url_field_e f, const char *v);

const char * oio_url_get(struct oio_url_s *u, enum oio_url_field_e f);

int oio_url_has(struct oio_url_s *u, enum oio_url_field_e f);

/* <id> must be oio_url_get_id_size() bytes long */
void oio_url_set_id(struct oio_url_s *u, const void *id);

/* @deprecated */
void oio_url_set_oldns(struct oio_url_s *u, const char *ns);

/* the returned value points to an array of oio_url_get_id_size() bytes long. */
const void* oio_url_get_id(struct oio_url_s *u);

/* returns the number of bytes */
size_t oio_url_get_id_size(struct oio_url_s *u);

/** Returns the value of the given option. */
const char* oio_url_get_option_value(struct oio_url_s *u,
		const char *option_name);

/** Sets a new options in the URL. 'u' and 'k' cannot be NULL. If 'v' is
 * NULL then an empty string will be saved. */
void oio_url_set_option (struct oio_url_s *u,  const char *k, const char *v);

/** Returns wether all the mandatory components for a path are present */
int oio_url_has_fq_path (struct oio_url_s *u);

/** Returns wether all the mandatory components for a container are present */
int oio_url_has_fq_container (struct oio_url_s *u);

#ifdef __cplusplus
}
#endif
#endif /*OIO_SDS__core__oiourl_h*/
