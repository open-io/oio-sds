/*
OpenIO SDS client
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

#ifndef OIO_SDS__sdk__oio_sds_h
#define OIO_SDS__sdk__oio_sds_h 1

struct oio_sds_s;
struct oio_error_s;
struct hc_url_s;
enum oio_sds_config_e
{
	OIOSDS_CFG_TIMEOUT_PROXY = 1,
	OIOSDS_CFG_TIMEOUT_RAWX,
	OIOSDS_CFG_FLAG_SYNCATDOWNLOAD
};

/* error management */
void oio_error_free (struct oio_error_s *e);
void oio_error_pfree (struct oio_error_s **pe);
int oio_error_code (const struct oio_error_s *e);
const char * oio_error_message (const struct oio_error_s *e);

/* client management */
struct oio_error_s * oio_sds_init (struct oio_sds_s **out, const char *ns);
void oio_sds_free (struct oio_sds_s *sds);
void oio_sds_pfree (struct oio_sds_s **psds);
/* return 0 on success, or errno in case of error */
int oio_sds_configure (struct oio_sds_s *sds, enum oio_sds_config_e what,
		void *pv, unsigned int vlen);

/* works with fully qualified urls (content) and local paths */
struct oio_error_s* oio_sds_download_to_file (struct oio_sds_s *sds,
		struct hc_url_s *u, const char *local);

/* works with fully qualified urls (content) and local paths */
struct oio_error_s* oio_sds_upload_from_file (struct oio_sds_s *sds,
		struct hc_url_s *u, const char *local);

/* works with fully qualified urls (content) */
struct oio_error_s* oio_sds_delete (struct oio_sds_s *sds,
		struct hc_url_s *u);

/* currently works with fully qualified urls (content) */
struct oio_error_s* oio_sds_has (struct oio_sds_s *sds,
		struct hc_url_s *url, int *phas);

#endif /*OIO_SDS__sdk__oio_sds_h*/
