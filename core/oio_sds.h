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
struct oio_url_s;

enum oio_sds_config_e
{
	/* expects an <int> as a number of seconds */
	OIOSDS_CFG_TIMEOUT_PROXY = 1,

	/* expects an <int> as a number of seconds */
	OIOSDS_CFG_TIMEOUT_RAWX,

	/* expects an <int> used for its boolean value */
	OIOSDS_CFG_FLAG_SYNCATDOWNLOAD,
};

/* API-global --------------------------------------------------------------- */

extern volatile int oio_sds_default_autocreate;

/* OpenIO SDK internally relies on GLib-2.0 logging features,
 * so this only sets a callback into GLib's system. The calling app
 * keeps the freedom to change this. */

/* Configures the GLib-2.0 to send the logging output to the syslog. This
 * function does not call openlog() */
void oio_log_to_syslog (void);

/* Configures the GLib-2.0 to send the logging output to the standard error
 * output. The format follow an internal rules of OpeIO. If the walling app
 * wants to another format, it is its responsibility. */
void oio_log_to_stderr (void);

/* As the name suggests, it turns of the log output from the OpenIO's SDK */
void oio_log_nothing (void);

/* Increases the verbosity of the internal logging output.
 * OpenIO's log levels are ERROR, WARNING, NOTICE, INFO, DEBUG, TRACE.
 * The default level is WARNING.
 * DEBUG: output the SDK behavior.
 * TRACE: also outputs the licurl behavior. */
void oio_log_more (void);

/** @return a NULL-terminated array of strings where
 * result[(2*i)]   is the name of the i-th configuration directive 
 * result[(2*i)+1] is the value of the i-th configuration directive.
 * The output has to be freed with free().
 */
char ** oio_sds_get_compile_options (void);

/* Error management --------------------------------------------------------- */

void oio_error_free (struct oio_error_s *e);
void oio_error_pfree (struct oio_error_s **pe);
int oio_error_code (const struct oio_error_s *e);
const char * oio_error_message (const struct oio_error_s *e);

/* Client-related features -------------------------------------------------- */

/* constructor */
struct oio_error_s * oio_sds_init (struct oio_sds_s **out, const char *ns);

/* destructor */
void oio_sds_free (struct oio_sds_s *sds);

/* Calls oio_sds_free() on *psds, then set it to NULL */
void oio_sds_pfree (struct oio_sds_s **psds);

/* return 0 on success, or errno in case of error */
int oio_sds_configure (struct oio_sds_s *sds, enum oio_sds_config_e what,
		void *pv, unsigned int vlen);

/* works with fully qualified urls (content) and local paths */
struct oio_error_s* oio_sds_download_to_file (struct oio_sds_s *sds,
		struct oio_url_s *u, const char *local);

/* Simply wraps oio_sds_upload_from_source() without the autocreation flag
 * set. */
struct oio_error_s* oio_sds_upload_from_file (struct oio_sds_s *sds,
		struct oio_url_s *u, const char *local);

struct oio_source_s {
	int autocreate;
	enum {
		OIO_SRC_NONE = 0, /* do not use this */
		OIO_SRC_FILE,
		OIO_SRC_BUFFER,
	} type;
	union {
		const char *path;
		struct {
			const void *data;
			gsize length;
		} buffer;
	} data;
};

/* works with fully qualified urls (content) and local paths */
struct oio_error_s* oio_sds_upload_from_source (struct oio_sds_s *sds,
		struct oio_url_s *u, struct oio_source_s *src);

/* works with fully qualified urls (content) */
struct oio_error_s* oio_sds_delete (struct oio_sds_s *sds,
		struct oio_url_s *u);

/* currently works with fully qualified urls (content) */
struct oio_error_s* oio_sds_has (struct oio_sds_s *sds,
		struct oio_url_s *url, int *phas);

/* Creates an alias pointing on the physical content 'iname' in the container
 * identified by 'url'. If the physical content doesn't exist, a new content
 * will be uploaded.
 *  'url' be a fully qualified content URI.
 *  'iname' must be an hexadecimal string.
 */
struct oio_error_s* oio_sds_link (struct oio_sds_s *sds,
		struct oio_url_s *url, struct oio_source_s *src,
		const char *iname);

#endif /*OIO_SDS__sdk__oio_sds_h*/
