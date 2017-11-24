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

#ifndef OIO_SDS__sdk__oio_sds_h
#define OIO_SDS__sdk__oio_sds_h 1

/**
 * @addtogroup oio-api-c
 * @{
 */

#include <stdlib.h>
#include <core/oiourl.h>

/** Version started to be defined in June, 2016. Version prior to 20160600
 * have no ABI incompatibilities. */
#define OIO_SDS_VERSION 20170301

#ifdef __cplusplus
extern "C" {
#endif

struct oio_sds_s;
struct oio_error_s;

/**
 * Define configuration directives for oio_sds_configure().
 */
enum oio_sds_config_e
{
	/** expects an integer as a number of seconds */
	OIOSDS_CFG_TIMEOUT_PROXY = 1,

	/** expects an integer as a number of seconds */
	OIOSDS_CFG_TIMEOUT_RAWX,

	/** expects an integer used for its boolean value */
	OIOSDS_CFG_FLAG_SYNCATDOWNLOAD,

	/** expects an integer used for its boolean value */
	OIOSDS_CFG_FLAG_ADMIN,

	/** Disable the shuffling of chunks before reading,
	 * and instead sort them by score.
	 * Expects an integer used for its boolean value. */
	OIOSDS_CFG_FLAG_NO_SHUFFLE,
};

/**
 * Define a value to be reported by oio_sds_show_content(), via the
 * oio_sds_info_reporter_f hook.
 */
enum oio_sds_content_key_e
{
	/** Indicate the value reports the hexadecimal content ID. */
	OIO_SDS_CONTENT_ID = 1,

	/** the value reports the version number in a textual decimal
	 * representation */
	OIO_SDS_CONTENT_VERSION = 2,

	/** The value represents the hexadecimal hash of the whole content. */
	OIO_SDS_CONTENT_HASH = 3,

	/** Reports the size of the content, as an integer in a decimal
	 * representation. Requires to manage 64bits-wide integers. */
	OIO_SDS_CONTENT_SIZE = 4,

	/** Reports the textual chunk-method that generated the chunks. */
	OIO_SDS_CONTENT_CHUNKMETHOD = 5,
};

/** How properties are reported with oio_sds_show_content()
 * @param key the name of the property
 * @param value its value ... suprising isn't it? */
typedef void (*oio_sds_info_reporter_f) (void *cb_data,
		enum oio_sds_content_key_e key, const char *value);

/** How properties are reported.
 * @param key the name of the property
 * @param value its value ... suprising isn't it? */
typedef void (*oio_sds_property_reporter_f) (void *cb_data,
		const char *key, const char *value);

/**
 * How hints on the internal chunking are reported.
 * @param seq the sequence number
 * @param offset the offset of the metachunk in the whole content
 * @param length the size of the metachunk
 */
typedef void (*oio_sds_metachunk_reporter_f) (void *cb_data,
		unsigned int seq, size_t offset, size_t length);



/* API-global --------------------------------------------------------------- */

/* OpenIO SDK internally relies on GLib-2.0 logging features,
 * so this only sets a callback into GLib's system. The calling app
 * keeps the freedom to change this. */

/**
 * Should the call to oio_sds_upload() (and its family) try to autocreate
 * the container.
 */
extern volatile int oio_sds_default_autocreate;


/**
 * Configures the GLib-2.0 to send the logging output to the syslog. This
 * function does not call openlog()
 */
void oio_log_to_syslog (void);

/**
 * Configures the GLib-2.0 to send the logging output to the standard error
 * output.
 *
 * The format follow an internal rules of OpeIO. If the walling app
 * wants to another format, it is its responsibility.
 */
void oio_log_to_stderr (void);

/**
 * As the name suggests, it turns off the log output from the OpenIO's SDK
 */
void oio_log_nothing (void);

/**
 * Increases the verbosity of the internal logging output.
 * OpenIO's log levels are ERROR, WARNING, NOTICE, INFO, DEBUG, TRACE.
 * The default level is WARNING.
 * DEBUG: output the SDK behavior.
 * TRACE: also outputs the licurl behavior.
 */
void oio_log_more (void);

#ifdef OIO_SDS_VERSION
/** Returns the integer version of the API. Compare the version returned to the
 * version you know from the OIO_SDS_VERSION macro. If it differs, the only
 * behavior to have is upgrading your header AND your library to the same
 * level. */
unsigned int oio_sds_version (void);
#endif /* defined OIO_SDS_VERSION */


/* Error management --------------------------------------------------------- */

/**
 * Free an error pointed by the given argument.
 * @param e May be NULL
 */
void oio_error_free (struct oio_error_s *e);

/**
 * Free the error whose pointer is pointed by pe
 * @param pe May be NULL or point to NULL
 */
void oio_error_pfree (struct oio_error_s **pe);

/**
 * Return an error code associated with the error structure.
 * @param e May be NULL
 * @return 0 is e is NULL, an integer otherwise
 */
int oio_error_code (const struct oio_error_s *e);

/**
 * Returns a human-readable message describing the error.
 * @param e May be NULL
 * @return a pointer to a constant string
 */
const char * oio_error_message (const struct oio_error_s *e);



/* Client-related features -------------------------------------------------- */

/**
 * Prepare an OpenIO SDS client.
 *
 * @param out A placeholder for the 
 * @param ns
 * @return NULL if an error occured, or a pointer to a valid OpenIO SDS client.
 */
struct oio_error_s * oio_sds_init (struct oio_sds_s **out, const char *ns);

/* destructor */
void oio_sds_free (struct oio_sds_s *sds);

/** Calls oio_sds_free() on *psds, then set it to NULL */
void oio_sds_pfree (struct oio_sds_s **psds);

/** return 0 on success, or errno in case of error */
int oio_sds_configure (struct oio_sds_s *sds, enum oio_sds_config_e what,
		void *pv, unsigned int vlen);



/* Create / destroy --------------------------------------------------------- */

/** Links the meta2 then triggers container creation */
struct oio_error_s* oio_sds_create (struct oio_sds_s *sds,
		struct oio_url_s *url);

struct oio_error_s* oio_sds_delete_container(struct oio_sds_s *sds,
		struct oio_url_s *url);



/* Download ----------------------------------------------------------------- */

/** Expected to return the number of bytes read, and something
 * else when it failed. */
typedef int (*oio_sds_dl_hook_f) (void*, const unsigned char*, size_t);

enum oio_sds_dl_dst_type_e
{
	OIO_DL_DST_HOOK_SEQUENTIAL = 1,
	OIO_DL_DST_BUFFER,
	OIO_DL_DST_FILE,
};

struct oio_sds_dl_dst_s
{
	/* output variable: how many bytes have been read, at all */
	size_t out_size;

	enum oio_sds_dl_dst_type_e type;

	union {
		struct {
			const char *path;
		} file;
		struct {
			unsigned char *ptr;
			size_t length;
		} buffer;
		struct {
			oio_sds_dl_hook_f cb;
			void *ctx;

			/* set 'length' to ((size_t)-1) to mark it unset and allow the
			 * whole content to be downloaded. If set, it must be coherent
			 * with the ranges provided. */
			size_t length;
		} hook;
	} data;
};

struct oio_sds_dl_range_s
{
	size_t offset;
	size_t size;
};

struct oio_sds_dl_src_s
{
	struct oio_url_s *url;

	/** if not set, the whole content will be read at once.
	 * To be set, it must contain a pointer to a NULL-terminated array
	 * of pointers to ranges. */
	struct oio_sds_dl_range_s **ranges;
};

struct oio_error_s* oio_sds_download (struct oio_sds_s *sds,
		struct oio_sds_dl_src_s *src, struct oio_sds_dl_dst_s *dst);

/**
 * Downloads the whole file
 * works with fully qualified urls (content) and local paths
 */
struct oio_error_s* oio_sds_download_to_file (struct oio_sds_s *sds,
		struct oio_url_s *u, const char *local);

/**
 * Tells how is the content internally split.
 *
 * Helps applications to paginate the downloads, with pages aligned on chunks
 * boundaries.
 * @param cb_data not even checked, implementation-dependant
 * @param cb_info ignored if NULL
 * @param cb_metachunks ignored if NULL
 * @param cb_props ignored if NULL
 */
struct oio_error_s* oio_sds_show_content (struct oio_sds_s *sds,
		struct oio_url_s *u, void *cb_data,
		oio_sds_info_reporter_f cb_info,
		oio_sds_metachunk_reporter_f cb_metachunks,
		oio_sds_property_reporter_f cb_props);



/* Upload ------------------------------------------------------------------- */

struct oio_sds_ul_dst_s
{
	struct oio_url_s *url;

	/* Should the container be autocreated */
	unsigned int autocreate : 1;

	/* Should the data be appended to the content in place. When set to 1,
	 * `content_id` and `meta_pos` must be set. */
	unsigned int append : 1;

	/* Do a partial upload. When set to 1, `content_id` and `meta_pos` are
	 * mandatory. */
	unsigned int partial : 1;

	/* output variable: how many bytes have been uploaded */
	size_t out_size;

	/* The unique content name.
	 * Optional when both `partial` and `append` are set to 0.
	 * When set, it MUST be an hexadecimal string (with an even number of
	 * characters). */
	const char *content_id;

	/* NULL-terminated array of property keys and values.
	 * Set to NULL when you have no property to set upon the upload. */
	const char * const * properties;

	/* Position of the first metachunk that is to be modified */
	int meta_pos;

	/* Offset of the first byte of the metachunk, relative to the
	 * beginning of the content, used to check write alignment. */
	size_t offset;
};

#define OIO_SDS_UPLOAD_DST_INIT {NULL, 0, 0, 0, 0, NULL, NULL, 0, 0}

/** "Female" upload API
 * The sequence is managed by the caller: an upload context has to be
 * initiated, then fed with some data, told to progress, then closed. */

struct oio_sds_ul_s;

struct oio_sds_ul_s * oio_sds_upload_init (struct oio_sds_s *sds,
		struct oio_sds_ul_dst_s *dst);

struct oio_error_s * oio_sds_upload_prepare (struct oio_sds_ul_s *ul,
	size_t size);

struct oio_error_s * oio_sds_upload_feed (struct oio_sds_ul_s *ul,
		const unsigned char *buf, size_t len);

struct oio_error_s * oio_sds_upload_step (struct oio_sds_ul_s *ul);

struct oio_error_s * oio_sds_upload_commit (struct oio_sds_ul_s *ul);

struct oio_error_s * oio_sds_upload_abort (struct oio_sds_ul_s *ul);

/** Tells if the upload is ready to accept data */
int oio_sds_upload_greedy (struct oio_sds_ul_s *ul);

/** Tells if the upload is ready to be (in)validated */
int oio_sds_upload_done (struct oio_sds_ul_s *ul);

/** Tells if the upload will need a data-daemon aside.
 * TODO rename to be more generic (not only EC requires side daemon) */
int oio_sds_upload_needs_ecd(struct oio_sds_ul_s *ul);

void oio_sds_upload_clean (struct oio_sds_ul_s *ul);

/** "Male" upload API
 * This API wraps the "female" API. The sequence is managed by the underlying
 * API call, you just have to provide some data. When the data is called,
 * it has to be available. */

#define OIO_SDS_UL__ERROR  ((size_t)-2)
#define OIO_SDS_UL__DONE   ((size_t)-1)
#define OIO_SDS_UL__NODATA ((size_t)0)

typedef size_t (*oio_sds_ul_hook_f) (void*, unsigned char *p, size_t s);

enum oio_sds_ul_src_type_e
{
	OIO_UL_SRC_HOOK_SEQUENTIAL = 1,
	/*OIO_UL_SRC_HOOK_RANDOM, */ /* coming soon */
};

struct oio_sds_ul_src_s
{
	enum oio_sds_ul_src_type_e type;

	union {
		struct {
			oio_sds_ul_hook_f cb;
			void *ctx;
			size_t size;
		} hook;
	} data;
};

#define OIO_SDS_UPLOAD_SRC_INIT {.type=0, .data={ .hook={.cb=NULL, .ctx=NULL, .size=0}}}

/* works with fully qualified urls (content) and local paths */
struct oio_error_s* oio_sds_upload (struct oio_sds_s *sds,
		struct oio_sds_ul_src_s *src, struct oio_sds_ul_dst_s *dst);

/** Simply wraps oio_sds_upload() without the autocreation flag
 * set. */
struct oio_error_s* oio_sds_upload_from_file (struct oio_sds_s *sds,
		struct oio_sds_ul_dst_s *dst, const char *local,
		size_t off, size_t len);

/** Simply wraps oio_sds_upload() without the autocreation flag
 * set. */
struct oio_error_s* oio_sds_upload_from_buffer (struct oio_sds_s *sds,
		struct oio_sds_ul_dst_s *dst, void *base, size_t len);



/* List --------------------------------------------------------------------- */

struct oio_sds_list_param_s
{
	struct oio_url_s *url;
	const char *prefix;
	const char *marker;
	const char *end;

	/* 0 means not set */
	size_t max_items;

	/* 0 means no set */
	char delimiter;

	unsigned char flag_nodeleted : 1;
	unsigned char flag_allversions : 1;
	unsigned char flag_properties : 1;
};

struct oio_sds_list_item_s
{
	const char *name;
	const char *hash;
	size_t size;
	size_t version;
	/** NULL-terminated array of property keys and values */
	const char * const *properties;
};

struct oio_sds_list_listener_s
{
	/** An arbitraty pointer that will be passed as-is to all the hooks
	 * producing an output for this listing. */
	void *ctx;

	/** called for each item listed */
	int (*on_item) (void *ctx, const struct oio_sds_list_item_s *item);

	/** called for each sub-prefix detected (depends on the delimiter) */
	int (*on_prefix) (void *ctx, const char *prefix);

	/** called once, with no warranty to be called before 'on_item' nor
	 * 'on_bound' */
	int (*on_bound) (void *ctx, const char *next_marker);

	/** How many items have been returned, eventually */
	size_t out_count;

	/** Has the list been truncated. If so, a subsequent call to list with
	 * the appropriate marker shoudl be issued for a full list. */
	int out_truncated;
};

/**
 * List the object present in the container.
 *
 * @param sds
 * @param param
 * @param listener
 * @return
 */
struct oio_error_s* oio_sds_list (struct oio_sds_s *sds,
		struct oio_sds_list_param_s *param,
		struct oio_sds_list_listener_s *listener);

/* Quota -------------------------------------------------------------------- */

/**
 * Report the usage of a container.
 */
struct oio_sds_usage_s
{
	/** The number of bytes used for the storage */
	size_t used_bytes;

	/** The maximum number of  */
	size_t quota_bytes;

	/** The number of objects present in the container. */
	int used_objects;
};

/**
 * Report the usage of the container identified by the oio_url_s `u`.
 *
 * @param sds A pointer to a valid oio_sds_s.
 * @param u A pointer to a valid oio_url_s.
 * @param out output variable, filled with the stats upon success.
 * @return NULL if the requests succeeds, or an oio_error_s pointer otherwise,
 *         to be freed with oio_error_free().
 */
struct oio_error_s* oio_sds_get_usage (struct oio_sds_s *sds,
		struct oio_url_s *u, struct oio_sds_usage_s *out);



/* Misc. -------------------------------------------------------------------- */

/**
 * Drain the content identified by `u`, a.k.a. make it remain in the directory
 * but not point to valid contents.
 *
 * @param sds a pointer to a valid sds client.
 * @param u a pointer to a valid oio_url_s identifying the content.
 * @return NULL in case of success, a valid error pointer otherwise
 */
struct oio_error_s* oio_sds_drain(struct oio_sds_s *sds, struct  oio_url_s *u);

/**
 * Works with fully qualified urls (content)
 */
struct oio_error_s* oio_sds_delete (struct oio_sds_s *sds, struct oio_url_s *u);

/** currently works with fully qualified urls (content) */
struct oio_error_s* oio_sds_has (struct oio_sds_s *sds, struct oio_url_s *url,
		int *phas);


typedef void (*on_element_f) (void *ctx, const char *key, const char *value);

/** Get properties of a file: fct function will be called for each k,v couple */
struct oio_error_s* oio_sds_get_content_properties (struct oio_sds_s *sds,
		struct oio_url_s *url, on_element_f fct, void* ctx);

/** Set properties of a file with the val values */
struct oio_error_s* oio_sds_set_content_properties(struct oio_sds_s *sds,
		struct oio_url_s *url, const char * const *val);

/** Get properties of a container: fct function will be called for each k,v couple */
struct oio_error_s* oio_sds_get_container_properties (struct oio_sds_s *sds,
		struct oio_url_s *url, on_element_f fct, void* ctx);

/** Set properties of a file with the val values */
struct oio_error_s* oio_sds_set_container_properties(struct oio_sds_s *sds,
		struct oio_url_s *url, const char * const *val);

/** Creates an alias named 'url' pointing on the physical content 'content_id'
 * in the same container.
 *  'url' be a fully qualified content URI.
 *  'content_id' must be an hexadecimal string. */
struct oio_error_s* oio_sds_link (struct oio_sds_s *sds, struct oio_url_s *url,
		const char *content_id);

/**
 * Attempts a link with oio_sds_link(), then calls oio_sds_upload_from_source()
 * in case of error, if the link failed because of a content not found.
 * The underlying call to oio_sds_link() requires the 'content_id' field of
 * 'dst' to be set to a non-NULL value. */
struct oio_error_s* oio_sds_link_or_upload (struct oio_sds_s *sds,
		struct oio_sds_ul_src_s *src, struct oio_sds_ul_dst_s *dst);

/**
 * Truncate a content to the specified size.
 *
 * The size must be aligned on a metachunk boundary (you can use
 * oio_sds_show_content() to find it).
 * It is preferable to specify the content by its ID instead of its path. */
struct oio_error_s* oio_sds_truncate(struct oio_sds_s *sds,
		struct oio_url_s *u, size_t size);

#ifdef __cplusplus
}
#endif

/** @} */
#endif /*OIO_SDS__sdk__oio_sds_h*/
