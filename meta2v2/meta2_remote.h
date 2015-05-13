/*
OpenIO SDS meta2
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

#ifndef OIO_SDS__meta2__remote__meta2_remote_h
# define OIO_SDS__meta2__remote__meta2_remote_h 1

/**
 * @defgroup meta2_remote Remote
 * @ingroup meta2
 * @{
 */

#include <metautils/lib/metatypes.h>
#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <glib.h>

#define REMOTECONTAINER_FLAG_OK       0x00000000
#define REMOTECONTAINER_FLAG_FROZEN   0x00000001
#define REMOTECONTAINER_FLAG_DISABLED 0x00000002

#define META2TOUCH_FLAGS_UPDATECSIZE     0x00000001
#define META2TOUCH_FLAGS_RECALCCSIZE     0x00000002

#define NAME_HEADER_METADATA_USR "METADATA_USR"
#define NAME_HEADER_METADATA_SYS "METADATA_SYS"
#define NAME_HEADER_NAMESPACE "NS"
#define NAME_HEADER_CONFIGURATION "CFG"
#define NAME_HEADER_CONTAINERNAME "CONTAINER_NAME"
#define NAME_HEADER_VIRTUALNAMESPACE "VIRTUAL_NAMESPACE"
#define NAME_HEADER_ADMIN_KEY "ADMIN_KEY"
#define NAME_HEADER_ADMIN_VALUE "ADMIN_VALUE"
#define NAME_HEADER_ADMIN_VALUE_SIZE "ADMIN_VALUE_SIZE"
#define NAME_HEADER_CHECKFLAGS "CHECK_FLAGS"
#define NAME_HEADER_STORAGEPOLICY "STORAGE_POLICY"
#define NAME_HEADER_VERSIONPOLICY "VERSION_POLICY"

/** Get the list of contents of ths container. */
GSList *meta2_remote_container_list (const addr_info_t *m2, gint ms, GError **err,
		struct hc_url_s *url);

/** Creates a container on the distant META2 server with an explicit storage policy. */
gboolean meta2_remote_container_create_v3 (const addr_info_t *m2, gint ms, GError **err,
		struct hc_url_s *url, const char *stgpol);

/** Add a new content in the container (identified by the container ID) on the
 * distant META2 server. A NULL return well indicates an error, because even
 * the empty contents contains at least one chunk whom size is zero. */
GSList *meta2_remote_content_add(const addr_info_t *m2, gint ms, GError **err,
    struct hc_url_s *url, content_length_t content_length,
    GByteArray * metadata, GByteArray ** new_metadata);

/** Returns all the information about the content with the given path in the
 * given container. This content must be available. The returned structure is
 * the same as those returned by meta2raw_remote_get_chunks() on an available
 * content.  */
struct meta2_raw_content_s *meta2_remote_stat_content(struct metacnx_ctx_s *cnx,
		GError **error, struct hc_url_s *url);

/* ------------------------------------------------------------------------- */

GSList* meta2_remote_content_add_in_fd (int *fd, gint ms, GError **err,
		struct hc_url_s *url, content_length_t content_length,
		GByteArray *metadata, GByteArray **new_metadata);

/** @see meta2_remote_content_add() */
GSList* meta2_remote_content_spare_in_fd_full (int *fd, gint ms, GError **err, struct hc_url_s *url,
		gint count, gint distance, const gchar *notin, const gchar *broken);

/* ------------------------------------------------------------------------- */

gboolean meta2raw_remote_update_chunks(struct metacnx_ctx_s *ctx, GError **err,
		struct hc_url_s *url, struct meta2_raw_content_s *content,
		gboolean allow_update, char *position_prefix);

gboolean meta2raw_remote_update_content(struct metacnx_ctx_s *ctx, GError **err,
		struct hc_url_s *url, struct meta2_raw_content_s *content,
		gboolean allow_update);

gboolean meta2raw_remote_delete_chunks(struct metacnx_ctx_s *ctx, GError **err,
		struct hc_url_s *url, struct meta2_raw_content_s *content);

struct meta2_raw_content_s *meta2raw_remote_get_content_from_name(
		struct metacnx_ctx_s *ctx, GError **err, struct hc_url_s *url);

gboolean meta2_remote_touch_content(struct metacnx_ctx_s *ctx, GError **err, struct hc_url_s *url);

gboolean meta2_remote_touch_container_ex(struct metacnx_ctx_s *ctx, GError **err,
		struct hc_url_s *url, unsigned int flags);

/* Code got from auto-generation
 * FIXME function to be removed ASAP, as soon as the caller disappears */
gboolean meta2_remote_stat_content_v2(struct metacnx_ctx_s *ctx, GError **err,
		struct hc_url_s *url, meta2_raw_content_v2_t* *var_2);

/* Code got from auto-generation
 * FIXME function to be removed ASAP, as soon as the caller disappears */
gboolean meta2_remote_modify_metadatasys(struct metacnx_ctx_s *ctx, GError **err,
		struct hc_url_s *url, const gchar* var_2);

/** @} */

#endif /*OIO_SDS__meta2__remote__meta2_remote_h*/
