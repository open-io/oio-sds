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

#define REMOTECONTAINER_FLAG_OK       0x00000000
#define REMOTECONTAINER_FLAG_FROZEN   0x00000001
#define REMOTECONTAINER_FLAG_DISABLED 0x00000002

#define META2TOUCH_FLAGS_UPDATECSIZE     0x00000001
#define META2TOUCH_FLAGS_RECALCCSIZE     0x00000002

/** used in client/c/lib */
gboolean meta2_remote_container_create_v3 (const addr_info_t *m2, gint ms, GError **err,
		struct hc_url_s *url, const char *stgpol);

/** used in client/c/lib */
struct meta2_raw_content_s *meta2_remote_stat_content(struct metacnx_ctx_s *cnx,
		GError **error, struct hc_url_s *url);

/** used in client/c/lib */
GSList* meta2_remote_content_add_in_fd (int *fd, gint ms, GError **err,
		struct hc_url_s *url, content_length_t content_length,
		GByteArray *metadata, GByteArray **new_metadata);

/** used in client/c/lib */
GSList* meta2_remote_content_spare_in_fd_full (int *fd, gint ms, GError **err, struct hc_url_s *url,
		gint count, gint distance, const gchar *notin, const gchar *broken);

/** used in client/c/lib for rainx purposes */
gboolean meta2raw_remote_update_chunks(struct metacnx_ctx_s *ctx, GError **err,
		struct hc_url_s *url, struct meta2_raw_content_s *content,
		gboolean allow_update, char *position_prefix);

/** used in client/c/lib for rainx purposes */
gboolean meta2raw_remote_update_content(struct metacnx_ctx_s *ctx, GError **err,
		struct hc_url_s *url, struct meta2_raw_content_s *content,
		gboolean allow_update);

/** used in client/c/lib for rainx purposes */
gboolean meta2raw_remote_delete_chunks(struct metacnx_ctx_s *ctx, GError **err,
		struct hc_url_s *url, struct meta2_raw_content_s *content);

/* used in client/c/lib
 * Code got from auto-generation
 * FIXME function to be removed ASAP, as soon as the caller disappears */
gboolean meta2_remote_modify_metadatasys(struct metacnx_ctx_s *ctx, GError **err,
		struct hc_url_s *url, const gchar* var_2);

/** @} */

#endif /*OIO_SDS__meta2__remote__meta2_remote_h*/
