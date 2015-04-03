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

/*
 * ---------------------------
 *   Raw requests management
 * ---------------------------
 */

#define NAME_MSGNAME_M2_CREATE  "REQ_M2_CREATE"
#define NAME_MSGNAME_M2_DESTROY "REQ_M2_DESTROY"
#define NAME_MSGNAME_M2_LIST    "REQ_M2_LIST"
#define NAME_MSGNAME_M2_SETFLAG "REQ_M2_SETFLAG"
#define NAME_MSGNAME_M2_CONTENTSPARE    "REQ_M2_CONTENTSPARE"
#define NAME_MSGNAME_M2_CONTENTADD      "REQ_M2_CONTENTADD"
#define NAME_MSGNAME_M2_CONTENTREMOVE   "REQ_M2_CONTENTREMOVE"
#define NAME_MSGNAME_M2_CONTENTRETRIEVE "REQ_M2_CONTENTRETRIEVE"
#define NAME_MSGNAME_M2_CONTENTCOMMIT   "REQ_M2_CONTENTCOMMIT"
#define NAME_MSGNAME_M2_CONTENTROLLBACK "REQ_M2_CONTENTROLLBACK"
#define NAME_MSGNAME_M2_CONTENTAPPEND   "REQ_M2_CONTENTAPPEND"

#define NAME_MSGNAME_M2_CHUNK_COMMIT   "REQ_M2_CHUNK_COMMIT"

#define REMOTECONTAINER_FLAG_OK       0x00000000
#define REMOTECONTAINER_FLAG_FROZEN   0x00000001
#define REMOTECONTAINER_FLAG_DISABLED 0x00000002

#define META2TOUCH_FLAGS_UPDATECSIZE     0x00000001
#define META2TOUCH_FLAGS_RECALCCSIZE     0x00000002

#define NAME_MSGNAME_M2RAW_GETCONTENTS "REQ_M2RAW_CONTENT_GETALL"
#define NAME_MSGNAME_M2RAW_GETCONTENTBYPATH  "REQ_M2RAW_CONTENT_GETBYPATH"
#define NAME_MSGNAME_M2RAW_GETCONTENTBYCHUNK "REQ_M2RAW_CONTENT_GETBYCHUNK"
#define NAME_MSGNAME_M2RAW_SETCONTENT  "REQ_M2RAW_CONTENT_SET"
#define NAME_MSGNAME_M2RAW_DELCONTENT  "REQ_M2RAW_CONTENT_DEL"
#define NAME_MSGNAME_M2RAW_GETCHUNKS   "REQ_M2RAW_CHUNKS_GET"
#define NAME_MSGNAME_M2RAW_SETCHUNKS   "REQ_M2RAW_CHUNKS_SET"
#define NAME_MSGNAME_M2RAW_DELCHUNKS   "REQ_M2RAW_CHUNKS_DEL"
#define NAME_MSGNAME_M2RAW_MARK_REPAIRED  "REQ_M2RAW_MARK_REPAIRED"

#define NAME_MSGNAME_M2ADMIN_GETALL "REQ_M2RAW_ADMIN_GETALL"
#define NAME_MSGNAME_M2ADMIN_SETONE "REQ_M2RAW_ADMIN_SETONE"

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

GSList *meta2_remote_content_append_v2(struct metacnx_ctx_s *ctx, GError ** err,
		gchar *virtual_namespace, const container_id_t container_id, const gchar * content_path, content_length_t content_length);

/** Get the list of contents of ths container. */
GSList *meta2_remote_container_list(addr_info_t * m2_addr, gint ms, GError ** err, const container_id_t container_id);

/** Creates a container on the distant META2 server. */
gboolean meta2_remote_container_create(addr_info_t * m2_addr, gint ms, GError ** err, const container_id_t container_id,
		const gchar * name);

gboolean meta2_remote_container_create_v2(addr_info_t * m2_addr, gint ms, GError ** err, const container_id_t container_id,
		const gchar * name, const gchar * virtual_namespace);

gboolean meta2_remote_container_create_v3 (const addr_info_t *m2, gint ms, const char *ns, const char *cname,
		const container_id_t cid, const char *stgpol, GError **e);

/** Destroys the container with the given ID on the remote container */
gboolean meta2_remote_container_destroy(addr_info_t * m2_addr, gint ms, GError ** err, const container_id_t container_id);

/** Add a new content in the container (identified by the container ID) on the
 * distant META2 server. A NULL return well indicates an error, because even
 * the empty contents contains at least one chunk whom size is zero. */
GSList *meta2_remote_content_add(addr_info_t * m2_addr, gint ms, GError ** err,
    const container_id_t container_id, const gchar * content_path, content_length_t content_length,
    GByteArray * system_metadata, GByteArray ** new_system_metadata);

/** Mark for removal the give content from the given container, on the
 * targeted META2 server. Currently, there is no management of META2
 * replications in the removal operations. After this step a COMMIT or
 * a ROLLBACK on the content is necessary. Before this step, the content
 * won't be accessible. */
gboolean meta2_remote_content_remove(addr_info_t * m2_addr, gint ms, GError ** err, const container_id_t container_id,
    const gchar * content_path);

/** Commit (approve) the last operation on the given content in the given container. */
gboolean meta2_remote_content_commit(addr_info_t * m2_addr, gint ms, GError ** err, const container_id_t container_id,
    const gchar * content_path);

/** Rollback on the last operation performed on the given content in the
 * given container. */
gboolean meta2_remote_content_rollback(addr_info_t * m2_addr, gint ms, GError ** err, const container_id_t container_id,
    const gchar * content_path);

/** Get the chunks locations of the given content in the givan container.
 * To be successful, the retrieval must target an opened container and
 * an online content. */
GSList *meta2_remote_content_retrieve(addr_info_t * m2_addr, gint ms, GError ** err, const container_id_t container_id,
    const gchar * content_path);

/** Returns all the information about the content with the given path in the
 * given container. This content must be available. The returned structure is
 * the same as those returned by meta2raw_remote_get_chunks() on an available
 * content.  */
struct meta2_raw_content_s *meta2_remote_stat_content(struct metacnx_ctx_s *cnx,
	const container_id_t cid, const gchar *path, gsize path_len, GError **error);

/* ------------------------------------------------------------------------- */

/** @see meta2_remote_content_add() */
GSList *meta2_remote_content_add_in_fd(int *fd, gint ms, GError ** err,
		const container_id_t container_id, const gchar * content_path,
		content_length_t content_length, GByteArray * system_metadata,
		GByteArray ** new_system_metadata);

/** @see meta2_remote_content_add() */
GSList *meta2_remote_content_add_in_fd_v2(int *fd, gint ms, GError ** err,
		const container_id_t container_id, const gchar * content_path,
		content_length_t content_length, GByteArray *user_metadata,
		GByteArray * system_metadata, GByteArray ** new_system_metadata);

/** @see meta2_remote_content_add() */
GSList* meta2_remote_content_spare_in_fd_full (int *fd, gint ms, GError **err,
		const container_id_t container_id, const gchar *content_path,
		gint count, gint distance, const gchar *notin, const gchar *broken);

/** @see meta2_remote_content_rollback() */
gboolean meta2_remote_content_rollback_in_fd(int *fd, gint ms, GError ** err,
		const container_id_t container_id, const gchar * content_path);

GSList *meta2_remote_content_append_in_fd_v2(int *fd, gint ms, GError ** err,
		const container_id_t container_id, const gchar * content_path,
		content_length_t content_length, GByteArray **sys_metadata);

/* ------------------------------------------------------------------------- */

GSList *meta2_remote_content_append(struct metacnx_ctx_s *ctx, GError ** err,
		const container_id_t container_id, const gchar * content_path,
		content_length_t content_length);

gboolean meta2raw_remote_update_chunks(struct metacnx_ctx_s *ctx, GError ** err,
		struct meta2_raw_content_s *content, gboolean allow_update,
		char *position_prefix);

gboolean meta2raw_remote_update_content(struct metacnx_ctx_s *ctx, GError ** err,
		struct meta2_raw_content_s *content, gboolean allow_update);

gboolean meta2raw_remote_delete_chunks(struct metacnx_ctx_s *ctx, GError ** err,
		struct meta2_raw_content_s *content);

struct meta2_raw_content_s *meta2raw_remote_get_content_from_name(
		struct metacnx_ctx_s *ctx, GError ** err,
		const container_id_t container_id, const gchar * path, gsize path_len);

/** Get the contents elements including its chunks, nevermind its availability. */
struct meta2_raw_content_s *meta2raw_remote_get_chunks(struct metacnx_ctx_s *ctx, GError ** err,
    const container_id_t container_id, const char *path, gsize path_len);

/** Returns a list of contents names known in the given container,  nevermind
 * their availability. */
GSList *meta2raw_remote_get_contents_names(struct metacnx_ctx_s *ctx, GError ** error,
    const container_id_t container_id);

status_t meta2_remote_touch_content(struct metacnx_ctx_s *ctx,
		const container_id_t var_0, const gchar* var_1, GError **err);

status_t meta2_remote_touch_container_ex(struct metacnx_ctx_s *ctx,
		const container_id_t var_0, unsigned int flags, GError **err);

/** @} */

#endif /*OIO_SDS__meta2__remote__meta2_remote_h*/
