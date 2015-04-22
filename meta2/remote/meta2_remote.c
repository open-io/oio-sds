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

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "meta2.remote"
#endif

#include <metautils/lib/metautils.h>

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "meta2_remote.h"

typedef enum meta2_operation_e
{
	M2_OP_CONTAINER_CREATE,
	M2_OP_CONTAINER_DESTROY,
	M2_OP_CONTAINER_LIST,

	M2_OP_CONTAINER_SETFLAG,
	
	M2_OP_CONTENT_SPARE,
	M2_OP_CONTENT_ADD,
	M2_OP_CONTENT_REMOVE,
	M2_OP_CONTENT_COMMIT,
	M2_OP_CONTENT_ROLLBACK,

	M2_OP_CHUNK_COMMIT,
	M2_OP_CONTENT_APPEND

} meta2_operation_t;

static void
__get_request_name2 (meta2_operation_t mo, gchar **str, gsize *len)
{
#define SETSTR(S) do { *str=S; *len=sizeof(S)-1; } while (0)
	switch (mo)
	{
		case M2_OP_CONTAINER_CREATE:        SETSTR(NAME_MSGNAME_M2_CREATE);         return ;
		case M2_OP_CONTAINER_DESTROY:       SETSTR(NAME_MSGNAME_M2_DESTROY);        return ;
		case M2_OP_CONTAINER_LIST:          SETSTR(NAME_MSGNAME_M2_LIST);           return ;
		case M2_OP_CONTAINER_SETFLAG:       SETSTR(NAME_MSGNAME_M2_SETFLAG);        return ;

		case M2_OP_CONTENT_SPARE:    SETSTR(NAME_MSGNAME_M2_CONTENTSPARE);    return ;
		case M2_OP_CONTENT_ADD:      SETSTR(NAME_MSGNAME_M2_CONTENTADD);      return ;
		case M2_OP_CONTENT_REMOVE:   SETSTR(NAME_MSGNAME_M2_CONTENTREMOVE);   return ;
		case M2_OP_CONTENT_COMMIT:   SETSTR(NAME_MSGNAME_M2_CONTENTCOMMIT);   return ;
		case M2_OP_CONTENT_ROLLBACK: SETSTR(NAME_MSGNAME_M2_CONTENTROLLBACK); return ;

		case M2_OP_CHUNK_COMMIT:     SETSTR(NAME_MSGNAME_M2_CHUNK_COMMIT); return ;
		case M2_OP_CONTENT_APPEND:   SETSTR(NAME_MSGNAME_M2_CONTENTAPPEND); return ;
	}
	g_assert_not_reached();
#undef SETSTR
}

static void
meta2_remote_request_add_path(MESSAGE m, const gchar * path,
		gboolean hasLength, const content_length_t content_length)
{
	g_assert (m != NULL);
	g_assert (path != NULL);

	message_add_field(m, NAME_MSGKEY_CONTENTPATH, path, strlen(path));

	if (hasLength) {
		gchar wrkBuf[32];
		gsize wrkLen = g_snprintf(wrkBuf, 31, "%"G_GINT64_FORMAT, content_length);
		message_add_field(m, NAME_MSGKEY_CONTENTLENGTH, wrkBuf, wrkLen);
	}
}

static MESSAGE
meta2_remote_request_create(meta2_operation_t mop, const container_id_t id)
{
	gsize wrkLen = 0;
	char *wrkBuf = NULL;

	g_assert (id != NULL);
	__get_request_name2(mop, &wrkBuf, &wrkLen);
	MESSAGE m = message_create_named(wrkBuf);
	message_add_field(m, NAME_MSGKEY_CONTAINERID, id, sizeof(container_id_t));
	return m;
}

static gint
meta2_remote_container_common_fd_v2(const char *caller, int *fd, gint ms, GError ** err, meta2_operation_t mop,
    const container_id_t cid, const gchar *name, const gchar *vns, const char *stgpol)
{
	static struct code_handler_s codes[] = {
		{CODE_FINAL_OK, REPSEQ_FINAL, NULL, NULL},
		{0, 0, NULL, NULL}
	};
	struct reply_sequence_data_s data = { NULL, 0, codes };

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	MESSAGE request = meta2_remote_request_create(mop, cid);

	if (name)
	    message_add_field(request, NAME_HEADER_CONTAINERNAME, name, strlen(name));
	if (vns)
	    message_add_field(request, NAME_HEADER_VIRTUALNAMESPACE, vns, strlen(vns));
	if (stgpol)
	    message_add_field(request, NAME_HEADER_STORAGEPOLICY, stgpol, strlen(stgpol));

	if (!metaXClient_reply_sequence_run(err, request, fd, ms, &data)) {
		GSETERROR(err, "<%s> An error occured while executing the request", caller);
		goto errorLabel;
	}

	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	message_destroy(request);
	return TRUE;

errorLabel:
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	message_destroy(request);
	return FALSE;
}

static gint
meta2_remote_container_common_v2(const char *caller, const addr_info_t * m2_addr, gint ms,
		GError ** err, meta2_operation_t mop,
		const container_id_t cid, const char *name, const char *vns, const char *stgpol)
{
	int fd = addrinfo_connect(m2_addr, ms, err);
	if (fd < 0) {
		GSETERROR(err, "<%s> Connection failed", caller);
		return 0;
	}

	gint rc = meta2_remote_container_common_fd_v2(caller, &fd, ms, err, mop, cid, name, vns, stgpol);
	metautils_pclose(&fd);
	return rc;
}

static gint
meta2_remote_container_common(const char *caller, addr_info_t * m2_addr, gint ms, GError ** err, meta2_operation_t mop,
    const container_id_t container_id, const gchar * name)
{
	return meta2_remote_container_common_v2(caller, m2_addr, ms, err, mop, container_id, name, NULL, NULL);
}

/* ------------------------------------------------------------------------- */

gboolean meta2_remote_container_create (addr_info_t *m2_addr, gint ms, GError **err, const container_id_t container_id, const gchar *name)
{
	return meta2_remote_container_common (__FUNCTION__, m2_addr, ms, err, M2_OP_CONTAINER_CREATE, container_id, name);
}

gboolean meta2_remote_container_create_v2 (addr_info_t *m2_addr, gint ms, GError **err, const container_id_t container_id,
		 const gchar *name, const gchar *virtual_namespace)
{
	return meta2_remote_container_common_v2 (__FUNCTION__, m2_addr, ms, err, M2_OP_CONTAINER_CREATE,
			container_id, name, virtual_namespace, NULL);
}

gboolean meta2_remote_container_create_v3 (const addr_info_t *m2, gint ms, const char *ns, const char *cname,
		const container_id_t cid, const char *stgpol, GError **e)
{
	const char *vns = NULL;
	if( NULL != ns && NULL != strchr(ns, '.'))
		vns = ns;

	return meta2_remote_container_common_v2 (__FUNCTION__, m2, ms, e, M2_OP_CONTAINER_CREATE, cid, cname, vns, stgpol);
}

GSList* meta2_remote_container_list (addr_info_t *m2_addr, gint ms, GError **err, const container_id_t container_id)
{
	static struct code_handler_s codes [] = {
		{ CODE_FINAL_OK, REPSEQ_FINAL,         &path_info_concat, NULL},
		{ CODE_PARTIAL_CONTENT, REPSEQ_BODYMANDATORY, &path_info_concat, NULL},
		{ 0, 0, NULL, NULL},
	};

	GSList *result = NULL;
	struct reply_sequence_data_s data = { &result , 0 , codes };

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	MESSAGE request = meta2_remote_request_create (M2_OP_CONTAINER_LIST, container_id);

	if (!metaXClient_reply_sequence_run_from_addrinfo (err, request, m2_addr, ms, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto errorLabel;
	}

	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	message_destroy(request);
	return result;

errorLabel:
	g_slist_free_full(result, (GDestroyNotify) path_info_clean);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	message_destroy(request);
	return NULL;
}

/* ------------------------------------------------------------------------- */

gboolean meta2_remote_content_remove (addr_info_t *m2_addr, gint ms, GError **err, const container_id_t container_id, const gchar *content_path)
{
	static struct code_handler_s codes [] = {
		{ CODE_FINAL_OK, REPSEQ_FINAL, NULL, NULL },
		{ 0, 0, NULL, NULL },
	};
	struct reply_sequence_data_s data = { NULL , 0 , codes };

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	MESSAGE request = meta2_remote_request_create (M2_OP_CONTENT_REMOVE, container_id);
	meta2_remote_request_add_path (request, content_path, FALSE, 0);

	if (!metaXClient_reply_sequence_run_from_addrinfo (err, request, m2_addr, ms, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto errorLabel;
	}

	message_destroy(request);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return TRUE;
errorLabel:
	message_destroy(request);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return FALSE;
}

gboolean meta2_remote_content_commit (addr_info_t *m2_addr, gint ms, GError **err, const container_id_t container_id, const gchar *content_path)
{
	static struct code_handler_s codes [] = {
		{ CODE_FINAL_OK, REPSEQ_FINAL, NULL, NULL },
		{ 0,0,NULL,NULL}
	};
	struct reply_sequence_data_s data = { NULL , 0 , codes };

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	MESSAGE request = meta2_remote_request_create (M2_OP_CONTENT_COMMIT, container_id);
	meta2_remote_request_add_path (request, content_path, FALSE, 0);

	if (!metaXClient_reply_sequence_run_from_addrinfo (err, request, m2_addr, ms, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto errorLabel;
	}

	message_destroy(request);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	return TRUE;
errorLabel:
	message_destroy(request);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return FALSE;
}

gint meta2_remote_content_rollback (addr_info_t *m2_addr, gint ms, GError **err,
	const container_id_t container_id, const gchar *content_path)
{
	static struct code_handler_s codes [] = {
		{ CODE_FINAL_OK, REPSEQ_FINAL, NULL, NULL },
		{ 0,0,NULL,NULL}
	};
	struct reply_sequence_data_s data = { NULL , 0 , codes };

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	MESSAGE request = meta2_remote_request_create (M2_OP_CONTENT_ROLLBACK, container_id);
	message_add_field(request, NAME_MSGKEY_CONTENTPATH, content_path, strlen(content_path));

	if (!metaXClient_reply_sequence_run_from_addrinfo (err, request, m2_addr, ms, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto errorLabel;
	}

	message_destroy(request);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return 1;
errorLabel:
	message_destroy(request);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return 0;
}

GSList* meta2_remote_content_add (addr_info_t *m2_addr, gint ms, GError **err,
	const container_id_t container_id, const gchar *content_path,
	content_length_t content_length, GByteArray *system_metadata, GByteArray **new_system_metadata)
{
	gboolean get_sys_metadata (GError **err0, gpointer udata, gint code, MESSAGE rep) {
		int rc;
		void *field=NULL;
		gsize fieldLen=0;

		(void)code;
		(void)udata;

		if (!rep)
			return FALSE;
		if (!new_system_metadata)
			return TRUE;
		rc = message_get_field (rep, NAME_HEADER_METADATA_SYS, sizeof(NAME_HEADER_METADATA_SYS)-1, &field, &fieldLen, err0);
		switch (rc) {
			case 1:
				*new_system_metadata = g_byte_array_append( g_byte_array_new(), field, fieldLen);
				return TRUE;
			case 0:
				*new_system_metadata = NULL;
				return TRUE;
		}
		GSETERROR(err0, "Cannot lookup the updated systemetadata");
		return FALSE;
	}

	struct code_handler_s codes [] = {
		{ CODE_PARTIAL_CONTENT, REPSEQ_BODYMANDATORY, chunk_info_concat, NULL },
		{ CODE_FINAL_OK, REPSEQ_FINAL,         chunk_info_concat, get_sys_metadata },
		{ 0,0,NULL,NULL}
	};
	GSList *result = NULL;
	struct reply_sequence_data_s data = { &result , 0 , codes };

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	MESSAGE request = meta2_remote_request_create (M2_OP_CONTENT_ADD, container_id);
	meta2_remote_request_add_path(request, content_path, TRUE, content_length);

	if (system_metadata && system_metadata->data && system_metadata->len>0)
		message_add_field (request, NAME_HEADER_METADATA_SYS, system_metadata->data, system_metadata->len);

	if (!metaXClient_reply_sequence_run_from_addrinfo (err, request, m2_addr, ms, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto errorLabel;
	}

	message_destroy(request);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return result;
errorLabel:
	message_destroy(request);
	g_slist_free_full (result, (GDestroyNotify) chunk_info_clean);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return NULL;
}

/* ------------------------------------------------------------------------- */

gint meta2_remote_content_rollback_in_fd (int *fd, gint ms, GError **err,
	const container_id_t container_id, const gchar *content_path)
{
	static struct code_handler_s codes [] = {
		{ CODE_FINAL_OK, REPSEQ_FINAL, NULL, NULL },
		{ 0,0,NULL,NULL}
	};
	
	struct reply_sequence_data_s data = { NULL , 0 , codes };
	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	MESSAGE request = meta2_remote_request_create (M2_OP_CONTENT_ROLLBACK, container_id);
	message_add_field(request, NAME_MSGKEY_CONTENTPATH, content_path, strlen(content_path));

	if (!metaXClient_reply_sequence_run (err, request, fd, ms, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto errorLabel;
	}

	message_destroy(request);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return 1;
errorLabel:
	message_destroy(request);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return 0;
}

GSList* meta2_remote_content_add_in_fd_v2 (int *fd, gint ms, GError **err,
	const container_id_t container_id, const gchar *content_path, content_length_t content_length,
	GByteArray *user_metadata, GByteArray *system_metadata, GByteArray **new_system_metadata)
{
	gboolean get_sys_metadata (GError **err0, gpointer udata, gint code, MESSAGE rep) {
		(void)udata, (void)code;
		if (!rep)
			return FALSE;
		if (!new_system_metadata)
			return TRUE;
		void *field=NULL;
		gsize fieldLen=0;
		int rc = message_get_field (rep, NAME_HEADER_METADATA_SYS, sizeof(NAME_HEADER_METADATA_SYS)-1, &field, &fieldLen, err0);
		switch (rc) {
			case 1:
				*new_system_metadata = g_byte_array_append( g_byte_array_new(), field, fieldLen);
				return TRUE;
			case 0:
				*new_system_metadata = NULL;
				return TRUE;
		}
		GSETERROR(err0, "Cannot lookup the updated systemetadata");
		return FALSE;
	}

	struct code_handler_s codes [] = {
		{ CODE_PARTIAL_CONTENT, REPSEQ_BODYMANDATORY, chunk_info_concat, NULL },
		{ CODE_FINAL_OK, REPSEQ_FINAL,         chunk_info_concat, get_sys_metadata },
		{ 0,0,NULL,NULL}
	};
	GSList *result = NULL;
	struct reply_sequence_data_s data = { &result , 0 , codes };

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	MESSAGE request = meta2_remote_request_create (M2_OP_CONTENT_ADD, container_id);
	meta2_remote_request_add_path(request, content_path, TRUE, content_length);

	if (system_metadata)
		message_add_field (request, NAME_HEADER_METADATA_SYS, system_metadata->data, system_metadata->len);

	if (user_metadata)
		message_add_field (request, NAME_HEADER_METADATA_USR, user_metadata->data, user_metadata->len);

	if (!metaXClient_reply_sequence_run (err, request, fd, ms, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto errorLabel;
	}

	message_destroy(request);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return result;
errorLabel:
	message_destroy(request);
	g_slist_free_full(result, (GDestroyNotify) chunk_info_clean);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return NULL;
}

GSList* meta2_remote_content_add_in_fd (int *fd, gint ms, GError **err,
	const container_id_t container_id, const gchar *content_path, content_length_t content_length,
	GByteArray *system_metadata, GByteArray **new_system_metadata)
{
	return meta2_remote_content_add_in_fd_v2(fd, ms, err, container_id, content_path, content_length, NULL, system_metadata, new_system_metadata);
}

GSList* meta2_remote_content_spare_in_fd_full (int *fd, gint ms, GError **err, const container_id_t container_id,
		const gchar *content_path, gint count, gint distance, const gchar *notin, const gchar *broken)
{
	static struct code_handler_s codes [] = {
		{ CODE_PARTIAL_CONTENT, REPSEQ_BODYMANDATORY, chunk_info_concat, NULL },
		{ CODE_FINAL_OK, REPSEQ_FINAL,         chunk_info_concat, NULL },
		{ 0,0,NULL,NULL}
	};

	GSList *result = NULL;
	struct reply_sequence_data_s data = { &result , 0 , codes };

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	MESSAGE request = meta2_remote_request_create (M2_OP_CONTENT_SPARE, container_id);
	meta2_remote_request_add_path(request, content_path, FALSE, 0);

	if (count > 0)
		message_add_field_strint64(request, NAME_MSGKEY_COUNT, count);
	if (distance > 0)
		message_add_field_strint64(request, NAME_MSGKEY_DISTANCE, distance);
	if (notin && *notin)
		message_add_field(request, NAME_MSGKEY_NOTIN, notin, strlen(notin) + 1);
	if (broken && *broken)
		message_add_field(request, NAME_MSGKEY_BROKEN, broken, strlen(broken) + 1);

	if (!metaXClient_reply_sequence_run (err, request, fd, ms, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto errorLabel;
	}

	message_destroy(request);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return result;
errorLabel:
	message_destroy(request);
	g_slist_free_full (result, (GDestroyNotify) chunk_info_clean);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return NULL;
}

/* ------------------------------------------------------------------------- */

static gboolean
concat_names (GError **err, gpointer udata, gint code, guint8 *body, gsize bodySize)
{
	GSList **pResult = (GSList**) udata;
	GSList *decoded=NULL;

	(void)code;

	if (!pResult)
		return FALSE;
	decoded = meta2_maintenance_names_unmarshall_buffer( body, bodySize, err);
	if (!decoded)
		return FALSE;
	*pResult = g_slist_concat(*pResult, decoded);
	return TRUE;
}

static gboolean
concat_contents (GError **err, gpointer udata, gint code, guint8 *body, gsize bodySize)
{
	struct meta2_raw_content_s **pContent=NULL, *decoded=NULL;

	(void)code;

	pContent = (struct meta2_raw_content_s**) udata;
	if (!pContent)
		return FALSE;
	/*unserialize the body*/
	decoded = meta2_maintenance_content_unmarshall_buffer(body, bodySize, err);
	if (!decoded)
		return FALSE;
	/*append the chunks*/
	if (!(*pContent)) {
		*pContent = decoded;
	} else {
		if ((*pContent)->raw_chunks) {
			(*pContent)->raw_chunks = g_slist_concat( (*pContent)->raw_chunks, decoded->raw_chunks);
		} else {
			(*pContent)->raw_chunks = decoded->raw_chunks;
		}
		decoded->raw_chunks = NULL;
		meta2_maintenance_destroy_content(decoded);
	}
	return TRUE;
}

static MESSAGE
meta2raw_create_request(char *name, GByteArray *body, ...)
{
	va_list args;
	MESSAGE msg = message_create_named (name);
	if (body)
		message_set_BODY (msg, body->data, body->len, NULL);
	va_start (args,body);
	message_add_fieldv_gba (msg, args);
	va_end(args);
	return msg;
}

static struct meta2_raw_content_s*
meta2raw_remote_stat_content(struct metacnx_ctx_s *ctx, const container_id_t cid,
		const gchar *path, gsize path_len, gboolean check_flags, GError **err)
{
	static struct code_handler_s codes [] = {
		{ CODE_FINAL_OK, REPSEQ_FINAL|REPSEQ_BODYMANDATORY, concat_contents, NULL },
		{ CODE_PARTIAL_CONTENT, REPSEQ_BODYMANDATORY, concat_contents, NULL },
		{ 0,0,NULL,NULL}
	};
	MESSAGE request=NULL;
	GByteArray *gba_path=NULL, *gba_cid=NULL, *gba_check=NULL;
	struct meta2_raw_content_s *result=NULL;
	struct reply_sequence_data_s data = { &result , 0 , codes };

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	if (!ctx || !cid || !path || !path_len) {
		GSETERROR(err,"invalid parameter");
		goto exit_label;
	}

	gba_cid = metautils_gba_from_cid(cid);
	gba_path = metautils_gba_from_string (path);
	gba_check = metautils_gba_from_string("1");
	request = meta2raw_create_request(NAME_MSGNAME_M2RAW_GETCHUNKS, NULL,
			NAME_MSGKEY_CONTAINERID, gba_cid,
			NAME_MSGKEY_CONTENTPATH, gba_path,
			NAME_HEADER_CHECKFLAGS, (check_flags ? gba_check : NULL),
			NULL);

	if (!metaXClient_reply_sequence_run_context (err, ctx, request, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto error_meta;
	}

	message_destroy(request);
	g_byte_array_free( gba_check, TRUE);
	g_byte_array_free( gba_path, TRUE);
	g_byte_array_free( gba_cid, TRUE);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return result;

error_meta:
	message_destroy(request);
	g_byte_array_free(gba_check, TRUE);
	g_byte_array_free(gba_path, TRUE);
	g_byte_array_free(gba_cid, TRUE);
exit_label:
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return NULL;
}

gboolean
meta2raw_remote_update_chunks(
        struct metacnx_ctx_s *ctx, GError **err,
	        struct meta2_raw_content_s *content, gboolean allow_update, char *position_prefix)
{
	static struct code_handler_s codes [] = {
		{ CODE_FINAL_OK, REPSEQ_FINAL, NULL, NULL },
		{ 0,0,NULL,NULL}
	};
	gboolean rc=FALSE;
	MESSAGE request=NULL;
	GByteArray *body;
	struct reply_sequence_data_s data = { NULL , 0 , codes };

	if (!ctx || !content) {
		GSETERROR(err,"invalid parameter");
		goto exit_label;
	}

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	/*init the request*/
	body = meta2_maintenance_marshall_content( content, err);
	if (!body) {
		GSETERROR(err,"failed to serialize the content structure");
		goto error_alloc_body;
	}

	request = meta2raw_create_request(NAME_MSGNAME_M2RAW_SETCHUNKS,body,NULL);

	if (allow_update)
		message_add_field(request, NAME_MSGKEY_ALLOWUPDATE, "1", 1);

	if (position_prefix)
		message_add_field(request, "POSITION_PREFIX", position_prefix, strlen(position_prefix));

	/*send the request*/
	if (!metaXClient_reply_sequence_run_context (err, ctx, request, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto error_meta;
	}

	rc = TRUE;
error_meta:
	message_destroy(request);
	g_byte_array_free( body, TRUE);
error_alloc_body:
exit_label:
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return rc;
}

gboolean
meta2raw_remote_update_content(
        struct metacnx_ctx_s *ctx, GError **err,
	        struct meta2_raw_content_s *content, gboolean allow_update)
{
	static struct code_handler_s codes [] = {
		{ CODE_FINAL_OK, REPSEQ_FINAL, NULL, NULL },
		{ 0,0,NULL,NULL}
	};
	gboolean rc=FALSE;
	MESSAGE request=NULL;
	GByteArray *body;
	struct reply_sequence_data_s data = { NULL , 0 , codes };

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	if (!ctx || !content) {
		GSETERROR(err,"invalid parameter");
		goto exit_label;
	}

	body = meta2_maintenance_marshall_content( content, err);
	if (!body) {
		GSETERROR(err,"failed to serialize the content structure");
		goto error_alloc_body;
	}

	request = meta2raw_create_request(NAME_MSGNAME_M2RAW_SETCONTENT,body,NULL);

	if (allow_update)
		message_add_field(request, NAME_MSGKEY_ALLOWUPDATE, "1", 1);

	/*send the request*/
	if (!metaXClient_reply_sequence_run_context (err, ctx, request, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto error_meta;
	}

	rc = TRUE;
error_meta:
	message_destroy(request);
	g_byte_array_free( body, TRUE);
error_alloc_body:
exit_label:
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return rc;
}

gboolean
meta2raw_remote_delete_chunks(
	struct metacnx_ctx_s *ctx, GError **err,
	struct meta2_raw_content_s *content)
{
	static struct code_handler_s codes [] = {
		{ CODE_FINAL_OK, REPSEQ_FINAL, NULL, NULL },
		{ 0,0,NULL,NULL}
	};
	gboolean rc=FALSE;
	MESSAGE request=NULL;
	GByteArray *body;
	struct reply_sequence_data_s data = { NULL , 0 , codes };

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	if (!ctx || !content) {
		GSETERROR(err,"invalid parameter");
		goto exit_label;
	}

	body = meta2_maintenance_marshall_content( content, err);
	if (!body) {
		GSETERROR(err,"memory allocation failure");
		goto error_alloc_body;
	}
	
	request = meta2raw_create_request(NAME_MSGNAME_M2RAW_DELCHUNKS,body,NULL);

	if (!metaXClient_reply_sequence_run_context (err, ctx, request, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto error_meta;
	}
	
	rc = TRUE;
error_meta:
	message_destroy(request);
	g_byte_array_free( body, TRUE);
error_alloc_body:
exit_label:
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return rc;
}

struct meta2_raw_content_s*
meta2raw_remote_get_content_from_name(
	struct metacnx_ctx_s *ctx, GError **err,
	const container_id_t container_id, const gchar *path, gsize path_len)
{
	static struct code_handler_s codes [] = {
		{ CODE_FINAL_OK, REPSEQ_FINAL|REPSEQ_BODYMANDATORY, concat_contents, NULL },
		{ 0,0,NULL,NULL}
	};
	MESSAGE request=NULL;
	GByteArray *gba_path=NULL, *gba_cid=NULL;
	struct meta2_raw_content_s *result=NULL;
	struct reply_sequence_data_s data = { &result , 0 , codes };

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	if (!ctx || !container_id || !path || !path_len) {
		GSETERROR(err,"invalid parameter");
		goto exit_label;
	}

	gba_cid = metautils_gba_from_cid (container_id);
	gba_path = metautils_gba_from_string (path);
	request = meta2raw_create_request(NAME_MSGNAME_M2RAW_GETCONTENTBYPATH, NULL,
		NAME_MSGKEY_CONTAINERID, gba_cid,
		NAME_MSGKEY_CONTENTPATH, gba_path,
		NULL);

	if (!metaXClient_reply_sequence_run_context (err, ctx, request, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto error_meta;
	}

	message_destroy(request);
	g_byte_array_free( gba_cid, TRUE);
	g_byte_array_free( gba_path, TRUE);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return result;

error_meta:
	message_destroy(request);
	g_byte_array_free(gba_cid, TRUE);
	g_byte_array_free(gba_path, TRUE);
exit_label:
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return NULL;
}

GSList*
meta2raw_remote_get_contents_names(
	struct metacnx_ctx_s *ctx, GError **err,
	const container_id_t container_id)
{
	static struct code_handler_s codes [] = {
		{ CODE_FINAL_OK, REPSEQ_FINAL|REPSEQ_BODYMANDATORY, concat_names, NULL },
		{ CODE_PARTIAL_CONTENT, REPSEQ_BODYMANDATORY, concat_names, NULL },
		{ 0,0,NULL,NULL}
	};
	MESSAGE request=NULL;
	GByteArray *gba_cid;
	GSList *result=NULL;
	struct reply_sequence_data_s data = { &result , 0 , codes };

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	
	if (!ctx || !container_id) {
		GSETERROR(err,"invalid parameter");
		goto exit_label;
	}

	gba_cid = metautils_gba_from_cid(container_id);
	request = meta2raw_create_request(NAME_MSGNAME_M2RAW_GETCONTENTS, NULL,
		NAME_MSGKEY_CONTAINERID, gba_cid,
		NULL);

	if (!metaXClient_reply_sequence_run_context (err, ctx, request, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto error_meta;
	}

	message_destroy(request);
	g_byte_array_free( gba_cid, TRUE);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return result;

error_meta:
	message_destroy(request);
	g_byte_array_free( gba_cid, TRUE);
exit_label:
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return NULL;
}

struct meta2_raw_content_s*
meta2_remote_stat_content(struct metacnx_ctx_s *cnx, const container_id_t container_id,
	const gchar *path, gsize path_len, GError **err)
{
	return meta2raw_remote_stat_content(cnx, container_id, path, path_len, TRUE, err);
}

status_t
meta2_remote_touch_content(struct metacnx_ctx_s *ctx,
		const container_id_t var_0, const gchar* var_1, GError **err)
{
	static struct code_handler_s codes [] = {
		{ CODE_FINAL_OK, REPSEQ_FINAL,         NULL, NULL },
		{ 0,0,NULL,NULL}
	};
	struct reply_sequence_data_s data = { NULL , 0 , codes };
	status_t status = 0;

	if (!ctx || !var_0 || !var_1) {
		GSETERROR(err,"Invalid parameter ( var_0=%p var_1=%p)"
				, (void*)var_0, (void*)var_1);
		return 0;
	}

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	MESSAGE request = message_create_named("REQ_M2RAW_TOUCH_CONTENT");
	do {
		GByteArray *gba = metautils_gba_from_cid(var_0);
		message_add_field(request, NAME_MSGKEY_CONTAINERID, gba->data, gba->len);
		g_byte_array_free(gba, TRUE);
	} while (0);

	do {
		GByteArray *gba = metautils_gba_from_string(var_1);
		message_add_field(request, NAME_MSGKEY_CONTENTPATH, gba->data, gba->len);
		g_byte_array_free(gba, TRUE);
	} while (0);

	/*Now send the request*/
	if (!metaXClient_reply_sequence_run_context (err, ctx, request, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto error_label;
	}

	status = 1;
error_label:
	message_destroy(request);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return status;
}

status_t meta2_remote_touch_container_ex(struct metacnx_ctx_s *ctx, const container_id_t var_0,
    unsigned int flags, GError **err)
{
	static struct code_handler_s codes [] = {
		{ CODE_FINAL_OK, REPSEQ_FINAL,         NULL, NULL },
		{ 0,0,NULL,NULL}
	};

	struct reply_sequence_data_s data = { NULL , 0 , codes };
	status_t status = 0;

	if (!ctx || !var_0) {
		GSETERROR(err,"Invalid parameter ( var_0=%p)" , (void*)var_0);
		return 0;
	}

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	MESSAGE request = message_create_named("REQ_M2RAW_TOUCH_CONTAINER");

	do {
		GByteArray *gba = metautils_gba_from_cid(var_0);
		message_add_field(request, NAME_MSGKEY_CONTAINERID, gba->data, gba->len);
		g_byte_array_free(gba, TRUE);
	} while (0);

	/*add flags...*/
	if (flags) {
		flags = g_htonl(flags);
	    message_add_field(request, NAME_MSGKEY_FLAGS, &flags, sizeof(flags));
	}

	/*Now send the request*/
	if (!metaXClient_reply_sequence_run_context (err, ctx, request, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto error_label;
	}

	status = 1;
error_label:
	message_destroy(request);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return status;
}


struct arg_stat_content_v2_s {
	meta2_raw_content_v2_t* var_2;
};

static gboolean
msg_manager_stat_content_v2(GError ** err, gpointer udata, gint code, MESSAGE rep)
{
	struct arg_stat_content_v2_s *args;
	if (!udata || !rep) {
		GSETERROR(err,"Invalid parameter udata=%p rep=%p", (void*)udata, (void*)rep);
		return FALSE;
	}
	args = udata;

	if (CODE_IS_OK(code)) {
		/* Get args->var_2 from the body */
		gint has_body = message_has_BODY(rep,NULL);
		if (code == CODE_PARTIAL_CONTENT && 0 > has_body) {
			GSETERROR(err,"No body found in the reply");
			goto error_label;
		}
		if (has_body > 0) { /*a body has been found in the message*/
			void *data = NULL;
			gsize data_size = 0;
			switch (message_get_BODY(rep, &data, &data_size, err)) {
				case -1:
					GSETCODE(err, CODE_BAD_REQUEST, "Invalid ASN.1 message, failed to extract the body");
					goto error_label;
				case 0:
					DEBUG("Optional body not found");
					break;

				default:
					{
						GError *error_local = NULL;
						DEBUG("Found body [%"G_GSIZE_FORMAT"/%p]", data_size, data);

						do { /* BLOCK unserialize_data */
							GSList *l = NULL, *l_next = NULL;
							meta2_raw_content_v2_unmarshall(&l, data, &data_size, &error_local);
							if (l) {
								(args-> var_2 ) = l->data;
								l->data = NULL;
								l_next = l->next;
								l->next = NULL;
								g_slist_free1(l);
								if (l_next) {
									g_slist_foreach(l_next, meta2_raw_content_v2_gclean, NULL);
									g_slist_free(l_next);
								}
							}
						} while (0);

						if (error_local) {
							GSETERROR(&error_local, "Cause: %s", gerror_get_message(error_local));
							GSETERROR(&error_local, "Invalid ASN.1 message : ");
							g_error_free(error_local);
							goto error_label;
						}
					}
					break;
			}
		}
	}

	return TRUE;
error_label:
	GSETERROR(err,"Reply management failure (code=%d)", code);
	return FALSE;
}

status_t
meta2_remote_stat_content_v2(struct metacnx_ctx_s *ctx, const container_id_t var_0, const gchar* var_1, meta2_raw_content_v2_t* *var_2, GError **err)
{
	static struct code_handler_s codes [] = {
		{ CODE_FINAL_OK, REPSEQ_FINAL, NULL, msg_manager_stat_content_v2 },
		{ CODE_PARTIAL_CONTENT, REPSEQ_BODYMANDATORY, NULL, msg_manager_stat_content_v2 },
		{ -1, REPSEQ_ERROR, NULL, msg_manager_stat_content_v2 },
		{ 0,0,NULL,NULL}
	};

	struct arg_stat_content_v2_s args;
	struct reply_sequence_data_s data = { &args , 0 , codes };

	args.var_2 = 0;

	if (!ctx || !var_0 || !var_1) {
		GSETERROR(err,"Invalid parameter");
		return 0;
	}

	MESSAGE request = message_create_named("META2_SERVICES_STAT_CONTENT_V2");
	status_t status = 0;

	do {
		GByteArray *gba = metautils_gba_from_cid (var_0);
		message_add_field(request, "field_0", gba->data, gba->len);
		g_byte_array_free(gba, TRUE);
	} while (0);

	do {
		GByteArray *gba = metautils_gba_from_string (var_1);
		message_add_field(request, "field_1", gba->data, gba->len);
		g_byte_array_free(gba, TRUE);
	} while (0);

	if (!metacnx_open(ctx, err)) {
		GSETERROR(err,"Failed to open the connexion");
	} else if (!metaXClient_reply_sequence_run_context (err, ctx, request, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
	} else {
		status = 1;
	}

	message_destroy(request);
	if (var_2)
		*var_2 = args.var_2;
	return status;
}

status_t
meta2_remote_modify_metadatasys(struct metacnx_ctx_s *ctx, const container_id_t var_0, const gchar* var_1, const gchar* var_2, GError **err)
{
	static struct code_handler_s codes [] = {
		{ CODE_FINAL_OK, REPSEQ_FINAL, NULL, NULL },
		{ 0,0,NULL,NULL}
	};
	struct reply_sequence_data_s data = { NULL , 0 , codes };

	if (!ctx || !var_0 || !var_1 || !var_2) {
		GSETERROR(err,"Invalid parameter");
		return 0;
	}

	status_t status = 0;
	MESSAGE request = message_create_named("META2_SERVICES_MODIFY_METADATASYS");

	do {
		GByteArray *gba = metautils_gba_from_cid (var_0);
		message_add_field(request, "field_0", gba->data, gba->len);
		g_byte_array_free(gba, TRUE);
	} while (0);

	do {
		GByteArray *gba = metautils_gba_from_string (var_1);
		message_add_field(request, "field_1", gba->data, gba->len);
		g_byte_array_free(gba, TRUE);
	} while (0);

	do {
		GByteArray *gba = metautils_gba_from_string (var_2);
		message_add_field(request, "field_2", gba->data, gba->len);
		g_byte_array_free(gba, TRUE);
	} while (0);

	if (metacnx_open(ctx, err)) {
		GSETERROR(err,"Failed to open the connexion");
	} else if (!metaXClient_reply_sequence_run_context (err, ctx, request, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
	} else {
		status = 1;
	}

	message_destroy(request);
	return status;
}

