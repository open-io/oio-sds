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
#include "meta2_macros.h"

static gint
meta2_remote_container_common_fd_v2 (int *fd, gint ms, GError ** err, const char *op,
    struct hc_url_s *url, const char *stgpol)
{
	static struct code_handler_s codes[] = {
		{CODE_FINAL_OK, REPSEQ_FINAL, NULL, NULL},
		{0, 0, NULL, NULL}
	};
	struct reply_sequence_data_s data = { NULL, 0, codes };

	EXTRA_ASSERT (fd != NULL);
	EXTRA_ASSERT (op != NULL);
	EXTRA_ASSERT (url != NULL);

	MESSAGE request = message_create_named(op);
	message_add_url (request, url);
	if (stgpol)
	    message_add_field_str(request, NAME_MSGKEY_STGPOLICY, stgpol);

	gboolean rc = metaXClient_reply_sequence_run(err, request, fd, ms, &data);
	message_destroy(request);
	if (!rc)
		GSETERROR(err, "An error occured while executing the request");
	return rc;
}

static gint
meta2_remote_container_common_v2 (const addr_info_t * m2, gint ms, GError ** err,
		const char *op, struct hc_url_s *url, const char *stgpol)
{
	int fd = addrinfo_connect(m2, ms, err);
	if (fd < 0) {
		GSETERROR(err, "Connection failed");
		return 0;
	}
	gint rc = meta2_remote_container_common_fd_v2(&fd, ms, err, op, url, stgpol);
	metautils_pclose(&fd);
	return rc;
}

/* ------------------------------------------------------------------------- */

gboolean
meta2_remote_container_create_v3 (const addr_info_t *m2, gint ms, GError **err,
		struct hc_url_s *url, const char *stgpol)
{
	return meta2_remote_container_common_v2 (m2, ms, err, NAME_MSGNAME_M2_CREATE, url, stgpol);
}

GSList*
meta2_remote_container_list (const addr_info_t *m2, gint ms, GError **err,
		struct hc_url_s *url)
{
	static struct code_handler_s codes [] = {
		{ CODE_FINAL_OK, REPSEQ_FINAL,         &path_info_concat, NULL},
		{ CODE_PARTIAL_CONTENT, REPSEQ_BODYMANDATORY, &path_info_concat, NULL},
		{ 0, 0, NULL, NULL},
	};
	GSList *result = NULL;
	struct reply_sequence_data_s data = { &result , 0 , codes };

	EXTRA_ASSERT (m2 != NULL);
	EXTRA_ASSERT (url != NULL);
	MESSAGE request = message_create_named (NAME_MSGNAME_M2_CREATE);
	message_add_url (request, url);

	if (!metaXClient_reply_sequence_run_from_addrinfo (err, request, m2, ms, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		g_slist_free_full(result, (GDestroyNotify) path_info_clean);
		result = NULL;
	}
	message_destroy(request);
	return result;
}

/* ------------------------------------------------------------------------- */

GSList*
meta2_remote_content_add_in_fd (int *fd, gint ms, GError **err,
		struct hc_url_s *url, content_length_t content_length,
		GByteArray *metadata, GByteArray **new_metadata)
{
	gboolean get_sys_metadata (GError **err0, gpointer udata, gint code, MESSAGE rep) {
		(void)udata, (void)code, (void)err0;
		if (!rep)
			return FALSE;
		if (!new_metadata)
			return TRUE;
		*new_metadata = NULL;
		gsize fieldLen=0;
		void *field = message_get_field (rep, NAME_HEADER_METADATA_SYS, &fieldLen);
		if (field)
			*new_metadata = g_byte_array_append( g_byte_array_new(), field, fieldLen);
		return TRUE;
	}

	struct code_handler_s codes [] = {
		{ CODE_PARTIAL_CONTENT, REPSEQ_BODYMANDATORY, chunk_info_concat, NULL },
		{ CODE_FINAL_OK, REPSEQ_FINAL, chunk_info_concat, get_sys_metadata },
		{ 0,0,NULL,NULL}
	};
	GSList *result = NULL;
	struct reply_sequence_data_s data = { &result , 0 , codes };

	EXTRA_ASSERT (fd != NULL);
	EXTRA_ASSERT (url != NULL);
	MESSAGE request = message_create_named (NAME_MSGNAME_M2_CONTENTADD);
	message_add_url (request, url);
	message_add_field_strint64 (request, NAME_MSGKEY_CONTENTLENGTH, content_length);

	if (metadata)
		message_add_field (request, NAME_HEADER_METADATA_SYS, metadata->data, metadata->len);
	if (!metaXClient_reply_sequence_run (err, request, fd, ms, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		g_slist_free_full(result, (GDestroyNotify) chunk_info_clean);
		result = NULL;
	}

	message_destroy(request);
	return result;
}

GSList*
meta2_remote_content_add (const addr_info_t *m2, gint ms, GError **err,
		struct hc_url_s *url, content_length_t content_length,
		GByteArray *metadata, GByteArray **new_metadata)
{
	GSList *result = NULL;
	struct metacnx_ctx_s cnx;
	metacnx_clear (&cnx);
	if (!metacnx_init_with_addr (&cnx, m2, err))
		GSETERROR(err, "Address error");
	else if (!metacnx_open(&cnx, err))
		GSETERROR(err, "Socket error");
	else {
		cnx.timeout.cnx = ms;
		cnx.timeout.req = ms;
		result = meta2_remote_content_add_in_fd (&cnx.fd, ms, err, url, content_length, metadata, new_metadata);
	}
	metacnx_close (&cnx);
	metacnx_clear (&cnx);

	return result;
}

/* ------------------------------------------------------------------------- */


GSList*
meta2_remote_content_spare_in_fd_full (int *fd, gint ms, GError **err,
		struct hc_url_s *url, gint count, gint distance,
		const gchar *notin, const gchar *broken)
{
	static struct code_handler_s codes [] = {
		{ CODE_PARTIAL_CONTENT, REPSEQ_BODYMANDATORY, chunk_info_concat, NULL },
		{ CODE_FINAL_OK, REPSEQ_FINAL, chunk_info_concat, NULL },
		{ 0,0,NULL,NULL}
	};
	GSList *result = NULL;
	struct reply_sequence_data_s data = { &result , 0 , codes };

	EXTRA_ASSERT (fd != NULL);
	EXTRA_ASSERT (url != NULL);
	MESSAGE request = message_create_named (NAME_MSGNAME_M2_CONTENTSPARE);
	message_add_url (request, url);

	if (count > 0)
		message_add_field_strint64(request, NAME_MSGKEY_COUNT, count);
	if (distance > 0)
		message_add_field_strint64(request, NAME_MSGKEY_DISTANCE, distance);
	if (notin && *notin)
		message_add_field_str(request, NAME_MSGKEY_NOTIN, notin);
	if (broken && *broken)
		message_add_field_str(request, NAME_MSGKEY_BROKEN, broken);

	if (!metaXClient_reply_sequence_run (err, request, fd, ms, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		g_slist_free_full (result, (GDestroyNotify) chunk_info_clean);
		result = NULL;
	}

	message_destroy(request);
	return result;
}

/* ------------------------------------------------------------------------- */

gboolean
meta2raw_remote_update_chunks (struct metacnx_ctx_s *ctx, GError **err,
		struct hc_url_s *url, struct meta2_raw_content_s *content,
		gboolean allow_update, char *position_prefix)
{
	static struct code_handler_s codes [] = {
		{ CODE_FINAL_OK, REPSEQ_FINAL, NULL, NULL },
		{ 0,0,NULL,NULL}
	};
	struct reply_sequence_data_s data = { NULL , 0 , codes };

	EXTRA_ASSERT (ctx != NULL);
	EXTRA_ASSERT (url != NULL);
	EXTRA_ASSERT (content != NULL);
	MESSAGE request = message_create_named (NAME_MSGNAME_M2RAW_SETCHUNKS);
	message_add_url (request, url);
	message_add_body_unref (request, meta2_maintenance_marshall_content (content, NULL));
	if (allow_update)
		message_add_field_str(request, NAME_MSGKEY_ALLOWUPDATE, "1");
	if (position_prefix)
		message_add_field_str(request, NAME_MSGKEY_POSITIONPREFIX, position_prefix);

	gboolean rc = metaXClient_reply_sequence_run_context (err, ctx, request, &data);
	if (!rc)
		GSETERROR(err,"Cannot execute the query and receive all the responses");
	message_destroy(request);
	return rc;
}

gboolean
meta2raw_remote_update_content (struct metacnx_ctx_s *ctx, GError **err,
		struct hc_url_s *url, struct meta2_raw_content_s *content,
		gboolean allow_update)
{
	static struct code_handler_s codes [] = {
		{ CODE_FINAL_OK, REPSEQ_FINAL, NULL, NULL },
		{ 0,0,NULL,NULL}
	};
	struct reply_sequence_data_s data = { NULL , 0 , codes };

	EXTRA_ASSERT (ctx != NULL);
	EXTRA_ASSERT (url != NULL);
	EXTRA_ASSERT (content != NULL);
	MESSAGE request = message_create_named (NAME_MSGNAME_M2RAW_SETCONTENT);
	message_add_body_unref (request, meta2_maintenance_marshall_content (content, err));
	if (allow_update)
		message_add_field_str (request, NAME_MSGKEY_ALLOWUPDATE, "1");

	gboolean rc = metaXClient_reply_sequence_run_context (err, ctx, request, &data);
	if (!rc)
		GSETERROR(err,"Cannot execute the query and receive all the responses");
	message_destroy(request);
	return rc;
}

gboolean
meta2raw_remote_delete_chunks(struct metacnx_ctx_s *ctx, GError **err,
		struct hc_url_s *url, struct meta2_raw_content_s *content)
{
	static struct code_handler_s codes [] = {
		{ CODE_FINAL_OK, REPSEQ_FINAL, NULL, NULL },
		{ 0,0,NULL,NULL}
	};
	struct reply_sequence_data_s data = { NULL , 0 , codes };

	EXTRA_ASSERT (ctx != NULL);
	EXTRA_ASSERT (url != NULL);
	EXTRA_ASSERT (content != NULL);
	MESSAGE request = message_create_named (NAME_MSGNAME_M2RAW_DELCHUNKS);
	message_add_url (request, url);
	message_add_body_unref (request, meta2_maintenance_marshall_content (content, NULL));
	
	gboolean rc = metaXClient_reply_sequence_run_context (err, ctx, request, &data);
	if (!rc)
		GSETERROR(err,"Cannot execute the query and receive all the responses");
	message_destroy (request);
	return rc;
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
	if (!(*pContent))
		*pContent = decoded;
	else {
		if ((*pContent)->raw_chunks)
			(*pContent)->raw_chunks = g_slist_concat( (*pContent)->raw_chunks, decoded->raw_chunks);
		else
			(*pContent)->raw_chunks = decoded->raw_chunks;
		decoded->raw_chunks = NULL;
		meta2_maintenance_destroy_content(decoded);
	}
	return TRUE;
}

struct meta2_raw_content_s*
meta2raw_remote_get_content_from_name(struct metacnx_ctx_s *ctx, GError **err,
		struct hc_url_s *url)
{
	static struct code_handler_s codes [] = {
		{ CODE_FINAL_OK, REPSEQ_FINAL|REPSEQ_BODYMANDATORY, concat_contents, NULL },
		{ 0,0,NULL,NULL}
	};
	struct meta2_raw_content_s *result=NULL;
	struct reply_sequence_data_s data = { &result , 0 , codes };

	EXTRA_ASSERT (ctx != NULL);
	EXTRA_ASSERT (url != NULL);
	MESSAGE request = message_create_named (NAME_MSGNAME_M2RAW_GETCONTENTBYPATH);
	message_add_url (request, url);
	gboolean rc = metaXClient_reply_sequence_run_context (err, ctx, request, &data);
	if (!rc)
		GSETERROR(err,"Cannot execute the query and receive all the responses");
	message_destroy(request);
	return result;
}

static struct meta2_raw_content_s*
meta2raw_remote_stat_content(struct metacnx_ctx_s *ctx, GError **err,
		struct hc_url_s *url, gboolean check_flags)
{
	static struct code_handler_s codes [] = {
		{ CODE_FINAL_OK, REPSEQ_FINAL|REPSEQ_BODYMANDATORY, concat_contents, NULL },
		{ CODE_PARTIAL_CONTENT, REPSEQ_BODYMANDATORY, concat_contents, NULL },
		{ 0,0,NULL,NULL}
	};
	struct meta2_raw_content_s *result=NULL;
	struct reply_sequence_data_s data = { &result , 0 , codes };

	EXTRA_ASSERT (ctx != NULL);
	EXTRA_ASSERT (url != NULL);
	MESSAGE request = message_create_named (NAME_MSGNAME_M2RAW_GETCHUNKS);
	message_add_url (request, url);
	if (check_flags)
		message_add_field_str (request, NAME_MSGKEY_CHECK, "1");
	gboolean rc = metaXClient_reply_sequence_run_context (err, ctx, request, &data);
	if (!rc)
		GSETERROR(err,"Cannot execute the query and receive all the responses");
	message_destroy(request);
	return result;
}

struct meta2_raw_content_s*
meta2_remote_stat_content(struct metacnx_ctx_s *cnx, GError **err,
		struct hc_url_s *url)
{
	return meta2raw_remote_stat_content(cnx, err, url, FALSE);
}

gboolean
meta2_remote_touch_content(struct metacnx_ctx_s *ctx, GError **err, struct hc_url_s *url)
{
	static struct code_handler_s codes [] = {
		{ CODE_FINAL_OK, REPSEQ_FINAL,         NULL, NULL },
		{ 0,0,NULL,NULL}
	};
	struct reply_sequence_data_s data = { NULL , 0 , codes };

	EXTRA_ASSERT (ctx != NULL);
	EXTRA_ASSERT (url != NULL);
	MESSAGE request = message_create_named(NAME_MSGNAME_M2V1_TOUCH_CONTENT);
	message_add_url (request, url);
	gboolean rc = metaXClient_reply_sequence_run_context (err, ctx, request, &data);
	if (!rc)
		GSETERROR(err,"Cannot execute the query and receive all the responses");
	message_destroy(request);
	return rc;
}

gboolean
meta2_remote_touch_container_ex(struct metacnx_ctx_s *ctx, GError **err,
		struct hc_url_s *url, unsigned int flags)
{
	static struct code_handler_s codes [] = {
		{ CODE_FINAL_OK, REPSEQ_FINAL, NULL, NULL },
		{ 0,0,NULL,NULL}
	};
	struct reply_sequence_data_s data = { NULL , 0 , codes };
	
	EXTRA_ASSERT (ctx != NULL);
	EXTRA_ASSERT (url != NULL);
	MESSAGE request = message_create_named(NAME_MSGNAME_M2V1_TOUCH_CONTAINER);
	message_add_url (request, url);
	if (flags) {
		flags = g_htonl(flags);
	    message_add_field (request, NAME_MSGKEY_FLAGS, &flags, sizeof(flags));
	}
	gboolean rc = metaXClient_reply_sequence_run_context (err, ctx, request, &data);
	if (!rc)
		GSETERROR(err,"Cannot execute the query and receive all the responses");
	message_destroy(request);
	return rc;
}

static gboolean
msg_manager_stat_content_v2(GError ** err, gpointer udata, gint code, MESSAGE rep)
{
	(void) code;
	struct arg_stat_content_v2_s **out = udata;
	EXTRA_ASSERT (udata != NULL);
	EXTRA_ASSERT (rep != NULL);

	GSList *l = NULL;
	GError *e = message_extract_body_encoded (rep, FALSE, &l, meta2_raw_content_v2_unmarshall);
	if (e) {
		g_slist_foreach (l, meta2_raw_content_v2_gclean, NULL);
		g_slist_free (l);
		GSETCODE(err, CODE_BAD_REQUEST, "The body cannot be decoded"); 
		return FALSE;
	}
	
	if (l && !*out) {
		*out = l->data;
		l->data = NULL;
	}
	return TRUE;
}

gboolean
meta2_remote_stat_content_v2(struct metacnx_ctx_s *ctx, GError **err,
		struct hc_url_s *url, meta2_raw_content_v2_t **result)
{
	static struct code_handler_s codes [] = {
		{ CODE_FINAL_OK, REPSEQ_FINAL, NULL, msg_manager_stat_content_v2 },
		{ CODE_PARTIAL_CONTENT, REPSEQ_BODYMANDATORY, NULL, msg_manager_stat_content_v2 },
		{ 0,0,NULL,NULL}
	};
	struct reply_sequence_data_s data = { result , 0 , codes };

	EXTRA_ASSERT (ctx != NULL);
	EXTRA_ASSERT (url != NULL);

	MESSAGE request = message_create_named(NAME_MSGNAME_M2V1_STAT);
	message_add_url (request, url);
	gboolean rc = metaXClient_reply_sequence_run_context (err, ctx, request, &data);
	if (!rc)
		GSETERROR(err,"Cannot execute the query and receive all the responses");
	message_destroy(request);
	return rc;
}

gboolean
meta2_remote_modify_metadatasys(struct metacnx_ctx_s *ctx, GError **err,
		struct hc_url_s *url, const gchar* var_2)
{
	static struct code_handler_s codes [] = {
		{ CODE_FINAL_OK, REPSEQ_FINAL, NULL, NULL },
		{ 0,0,NULL,NULL}
	};
	struct reply_sequence_data_s data = { NULL , 0 , codes };

	EXTRA_ASSERT (ctx != NULL);
	EXTRA_ASSERT (url != NULL);
	EXTRA_ASSERT (var_2 != NULL);

	MESSAGE request = message_create_named(NAME_MSGNAME_M2RAW_SETMDSYS);
	message_add_url (request, url);
	message_add_field_str (request, NAME_MSGKEY_VALUE, var_2);
	gboolean rc = metaXClient_reply_sequence_run_context (err, ctx, request, &data);
	if (!rc)
		GSETERROR(err,"Cannot execute the query and receive all the responses");
	message_destroy(request);
	return rc;
}

