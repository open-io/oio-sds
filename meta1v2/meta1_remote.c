/*
OpenIO SDS meta1v2
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
# define G_LOG_DOMAIN "meta1.remote"
#endif

#include <metautils/lib/metautils.h>

#include "./internals.h"
#include "./meta1_remote.h"

static gboolean
kv_handler_list (GError **err, gpointer udata, gint code,
		guint8 *body, gsize bodySize)
{
	(void) code;
	GSList *list = NULL;
	GHashTable **ppResL = NULL;
	GHashTable *table = NULL;
	gboolean status = FALSE;

	if (!udata) {
		GSETERROR(err,"Invalid parameter (%p)", udata);
		return status;
	}

	if(code == CODE_FINAL_OK && (!body || bodySize <= 0)) {
		GSETERROR(err,"Invalid parameter (%p, %p)", body, bodySize);
		return status;
	}

	ppResL = (GHashTable**) udata;
	if (!ppResL) {
		GSETERROR(err,"invalid parameter");
		return status;
	}

	if(code == CODE_FINAL_OK) {
		DEBUG("Code = %u, unmarshalling", CODE_FINAL_OK);
		if (0 >= key_value_pairs_unmarshall(&list, body, &bodySize, err)) {
			GSETERROR (err, "Cannot unserialize the content of the reply");
			goto errorLabel;
		}

		table = key_value_pairs_convert_to_map(list, err);
		if (!table) {
			GSETERROR (err, "Cannot unserialize the content of the reply");
			goto errorLabel;
		}

		DEBUG("Response body parsed, %d elements", g_hash_table_size(table));

		*ppResL = table;
	}
	status = TRUE;

errorLabel:
	g_slist_free_full(list, (GDestroyNotify) key_value_pair_clean);
	return status;
}

static void
meta1_container_request_common_v2 (MESSAGE m, const gchar *op, const container_id_t id,
		const gchar *name, const gchar *virtual_namespace)
{
	gsize nameSize;
	gsize virtualNsSize;

	g_assert(m != NULL);

	nameSize = name ? strlen(name) : 0;
	virtualNsSize = virtual_namespace ? strlen(virtual_namespace) : 0;
	message_set_NAME (m, op, strlen(op), NULL);

	if (id!=NULL || name!=NULL) {
		container_id_t usedID;
		if (id)
			memcpy(usedID, id, sizeof(container_id_t));
		else
			meta1_name2hash(usedID, virtual_namespace, name);
		message_add_field (m, NAME_MSGKEY_CONTAINERID, usedID, sizeof(container_id_t));
	}

	if (name && nameSize>0)
		message_add_field (m, NAME_MSGKEY_CONTAINERNAME, name, nameSize);

	if (virtual_namespace && virtualNsSize>0)
		message_add_field (m, NAME_MSGKEY_VIRTUALNAMESPACE, virtual_namespace, virtualNsSize);
}

static void
meta1_container_request_common (MESSAGE m, const gchar *op, const container_id_t id,
		const gchar *name)
{
	return meta1_container_request_common_v2(m, op, id, name, NULL);
}

/* M1V1 -------------------------------------------------------------------- */

gboolean 
meta1_remote_create_container_v2 (addr_info_t *meta1, gint ms, GError **err, const char *cName, const char *virtualNs,
		container_id_t cID, gdouble to_step, gdouble to_overall, gchar **master)
{
	(void) ms;
	struct client_s *client = NULL;
	GByteArray *packed = NULL;
	MESSAGE request=NULL;
	gboolean status = FALSE;
	gchar target[64];

	request = message_create();

	meta1_container_request_common_v2 (request, NAME_MSGNAME_M1_CREATE, cID, cName, virtualNs);

	addr_info_to_string(meta1, target, sizeof(target));
	packed = message_marshall_gba(request, NULL);
	client = gridd_client_create(target, packed, NULL, NULL);

	if(to_step > 0 && to_overall > 0)
		gridd_client_set_timeout(client, to_step, to_overall);

	gridd_client_start(client);
	if ((*err = gridd_client_loop(client)) != NULL)
		goto end_label;

	if (g_ascii_strcasecmp(target, gridd_client_url(client)) && NULL != master)
		*master = g_strdup(gridd_client_url(client));

	if((*err = gridd_client_error(client)) != NULL)
		goto end_label;

	status = TRUE;

end_label:
	message_destroy(request);
	if (packed)
		g_byte_array_unref(packed);
	gridd_client_free(client);
	return status;
}

struct meta1_raw_container_s* 
meta1_remote_get_container_by_id( struct metacnx_ctx_s *ctx, container_id_t container_id, GError **err,
		gdouble to_step, gdouble to_overall)
{
	struct meta1_raw_container_s *raw_container = NULL;
	struct client_s *client = NULL;
	GByteArray *packed = NULL;
	gchar target[64];

	gboolean on_reply(gpointer c1, MESSAGE reply) {
		void *b = NULL;
		gsize bsize = 0;
		(void) c1;
		if (0 < message_get_BODY(reply, &b, &bsize, NULL)) {
			raw_container = meta1_raw_container_unmarshall(b, bsize, err);
		}
		return TRUE;
	}

	if (!ctx || !container_id) {
		GSETERROR(err,"Invalid parameter (%p %p)", ctx, container_id);
		goto end_label;
	}

	MESSAGE request = message_create ();
	meta1_container_request_common (request, NAME_MSGNAME_M1_CONT_BY_ID, container_id, NULL);

	addr_info_to_string(&(ctx->addr), target, sizeof(target));
	packed = message_marshall_gba(request, NULL);
	client = gridd_client_create(target, packed, NULL, on_reply);

	if (to_step > 0 && to_overall > 0)
		gridd_client_set_timeout(client, to_step, to_overall);
	gridd_client_start(client);
	if ((*err = gridd_client_loop(client)) != NULL)
		goto end_label;

	do{
		struct client_s *clients[2];
		clients[0] = client;
		clients[1] = NULL;
		if((*err = gridd_clients_error(clients)) != NULL)
			goto end_label;
	} while(0);

end_label:
	message_destroy(request);
	g_byte_array_unref(packed);
	gridd_client_free(client);
	return(raw_container);
}

gboolean
meta1_remote_update_containers(gchar *meta1_addr_str, GSList *list_of_containers,
		gint ms, GError **err)
{
	(void) ms;

	gboolean status = FALSE;
	GByteArray *gba = NULL;
	struct client_s *client;
	GError *e = NULL;

	if (!meta1_addr_str || !list_of_containers) {
		GSETCODE(err, EINVAL, "Invalid parameter (%p %p)", meta1_addr_str, list_of_containers);
		return FALSE;
	}

	do {
		void *body = NULL;
		gsize bodySize = 0;
		MESSAGE request = message_create ();
		meta1_container_request_common (request, NAME_MSGNAME_M1_UPDATE_CONTAINERS, NULL, NULL);
		container_info_marshall(list_of_containers, &body, &bodySize, NULL);
		message_set_BODY(request, body, bodySize, NULL);
		gba = message_marshall_gba_and_clean(request);
	} while (0);

	client = gridd_client_create_idle(meta1_addr_str);
	if(!client) {
		e = NEWERROR(2, "errno=%d %s", errno, strerror(errno));
	} else {
		gridd_client_start(client);
		e = gridd_client_request(client, gba, NULL, NULL);
		if(!e){
			if(!(e = gridd_client_loop(client)))
				e = gridd_client_error(client);
			if (!e)
				status = TRUE;
		}
		gridd_client_free(client);
	}

	*err = e;
	g_byte_array_free(gba, TRUE);
	return status;
}

GHashTable*
meta1_remote_get_virtual_ns_state(addr_info_t *meta1, gint ms, GError **err)
{
	static struct code_handler_s codes [] = {
		{ CODE_TEMPORARY, 0, NULL, NULL },
		{ CODE_FINAL_OK, REPSEQ_FINAL, &kv_handler_list, NULL },
		{ CODE_PARTIAL_CONTENT, REPSEQ_FINAL, &kv_handler_list, NULL },
		{ 0, 0, NULL, NULL },
	};

	GHashTable *result = NULL;
	struct reply_sequence_data_s data = { &result , 0 , codes };

	MESSAGE request = message_create ();
	meta1_container_request_common (request, NAME_MSGNAME_M1_GET_VNS_STATE, NULL, NULL);
	if (!metaXClient_reply_sequence_run_from_addrinfo (err, request, meta1, ms, &data))
		GSETERROR(err, "An error occured while executing the VIRTUAL_NS_STATE request");
	message_destroy(request);
	return result;
}

/* M1V2 -------------------------------------------------------------------- */

static gboolean
on_reply(gpointer ctx, MESSAGE reply)
{
	GByteArray *out = ctx;
	void *b = NULL;
	gsize bsize = 0;

	if (0 < message_get_BODY(reply, &b, &bsize, NULL)) {
		if (out != NULL)
			g_byte_array_append(out, b, bsize);
	}

	g_byte_array_append(out, (const guint8*)"", 1);
	g_byte_array_set_size(out, out->len - 1);
	return TRUE;
}

static gchar **
list_request(const addr_info_t *a, gdouble to_step, gdouble to_overall, GError **err, GByteArray *req,
		gchar **master)
{
	gchar stra[128];
	struct client_s *client = NULL;
	GByteArray *gba;
	GError *e = NULL;

	EXTRA_ASSERT(a != NULL);
	EXTRA_ASSERT(req != NULL);
	GRID_TRACE2("%s:%d", __FUNCTION__, __LINE__);

	gba = g_byte_array_new();
	grid_addrinfo_to_string(a, stra, sizeof(stra));
	client = gridd_client_create(stra, req, gba, on_reply);

	if(to_step > 0 && to_overall > 0)
		gridd_client_set_timeout(client, to_step, to_overall);

	gscstat_tags_start(GSCSTAT_SERVICE_META1, GSCSTAT_TAGS_REQPROCTIME);
	gridd_client_start(client);
	if (!(e = gridd_client_loop(client)))
		e = gridd_client_error(client);
	gscstat_tags_end(GSCSTAT_SERVICE_META1, GSCSTAT_TAGS_REQPROCTIME);

	/* in RO request, we don't need this information */
	if(NULL != master) {
		char tmp[64];
		bzero(tmp, sizeof(tmp));
		addr_info_to_string(a, tmp, sizeof(tmp));

		if(g_ascii_strcasecmp(tmp, gridd_client_url(client)))
			*master = g_strdup(gridd_client_url(client));
	}

	gridd_client_free(client);

	if (e) {
		if (err)
			*err = e;
		else
			g_clear_error(&e);
		g_byte_array_free(gba, TRUE);
		return NULL;
	}

	gchar **lines = metautils_decode_lines((gchar*)gba->data,
			(gchar*)(gba->data + gba->len));
	if (!lines && err)
		*err = NEWERROR(CODE_BAD_REQUEST, "Invalid buffer content");
	g_byte_array_free(gba, TRUE);
	return lines;
}

gboolean 
meta1v2_remote_create_reference (const addr_info_t *meta1, GError **err,
		const char *ns, const container_id_t refid, const gchar *refname,
		gdouble to_step, gdouble to_overall, gchar **master)
{
	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refid != NULL);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_CREATE,
			NULL,
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"CONTAINER_ID", gba_poolify(&pool, metautils_gba_from_cid(refid)),
			"CONTAINER_NAME", gba_poolify(&pool, metautils_gba_from_string(refname)),
			NULL);
	gchar **result = list_request(meta1, to_step, to_overall, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), master);
	message_destroy(req);
	gba_pool_clean(&pool);

	if (!result)
		return FALSE;
	g_strfreev(result);
	return TRUE;
}

gboolean
meta1v2_remote_has_reference (const addr_info_t *meta1, GError **err,
		const char *ns, const container_id_t refid, gdouble to_step, gdouble to_overall)
{
	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refid != NULL);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_HAS,
			NULL,
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"CONTAINER_ID", gba_poolify(&pool, metautils_gba_from_cid(refid)),
			NULL);
	gchar **result = list_request(meta1, to_step, to_overall, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), NULL);
	message_destroy(req);
	gba_pool_clean(&pool);

	if (!result)
		return FALSE;
	g_strfreev(result);
	return TRUE;
}

gboolean 
meta1v2_remote_delete_reference (const addr_info_t *meta1, GError **err,
		const char *ns, const container_id_t refid, gdouble to_step, gdouble to_overall,
		char **master)
{
	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refid != NULL);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_DESTROY,
			NULL,
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"CONTAINER_ID", gba_poolify(&pool, metautils_gba_from_cid(refid)),
			NULL);
	gchar **result = list_request(meta1, to_step, to_overall, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), master);
	message_destroy(req);
	gba_pool_clean(&pool);

	if (!result)
		return FALSE;
	g_strfreev(result);
	return TRUE;
}

gchar** 
meta1v2_remote_link_service(const addr_info_t *meta1, GError **err, const char *ns, const container_id_t refID,
		const gchar *srvtype, gdouble to_step, gdouble to_overall, char **master)
{
	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refID != NULL);
	EXTRA_ASSERT(srvtype != NULL);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_SRVAVAIL,
			NULL,
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"CONTAINER_ID", gba_poolify(&pool, metautils_gba_from_cid(refID)),
			"SRVTYPE", gba_poolify(&pool, metautils_gba_from_string(srvtype)),
			NULL);
	gchar **result = list_request(meta1, to_step, to_overall, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), master);
	message_destroy(req);
	gba_pool_clean(&pool);

	return result;
}

gchar**
meta1v2_remote_list_reference_services(const addr_info_t *meta1, GError **err, const char *ns, const container_id_t refid,
		const gchar *srvtype, gdouble to_step, gdouble to_overall)
{
	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refid != NULL);
	GRID_TRACE2("%s:%d", __FUNCTION__, __LINE__);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_SRVALL,
			NULL,
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"CONTAINER_ID", gba_poolify(&pool, metautils_gba_from_cid(refid)),
			"SRVTYPE", gba_poolify(&pool, metautils_gba_from_string(srvtype)),
			NULL);
	gchar **result = list_request(meta1, to_step, to_overall, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), NULL);

	message_destroy(req);
	gba_pool_clean(&pool);

	return result;
}

gboolean 
meta1v2_remote_unlink_service(const addr_info_t *meta1, GError **err,
		const char *ns, const container_id_t refid, const gchar *srvtype
		, gdouble to_step, gdouble to_overall, char **master)
{
	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refid != NULL);
	EXTRA_ASSERT(srvtype != NULL);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_SRVDEL,
			NULL,
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"CONTAINER_ID", gba_poolify(&pool, metautils_gba_from_cid(refid)),
			"SRVTYPE", gba_poolify(&pool, metautils_gba_from_string(srvtype)),
			NULL);
	gchar **result = list_request(meta1, to_step, to_overall, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), master);
	message_destroy(req);
	gba_pool_clean(&pool);

	if (!result)
		return FALSE;
	g_strfreev(result);
	return TRUE;
}

gboolean meta1v2_remote_unlink_one_service(const addr_info_t *meta1,
		GError **err, const char *ns, const container_id_t refid,
		const gchar *srvtype , gdouble to_step, gdouble to_overall,
		char **master, gint64 seqid)
{
	GSList *pool = NULL;
	GByteArray *body = NULL;

	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refid != NULL);
	EXTRA_ASSERT(srvtype != NULL);

	body = gba_poolify(&pool, g_byte_array_new());

	if (seqid <= 0) {
		if (err)
			*err = NEWERROR(CODE_BAD_REQUEST, "Invalid sequence number [%"G_GINT64_FORMAT"]", seqid);
		gba_pool_clean(&pool);
		return FALSE;
	}
	else {
		gchar str[128];
		g_snprintf(str, sizeof(str), "%"G_GINT64_FORMAT"\n", seqid);
		g_byte_array_append(body, (guint8*)str, strlen(str));
		GRID_DEBUG("About to delete seqid=%s", str);
	}

	if (body->len <= 0) {
		if (err)
			*err = NEWERROR(CODE_BAD_REQUEST, "No sequence number provided");
		gba_pool_clean(&pool);
		return FALSE;
	}

	MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_SRVDEL,
			body,
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"CONTAINER_ID", gba_poolify(&pool, metautils_gba_from_cid(refid)),
			"SRVTYPE", gba_poolify(&pool, metautils_gba_from_string(srvtype)),
			NULL);
	gchar **result = list_request(meta1, to_step, to_overall, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), master);
	message_destroy(req);
	gba_pool_clean(&pool);

	if (!result)
		return FALSE;
	g_strfreev(result);
	return TRUE;
}

gchar **
meta1v2_remote_poll_reference_service(const addr_info_t *meta1,
		GError **err, const char *ns, const container_id_t refid,
		const gchar *srvtype, gdouble to_step, gdouble to_overall, char **master)
{
	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refid != NULL);
	EXTRA_ASSERT(srvtype != NULL);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_SRVNEW,
			NULL,
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"CONTAINER_ID", gba_poolify(&pool, metautils_gba_from_cid(refid)),
			"SRVTYPE", gba_poolify(&pool, metautils_gba_from_string(srvtype)),
			NULL);
	gchar **result = list_request(meta1, to_step, to_overall, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), master);

	message_destroy(req);
	gba_pool_clean(&pool);
	return result;
}

gchar **
meta1v2_remote_update_m1_policy(const addr_info_t *meta1,
                GError **err, const char *ns,  const container_id_t prefix, const container_id_t refid,
                const gchar *srvtype, const gchar* action, gboolean checkonly, const gchar *excludeurl, gdouble to_step, gdouble to_overall)
{
	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(srvtype != NULL);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_UPDATEM1POLICY,
			NULL,
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"SRVTYPE", gba_poolify(&pool, metautils_gba_from_string(srvtype)),
			"ACTION", gba_poolify(&pool, metautils_gba_from_string(action)),
			NULL);

	if (prefix)
		message_add_fields_gba(req,"PREFIX",gba_poolify(&pool,metautils_gba_from_cid(prefix)),NULL);
	if (refid)
		message_add_fields_gba(req,"CONTAINER_ID",gba_poolify(&pool,metautils_gba_from_cid(refid)),NULL);
	if (checkonly)
		message_add_field( req,"CHECKONLY", "true", sizeof("true")-1);
	if( excludeurl )
		message_add_fields_gba(req,"EXCLUDEURL",gba_poolify(&pool,metautils_gba_from_string(excludeurl)),NULL);

	gchar **result = list_request(meta1, to_step, to_overall, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), NULL);
	message_destroy(req);
	gba_pool_clean(&pool);
	return result;
}

gboolean
meta1v2_remote_force_reference_service(const addr_info_t *meta1,
		GError **err, const char *ns, const container_id_t refid,
		const gchar *url, gdouble to_step, gdouble to_overall, char **master)
{
	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refid != NULL);
	EXTRA_ASSERT(url != NULL);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_SRVSET,
			gba_poolify(&pool, metautils_gba_from_string(url)),
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"CONTAINER_ID", gba_poolify(&pool, metautils_gba_from_cid(refid)),
			NULL);
	gchar **result = list_request(meta1, to_step, to_overall, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), master);
	message_destroy(req);
	gba_pool_clean(&pool);

	if (!result)
		return FALSE;
	g_strfreev(result);
	return TRUE;
}

gboolean
meta1v2_remote_configure_reference_service(const addr_info_t *meta1,
		GError **err, const char *ns, const container_id_t refid,
		const gchar *url, gdouble to_step, gdouble to_overall, char **master)
{
	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refid != NULL);
	EXTRA_ASSERT(url != NULL);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_SRVSETARG,
			gba_poolify(&pool, metautils_gba_from_string(url)),
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"CONTAINER_ID", gba_poolify(&pool, metautils_gba_from_cid(refid)),
			NULL);
	gchar **result = list_request(meta1, to_step, to_overall, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), master);
	message_destroy(req);
	gba_pool_clean(&pool);

	if (!result)
		return FALSE;
	g_strfreev(result);
	return TRUE;
}

gboolean
meta1v2_remote_reference_set_property(const addr_info_t *m1, GError **err,
		const gchar *ns, const container_id_t refid, gchar **pairs,
		gdouble to_step, gdouble to_overall, char **master)
{
	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refid != NULL);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_CID_PROPSET,
			gba_poolify(&pool, metautils_encode_lines(pairs)),
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"CONTAINER_ID", gba_poolify(&pool, metautils_gba_from_cid(refid)),
			NULL);
	gchar **result = list_request(m1, to_step, to_overall, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), master);
	message_destroy(req);
	gba_pool_clean(&pool);

	if (!result)
		return FALSE;
	g_strfreev(result);
	return TRUE;
}

gboolean
meta1v2_remote_reference_get_property(const addr_info_t *m1, GError **err,
		const gchar *ns, const container_id_t refid,
		gchar **keys, gchar ***result, gdouble to_step, gdouble to_overall)
{
	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refid != NULL);
	EXTRA_ASSERT(result != NULL);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_CID_PROPGET,
			gba_poolify(&pool, metautils_encode_lines(keys)),
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"CONTAINER_ID", gba_poolify(&pool, metautils_gba_from_cid(refid)),
			NULL);
	*result = list_request(m1, to_step, to_overall, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), NULL);
	message_destroy(req);
	gba_pool_clean(&pool);

	return *result != NULL;
}

gboolean
meta1v2_remote_reference_del_property(const addr_info_t *m1, GError **err,
		const gchar *ns, const container_id_t refid,
		gchar **keys, gdouble to_step, gdouble to_overall, char **master)
{
	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refid != NULL);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_CID_PROPDEL,
			gba_poolify(&pool, metautils_encode_lines(keys)),
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"CONTAINER_ID", gba_poolify(&pool, metautils_gba_from_cid(refid)),
			NULL);
	gchar **result = list_request(m1, to_step, to_overall, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), master);
	message_destroy(req);
	gba_pool_clean(&pool);

	if (!result)
		return FALSE;
	g_strfreev(result);
	return TRUE;
}

static GError *
gba_request(const addr_info_t *a, gdouble to_step, gdouble to_overall,
		GByteArray **result, GByteArray *req)
{
	gboolean _reply(gpointer ctx, MESSAGE reply) {
		void *b = NULL;
		gsize bsize = 0;
		if (0 < message_get_BODY(reply, &b, &bsize, NULL)) {
			if (b && bsize)
				g_byte_array_append((GByteArray*)ctx, b, bsize);
		}
		return TRUE;
	}

	gchar stra[128];
	struct client_s *client = NULL;
	GError *e = NULL;
	gboolean gba_created = FALSE;

	EXTRA_ASSERT(req != NULL);

	grid_addrinfo_to_string(a, stra, sizeof(stra));
	if (!*result) {
		*result = g_byte_array_new();
		gba_created = TRUE;
	}
	client = gridd_client_create(stra, req, *result, _reply);

	if (to_step > 0 && to_overall > 0)
		gridd_client_set_timeout(client, to_step, to_overall);

	gscstat_tags_start(GSCSTAT_SERVICE_META1, GSCSTAT_TAGS_REQPROCTIME);
	gridd_client_start(client);
	if (!(e = gridd_client_loop(client)))
		e = gridd_client_error(client);
	gscstat_tags_end(GSCSTAT_SERVICE_META1, GSCSTAT_TAGS_REQPROCTIME);

	gridd_client_free(client);

	if (!e)
		return NULL;

	if (gba_created) {
		g_byte_array_free(*result, TRUE);
		*result = NULL;
	}
	return e;
}

gchar**
meta1v2_remote_list_services(const addr_info_t *m1, GError **err,
        const gchar *ns, const container_id_t refid  )
{

    EXTRA_ASSERT(m1 != NULL);
    EXTRA_ASSERT(ns != NULL);
    EXTRA_ASSERT(refid != NULL);

    GSList *pool = NULL;
    MESSAGE req = message_create_request(NULL, NULL,
            NAME_MSGNAME_M1V2_SRVALLONM1, NULL /* no body */,
            "NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
            "PREFIX", gba_poolify(&pool, metautils_gba_from_cid(refid)),
            NULL);

    gchar** result = list_request(m1,  60000, 60000, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), NULL);

    message_destroy(req);
    gba_pool_clean(&pool);
    return result;
}

GError *
meta1v2_remote_list_references(const addr_info_t *m1,
		const gchar *ns, const container_id_t refid,
		GByteArray **result)
{
	GError *err;

	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refid != NULL);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL,
			NAME_MSGNAME_M1V2_LISTBYPREF, NULL /* no body */,
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"PREFIX", gba_poolify(&pool, metautils_gba_from_cid(refid)),
			NULL);

	err = gba_request(m1, 60000, 60000, result,
			gba_poolify(&pool, message_marshall_gba(req, NULL)));

	message_destroy(req);
	gba_pool_clean(&pool);
	return err;
}

GError *
meta1v2_remote_list_references_by_service(const addr_info_t *m1,
		const gchar *ns, const container_id_t refid,
		const gchar *srvtype, const gchar *url,
		GByteArray **result)
{
	GError *err;

	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refid != NULL);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL,
			NAME_MSGNAME_M1V2_LISTBYSERV, NULL /* no body */,
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"PREFIX", gba_poolify(&pool, metautils_gba_from_cid(refid)),
			"SRVTYPE", gba_poolify(&pool, metautils_gba_from_string(srvtype)),
			"URL", gba_poolify(&pool, metautils_gba_from_string(url)),
			NULL);

	err = gba_request(m1, 60000, 60000, result,
			gba_poolify(&pool, message_marshall_gba(req, NULL)));

	message_destroy(req);
	gba_pool_clean(&pool);
	return err;
}

gboolean
meta1v2_remote_get_prefixes(const addr_info_t *m1, GError **err,
		gchar *** result)
{
	EXTRA_ASSERT(m1 != NULL);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_GETPREFIX,
			NULL,
			NULL);
	*result = list_request(m1, 60000, 60000, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), NULL);
	message_destroy(req);
	gba_pool_clean(&pool);

	return *result != NULL;
}

