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

/* M1V1 -------------------------------------------------------------------- */

// TODO remove this as soon as the hunk_checker has been replaced
gboolean 
meta1_remote_create_container_v2 (addr_info_t *meta1, GError **err,
		struct hc_url_s *url)
{
	EXTRA_ASSERT (meta1 != NULL);
	EXTRA_ASSERT (url != NULL);
	EXTRA_ASSERT (err != NULL);

	MESSAGE request = message_create_named(NAME_MSGNAME_M1_CREATE);
	message_add_url (request, url);
	GByteArray *packed = message_marshall_gba_and_clean(request);

	gchar target[64];
	addr_info_to_string(meta1, target, sizeof(target));
	struct gridd_client_s *client = gridd_client_create(target, packed, NULL, NULL);
	g_byte_array_unref(packed);

	gboolean status = FALSE;
	gridd_client_start(client);
	if (!(*err = gridd_client_loop(client)))
		if (!(*err = gridd_client_error(client)))
			status = TRUE;

	gridd_client_free(client);
	return status;
}

// TODO to be removed as soon ad the C SDK has been rewriten
struct meta1_raw_container_s* 
meta1_remote_get_container_by_id (struct metacnx_ctx_s *ctx, struct hc_url_s *url, GError **err)
{
	EXTRA_ASSERT (ctx != NULL);
	EXTRA_ASSERT (url != NULL);
	EXTRA_ASSERT (err != NULL);

	struct meta1_raw_container_s *raw_container = NULL;
	struct gridd_client_s *client = NULL;

	gboolean on_reply(gpointer c1, MESSAGE reply) {
		void *b = NULL;
		gsize bsize = 0;
		(void) c1;
		if (0 < message_get_BODY(reply, &b, &bsize, NULL)) {
			raw_container = meta1_raw_container_unmarshall(b, bsize, err);
		}
		return TRUE;
	}


	MESSAGE request = message_create_named (NAME_MSGNAME_M1_CONT_BY_ID);
	message_add_url (request, url);
	GByteArray *packed = message_marshall_gba_and_clean(request);

	gchar target[64];
	addr_info_to_string(&(ctx->addr), target, sizeof(target));
	client = gridd_client_create(target, packed, NULL, on_reply);

	gridd_client_start(client);
	if ((*err = gridd_client_loop(client)) != NULL)
		goto end_label;

	do{
		struct gridd_client_s *clients[2];
		clients[0] = client;
		clients[1] = NULL;
		if((*err = gridd_clients_error(clients)) != NULL)
			goto end_label;
	} while(0);

end_label:
	g_byte_array_unref(packed);
	gridd_client_free(client);
	return(raw_container);
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
list_request(const addr_info_t *a, GError **err, GByteArray *req)
{
	gchar stra[128];
	struct gridd_client_s *client = NULL;
	GByteArray *gba;
	GError *e = NULL;

	EXTRA_ASSERT(a != NULL);
	EXTRA_ASSERT(req != NULL);

	gba = g_byte_array_new();
	grid_addrinfo_to_string(a, stra, sizeof(stra));
	client = gridd_client_create(stra, req, gba, on_reply);
	g_byte_array_unref (req);

	gridd_client_start(client);
	if (!(e = gridd_client_loop(client)))
		e = gridd_client_error(client);

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

static gboolean
oneway_request (const addr_info_t *a, GError **err, GByteArray *req)
{
	gchar ** result = list_request (a, err, req);
	if (!result)
		return FALSE;
	g_strfreev(result);
	return TRUE;
}

static GError *
gba_request(const addr_info_t *a, GByteArray **result, GByteArray *req)
{
	gchar str[STRLEN_ADDRINFO];
	addr_info_to_string (a, str, sizeof(str));
	GError *err = gridd_client_exec_and_concat (str, M1V2_CLIENT_TIMEOUT, req, result);
	g_byte_array_unref (req);
	return err;
}

/* ------------------------------------------------------------------------- */

gboolean 
meta1v2_remote_create_reference (const addr_info_t *meta1, GError **err,
		struct hc_url_s *url)
{
	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(url != NULL);

	MESSAGE req = message_create_named(NAME_MSGNAME_M1V2_CREATE);
	message_add_url (req, url);
	return oneway_request(meta1, err, message_marshall_gba_and_clean(req));
}

gboolean
meta1v2_remote_has_reference (const addr_info_t *meta1, GError **err,
		struct hc_url_s *url)
{
	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(url != NULL);

	MESSAGE req = message_create_named(NAME_MSGNAME_M1V2_HAS);
	message_add_url (req, url);
	return oneway_request(meta1, err, message_marshall_gba_and_clean(req));
}

gboolean 
meta1v2_remote_delete_reference (const addr_info_t *meta1, GError **err,
		struct hc_url_s *url)
{
	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(url != NULL);

	MESSAGE req = message_create_named(NAME_MSGNAME_M1V2_DESTROY);
	message_add_url (req, url);
	return oneway_request(meta1, err, message_marshall_gba_and_clean(req));
}

gchar** 
meta1v2_remote_link_service(const addr_info_t *meta1, GError **err,
		struct hc_url_s *url, const gchar *srvtype)
{
	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(srvtype != NULL);

	MESSAGE req = message_create_named(NAME_MSGNAME_M1V2_SRVAVAIL);
	message_add_url (req, url);
	message_add_field_str (req, NAME_MSGKEY_SRVTYPE, srvtype);

	return list_request(meta1, err, message_marshall_gba_and_clean(req));
}

gchar**
meta1v2_remote_list_reference_services(const addr_info_t *meta1, GError **err,
		struct hc_url_s *url, const gchar *srvtype)
{
	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(url != NULL);

	MESSAGE req = message_create_named(NAME_MSGNAME_M1V2_SRVALL);
	message_add_url (req, url);
	if (srvtype)
		message_add_field_str (req, NAME_MSGKEY_SRVTYPE, srvtype);

	return list_request(meta1, err, message_marshall_gba_and_clean(req));
}

gboolean 
meta1v2_remote_unlink_service(const addr_info_t *meta1, GError **err,
		struct hc_url_s *url, const gchar *srvtype)
{
	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(srvtype != NULL);

	MESSAGE req = message_create_named(NAME_MSGNAME_M1V2_SRVDEL);
	message_add_url (req, url);
	message_add_field_str (req, NAME_MSGKEY_SRVTYPE, srvtype);
	return oneway_request(meta1, err, message_marshall_gba_and_clean(req));
}

gboolean
meta1v2_remote_unlink_one_service(const addr_info_t *meta1, GError **err,
		struct hc_url_s *url, const gchar *srvtype, gint64 seqid)
{
	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(srvtype != NULL);

	MESSAGE req = message_create_named(NAME_MSGNAME_M1V2_SRVDEL);
	message_add_field_str (req, NAME_MSGKEY_SRVTYPE, srvtype);
	if (seqid > 0) {
		gchar str[32];
		g_snprintf(str, sizeof(str), "%"G_GINT64_FORMAT"\n", seqid);
		message_add_body_unref (req, metautils_gba_from_string (str));
	}

	return oneway_request(meta1, err, message_marshall_gba_and_clean(req));
}

gchar **
meta1v2_remote_poll_reference_service(const addr_info_t *meta1, GError **err,
		struct hc_url_s *url, const gchar *srvtype)
{
	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(srvtype != NULL);

	MESSAGE req = message_create_named(NAME_MSGNAME_M1V2_SRVNEW);
	message_add_url (req, url);
	message_add_field_str (req, NAME_MSGKEY_SRVTYPE, srvtype);

	return list_request(meta1, err, message_marshall_gba_and_clean(req));
}

gboolean
meta1v2_remote_force_reference_service(const addr_info_t *meta1, GError **err,
		struct hc_url_s *url, const gchar *m1url)
{
	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(m1url != NULL);

	MESSAGE req = message_create_named(NAME_MSGNAME_M1V2_SRVSET);
	message_add_url (req, url);
	message_add_body_unref (req, metautils_gba_from_string(m1url));

	return oneway_request(meta1, err, message_marshall_gba_and_clean(req));
}

gboolean
meta1v2_remote_configure_reference_service(const addr_info_t *meta1, GError **err,
		struct hc_url_s *url, const gchar *m1url)
{
	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(m1url != NULL);

	MESSAGE req = message_create_named(NAME_MSGNAME_M1V2_SRVSETARG);
	message_add_url (req, url);
	message_add_body_unref (req, metautils_gba_from_string(m1url));

	return oneway_request(meta1, err, message_marshall_gba_and_clean(req));
}

gboolean
meta1v2_remote_reference_set_property(const addr_info_t *m1, GError **err,
		struct hc_url_s *url, gchar **pairs)
{
	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(url != NULL);

	MESSAGE req = message_create_named(NAME_MSGNAME_M1V2_CID_PROPSET);
	message_add_url (req, url);
	message_add_body_unref (req, metautils_encode_lines(pairs));

	return oneway_request(m1, err, message_marshall_gba_and_clean(req));
}

gboolean
meta1v2_remote_reference_get_property(const addr_info_t *m1, GError **err,
		struct hc_url_s *url, gchar **keys, gchar ***result)
{
	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(result != NULL);

	MESSAGE req = message_create_named(NAME_MSGNAME_M1V2_CID_PROPGET);
	message_add_url (req, url);
	message_add_body_unref (req, metautils_encode_lines(keys));

	*result = list_request(m1, err, message_marshall_gba_and_clean(req));
	return *result != NULL;
}

gboolean
meta1v2_remote_reference_del_property(const addr_info_t *m1, GError **err,
		struct hc_url_s *url, gchar **keys)
{
	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(url != NULL);

	MESSAGE req = message_create_named(NAME_MSGNAME_M1V2_CID_PROPDEL);
	message_add_url (req, url);
	message_add_body_unref (req, metautils_encode_lines(keys));

	return oneway_request(m1, err, message_marshall_gba_and_clean(req));
}

gchar**
meta1v2_remote_list_services_by_prefix(const addr_info_t *m1, GError **err,
        struct hc_url_s *url)
{
    EXTRA_ASSERT(m1 != NULL);
    EXTRA_ASSERT(url != NULL);

    MESSAGE req = message_create_named(NAME_MSGNAME_M1V2_SRVALLONM1);
	message_add_url (req, url);
	message_add_cid (req, NAME_MSGKEY_PREFIX, hc_url_get_id(url));

    return list_request(m1, err, message_marshall_gba_and_clean(req));
}

GError *
meta1v2_remote_list_references_by_prefix(const addr_info_t *m1, struct hc_url_s *url,
		GByteArray **result)
{
	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(url != NULL);

	MESSAGE req = message_create_named (NAME_MSGNAME_M1V2_LISTBYPREF);
	message_add_url (req, url);
	message_add_cid (req, NAME_MSGKEY_PREFIX, hc_url_get_id(url));

	return gba_request(m1, result, message_marshall_gba_and_clean(req));
}

GError *
meta1v2_remote_list_references_by_service(const addr_info_t *m1,
		struct hc_url_s *url, const gchar *srvtype, const gchar *m1url,
		GByteArray **result)
{
	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(srvtype != NULL);
	EXTRA_ASSERT(m1url != NULL);

	MESSAGE req = message_create_named (NAME_MSGNAME_M1V2_LISTBYSERV);
	message_add_url (req, url);
	message_add_cid (req, NAME_MSGKEY_PREFIX, hc_url_get_id(url));
	message_add_field_str (req, NAME_MSGKEY_SRVTYPE, srvtype);
	message_add_field_str (req, NAME_MSGKEY_URL, m1url);

	return gba_request(m1, result, message_marshall_gba_and_clean(req));
}

gboolean
meta1v2_remote_get_prefixes(const addr_info_t *m1, GError **err, gchar *** result)
{
	EXTRA_ASSERT(m1 != NULL);

	MESSAGE req = message_create_named(NAME_MSGNAME_M1V2_GETPREFIX);
	*result = list_request(m1, err, message_marshall_gba_and_clean(req));
	return *result != NULL;
}

