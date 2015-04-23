/*
OpenIO SDS meta1v2
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.meta1.disp"
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <cluster/lib/gridcluster.h>
#include <sqliterepo/sqliterepo.h>
#include <meta2v2/meta2_remote.h>
#include <server/grid_daemon.h>
#include <server/transport_gridd.h>

#include "./meta1_backend.h"
#include "./meta1_prefixes.h"
#include "./meta1_remote.h"
#include "./meta1_gridd_dispatcher.h"
#include "./internals.h"

static gsize m1b_bufsize_listbypref = 16384;

static gboolean
srv_to_addr(const gchar *srv, struct addr_info_s *a)
{
	const gchar *type, *addr;
	type = strchr(srv, '|') + 1; /* skip the sequence number*/
	addr = strchr(type, '|') + 1; /* skip the service type */
	if (!addr)
		return FALSE;
	return grid_string_to_addrinfo(addr, strchr(addr, '|'), a);
}

static GSList *
singleton_addrl(const struct addr_info_s *ai)
{
	return g_slist_append(NULL, g_memdup(ai, sizeof(*ai)));
}

static GSList *
convert_urlv_to_addrl(gchar **urlv)
{
	gchar **u;
	GSList *result = NULL;

	if (!urlv)
		return NULL;

	for (u=urlv; *u ;u++) {
		struct addr_info_s ai;
		memset(&ai, 0, sizeof(ai));
		if (!srv_to_addr(*u, &ai))
			GRID_DEBUG("Invalid META2 URL [%s]", *u);
		else
			result = g_slist_prepend(result, g_memdup(&ai, sizeof(ai)));
	}

	g_strfreev(urlv);
	return result;
}

static GByteArray *
marshall_addrl(GSList *l, GError **err)
{
	GByteArray *gba;
	
	gba = addr_info_marshall_gba(l, NULL);
	if (l) {
		g_slist_foreach(l, addr_info_gclean, NULL);
		g_slist_free(l);
	}

	if (gba)
		return gba;

	*err = NEWERROR(CODE_INTERNAL_ERROR, "Encoding error (addr_info_t)");
	return NULL;
}

static GByteArray *
marshall_stringv_and_clean(gchar ***pv)
{
	GByteArray *result = metautils_encode_lines(*pv);
	g_strfreev(*pv);
	*pv = NULL;
	return result;
}

/* -------------------------------------------------------------------------- */

static GError *
_stat_container(struct meta1_backend_s *m1, struct hc_url_s *url,
		struct meta1_raw_container_s **result)
{
	GError *err;
	struct meta1_raw_container_s *raw;
	gchar **names, **allsrv;

	/* Get the meta1 name */
	err = meta1_backend_info_container(m1, url, &names);
	if (err != NULL)
		return err;

	/* Get the meta2 services */
	err = meta1_backend_get_container_all_services(m1, url, NAME_SRVTYPE_META2, &allsrv);
	if (err != NULL) {
		g_strfreev(names);
		return err;
	}
	
	/* OK, we have all the data */
	raw = g_malloc0(sizeof(*raw));
	memcpy(raw->id, hc_url_get_id(url), sizeof(container_id_t));
	g_strlcpy(raw->name, names[0], sizeof(raw->name)-1);
	g_strfreev(names);
	raw->meta2 = convert_urlv_to_addrl(allsrv);

	*result = raw;
	return NULL;
}

static GError *
_create_on_meta2(const gchar *srv, struct hc_url_s *url, struct addr_info_s *m2addr)
{
	GRID_DEBUG("Creation attempt on META2 at [%s]", srv);
	if (!srv_to_addr(srv, m2addr))
		return NEWERROR(CODE_INTERNAL_ERROR, "Invalid address (%d %s)", errno, strerror(errno));

	GError *err = NULL;
	if (!meta2_remote_container_create_v3(m2addr, 30000, &err, url, NULL)) {
		if (!err)
			return NEWERROR(CODE_PROXY_ERROR, "Unknown error when contacting META2");
		g_prefix_error(&err, "META2 error : ");
		return err;
	}
	return NULL;
}

/* -------------------------------------------------------------------------- */

static gboolean
meta1_dispatch_v1_CREATE(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	struct addr_info_s m2addr;
	gchar **result = NULL;

	struct hc_url_s *url = message_extract_url (reply->request);
	reply->subject("%s|%s", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID));
	(void) ignored;

	/* Test if the container exsists */
	err = meta1_backend_get_container_all_services(m1, url, NAME_SRVTYPE_META2, &result);
	if (NULL != err) {
		if (err->code != CODE_CONTAINER_NOTFOUND) {
			hc_url_clean(url);
			reply->send_error(0, err);
			return TRUE;
		}
		g_clear_error(&err);

		GRID_DEBUG("Creating the container reference");
		err = meta1_backend_create_container(m1, url);
		if (NULL != err) {
			hc_url_clean(url);
			reply->send_error(0, err);
			return TRUE;
		}
	}

	/* Associate a META2 to the container */
	if (result && !*result) {
		g_free(result);
		result = NULL;
	}
	if (!result) {
		GRID_TRACE("Meta2 election...");
		err = meta1_backend_get_container_service_available(m1, url,
				NAME_SRVTYPE_META2, FALSE, &result);
		if (NULL != err) {
			hc_url_clean(url);
			reply->send_error(0, err);
			return TRUE;
		}
	}

	/* Contact the meta2 and create a container on it */
	gchar **p_url;
	for (p_url=result; *p_url ;p_url++) {

		err = _create_on_meta2(*p_url, url, &m2addr);
		if (!err) {
			GRID_DEBUG("Container created on META2");
			break;
		}

		if (err->code == CODE_CONTAINER_EXISTS) {
			GRID_DEBUG("Container already present on META2");
			break;
		}

		if (!CODE_IS_NETWORK_ERROR(err->code)) {
			GRID_DEBUG("Error when creating the container on META2 [%s]"
					" : code=%d message=%s",
					*p_url, err->code, err->message);
			break;
		}

		GRID_INFO("Network error : code=%d message=%s", err->code, err->message);
		g_clear_error(&err);
	}

	g_strfreev(result);
	hc_url_clean(url);

	if (err) {
		reply->send_error(0, err);
		return TRUE;
	}

	/* Send the META2 address in the body of the reply ? */
	reply->add_body(marshall_addrl(singleton_addrl(&m2addr), NULL));

	GRID_DEBUG("Container created!");
	reply->send_reply(CODE_FINAL_OK, "OK");
	return TRUE;
}

#define CINFO(P) ((struct container_info_s*)(P))

static gboolean
meta1_dispatch_v1_BYID(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	struct hc_url_s *url = message_extract_url (reply->request);
	reply->subject("%s|%s", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID));
	(void) ignored;

	struct meta1_raw_container_s *raw = NULL;
	GError *err = _stat_container(m1, url, &raw);
	if (NULL != err)
		reply->send_error(0, err);
	else {
		GByteArray *gba = meta1_raw_container_marshall(raw, NULL);
		meta1_raw_container_clean(raw);
		reply->add_body(gba);
		reply->send_reply(CODE_FINAL_OK, "OK");
	}

	hc_url_clean (url);
	return TRUE;
}

/* ------------------------------------------------------------------------- */

static gboolean
meta1_dispatch_v2_CREATE(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	(void) ignored;
	struct hc_url_s *url = message_extract_url (reply->request);
	reply->subject("%s|%s", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID));

	GError *err = meta1_backend_create_container(m1, url);
	if (NULL != err)
		reply->send_error(0, err);
	else
		reply->send_reply(CODE_FINAL_OK, "Created");

	hc_url_clean (url);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_DESTROY(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	struct hc_url_s *url = message_extract_url (reply->request);
	gboolean force = message_extract_flag(reply->request, NAME_MSGKEY_FORCE, FALSE);
	reply->subject("%s|%s|%d", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID), force);
	(void) ignored;

	GError *err = meta1_backend_destroy_container(m1, url, force);
	if (NULL != err)
		reply->send_error(0, err);
	else
		reply->send_reply(CODE_FINAL_OK, "OK");

	hc_url_clean (url);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_HAS(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	gchar **info = NULL;
	struct hc_url_s *url = message_extract_url (reply->request);
	reply->subject("%s|%s", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID));
	(void) ignored;
	
	if (NULL != (err = meta1_backend_info_container(m1, url, &info)))
		reply->send_error(0, err);
	else {
		reply->add_body(marshall_stringv_and_clean(&info));
		reply->send_reply(CODE_FINAL_OK, "OK");
	}

	if (info) g_strfreev (info);
	hc_url_clean (url);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_GETAVAIL(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	struct hc_url_s *url = message_extract_url (reply->request);
	gchar *srvtype = message_extract_string_copy (reply->request, NAME_MSGKEY_SRVTYPE);
	gboolean dryrun = message_extract_flag(reply->request, NAME_HEADER_DRYRUN, FALSE);
	reply->subject("%s|%s|%s|%d", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID), srvtype, dryrun);
	(void) ignored;

	gchar **result = NULL;
	GError *err = meta1_backend_get_container_service_available(m1, url,
			srvtype, dryrun, &result);
	if (NULL != err)
		reply->send_error(0, err);
	else {
		reply->add_body(marshall_stringv_and_clean(&result));
		reply->send_reply(CODE_FINAL_OK, "OK");
	}

	if (result) g_strfreev (result);
	hc_url_clean(url);
	g_free0 (srvtype);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_NEW(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	struct hc_url_s *url = message_extract_url (reply->request);
	gboolean dryrun = message_extract_flag(reply->request, NAME_HEADER_DRYRUN, FALSE);
	gchar *srvtype = message_extract_string_copy (reply->request, NAME_MSGKEY_SRVTYPE);
	reply->subject("%s|%s|%s|%d", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID), srvtype, dryrun);
	(void) ignored;

	gchar **result = NULL;
	GError *err = meta1_backend_get_container_new_service(m1, url, srvtype,
			dryrun, &result);
	if (NULL != err)
		reply->send_error(0, err);
	else {
		reply->add_body(marshall_stringv_and_clean(&result));
		reply->send_reply(CODE_FINAL_OK, "OK");
	}

	if (result) g_strfreev (result);
	hc_url_clean(url);
	g_free0 (srvtype);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_SET(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	gchar *m1url = NULL;
	struct hc_url_s *url = message_extract_url (reply->request);
	reply->subject("%s|%s|%s", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID), m1url);
	(void) ignored;

	if (NULL != (err = message_extract_body_string(reply->request, &m1url)))
		reply->send_error(CODE_BAD_REQUEST, err);
	else if (NULL != (err = meta1_backend_force_service(m1, url, m1url)))
		reply->send_error(0, err);
	else
		reply->send_reply(CODE_BAD_REQUEST, "OK");

	g_free0 (m1url);
	hc_url_clean (url);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_SETARG(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	gchar *m1url = NULL;
	struct hc_url_s *url = message_extract_url (reply->request);
	reply->subject("%s|%s", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID));
	(void) ignored;

	if (NULL != (err = message_extract_body_string(reply->request, &m1url)))
		reply->send_error(CODE_BAD_REQUEST, err);
	else if (NULL != (err = meta1_backend_set_service_arguments(m1, url, m1url)))
		reply->send_error(0, err);
	else
		reply->send_reply(CODE_FINAL_OK, "OK");

	g_free0 (m1url);
	hc_url_clean (url);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_DELETE(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	gchar **urlv = NULL;
	GError *err;
	gchar *srvtype = message_extract_string_copy (reply->request, NAME_MSGKEY_SRVTYPE);
	struct hc_url_s *url = message_extract_url (reply->request);
	reply->subject("%s|%s|%s", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID), srvtype);
	(void) ignored;

	if (!srvtype)
		reply->send_error(0, NEWERROR(CODE_BAD_REQUEST, "Missing srvtype"));
	else if (NULL != (err = message_extract_body_strv(reply->request, &urlv)))
		reply->send_error(CODE_BAD_REQUEST, err);
	else if (!srvtype)
		reply->send_error(CODE_BAD_REQUEST, NEWERROR(CODE_BAD_REQUEST, "Missing srvtype"));
	else if (NULL != (err = meta1_backend_del_container_services(m1, url, srvtype, urlv)))
		reply->send_error(0, err);
	else
		reply->send_reply(CODE_FINAL_OK, "OK");

	if (urlv) g_strfreev (urlv);
	hc_url_clean (url);
	g_free0 (srvtype);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_GETALL(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	gchar **result = NULL;
	struct hc_url_s *url = message_extract_url (reply->request);
	gchar *srvtype = message_extract_string_copy (reply->request, NAME_MSGKEY_SRVTYPE);
	reply->subject("%s|%s|%s", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID), srvtype);
	(void) ignored;

	if (!srvtype)
		reply->send_error (0, NEWERROR(CODE_BAD_REQUEST, "Missing srvtype"));
	else if (NULL != (err = meta1_backend_get_container_all_services(m1, url, srvtype, &result)))
		reply->send_error(0, err);
	else {
		reply->add_body(marshall_stringv_and_clean(&result));
		reply->send_reply(CODE_FINAL_OK, "OK");
	}

	if (result) g_strfreev (result);
	hc_url_clean (url);
	g_free0 (srvtype);
	return TRUE;
}

static gboolean 
meta1_dispatch_v2_SRV_GETALLonM1(struct gridd_reply_ctx_s *reply,
        struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	gchar **result = NULL;
	struct hc_url_s *url = message_extract_url (reply->request);
    reply->subject("%s|%s", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID));
    reply->send_reply(CODE_TEMPORARY, "Received");
    (void) ignored;

	if (NULL != (err = meta1_backend_get_all_services(m1, url, &result)))
        reply->send_error(0, err);
    else {
        reply->add_body(marshall_stringv_and_clean(&result));
        reply->send_reply(CODE_FINAL_OK, "OK");
    }

	if (result) g_strfreev (result);
	hc_url_clean (url);
    return TRUE;
}

static gboolean
meta1_dispatch_v2_CID_PROPGET(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	gchar **strv = NULL, **result = NULL;
	struct hc_url_s *url = message_extract_url (reply->request);
	reply->subject("%s|%s", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID));

	(void) ignored;

	if (NULL != (err = message_extract_body_strv(reply->request, &strv)))
		reply->send_error(CODE_BAD_REQUEST, err);
	else if (NULL != (err = meta1_backend_get_container_properties(m1, url, strv, &result)))
		reply->send_error(0, err);
	else {
		reply->add_body(marshall_stringv_and_clean(&result));
		reply->send_reply(CODE_FINAL_OK, "OK");
	}

	if (strv) g_strfreev (strv);
	if (result) g_strfreev (result);
	hc_url_clean (url);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_CID_PROPSET(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	gchar **strv = NULL;
	struct hc_url_s *url = message_extract_url (reply->request);
	reply->subject("%s|%s", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID));
	(void) ignored;

	if (NULL != (err = message_extract_body_strv(reply->request, &strv)))
		reply->send_error(CODE_BAD_REQUEST, err);
	else if (NULL != (err = meta1_backend_set_container_properties(m1, url, strv)))
		reply->send_error(0, err);
	else
		reply->send_reply(CODE_FINAL_OK, "OK");

	if (strv) g_strfreev (strv);
	hc_url_clean (url);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_CID_PROPDEL(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	gchar **strv = NULL;
	struct hc_url_s *url = message_extract_url (reply->request);
	reply->subject("%s|%s", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID));
	(void) ignored;

	if (NULL != (err = message_extract_body_strv(reply->request, &strv)))
		reply->send_error(CODE_BAD_REQUEST, err);
	else if (NULL != (err = meta1_backend_del_container_properties(m1, url, strv)))
		reply->send_error(0, err);
	else 
		reply->send_reply(CODE_FINAL_OK, "OK");

	if (strv) g_strfreev (strv);
	hc_url_clean (url);
	return TRUE;
}

struct reflist_ctx_s
{
	struct gridd_reply_ctx_s *reply;
	GByteArray *gba;
};

static void
reflist_hook(gpointer p, const gchar *ns, const gchar *ref)
{
	struct reflist_ctx_s *ctx = p;

	if (!ctx->gba)
		ctx->gba = g_byte_array_new();

	g_byte_array_append(ctx->gba, (guint8*)ns, strlen(ns));
	g_byte_array_append(ctx->gba, (guint8*)"/", 1);
	g_byte_array_append(ctx->gba, (guint8*)ref, strlen(ref));
	g_byte_array_append(ctx->gba, (guint8*)"\n", 1);

	if (ctx->gba->len > m1b_bufsize_listbypref) {
		ctx->reply->add_body(ctx->gba);
		ctx->gba = NULL;
		ctx->reply->send_reply(CODE_PARTIAL_CONTENT, "Partial content");
	}
}

static void
reflist_final(struct reflist_ctx_s *ctx, GError *err)
{
	if (err) {
		if (ctx->gba)
			g_byte_array_free(ctx->gba, TRUE);
		ctx->reply->send_error(0, err);
	}
	else {
		if (ctx->gba)
			ctx->reply->add_body(ctx->gba);
		ctx->reply->send_reply(CODE_FINAL_OK, "OK");
	}

	ctx->gba = NULL;
	ctx->reply = NULL;
}

static gboolean
meta1_dispatch_v2_SRV_LISTPREF(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	struct hc_url_s *url = message_extract_url (reply->request);
	gchar *srvtype = message_extract_string_copy (reply->request, NAME_MSGKEY_SRVTYPE);
	reply->subject("%s|%s", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID));
	(void) ignored;

	if (!srvtype)
		reply->send_error (0, NEWERROR(CODE_BAD_REQUEST, "Missing srvtype"));
	else {
		struct reflist_ctx_s reflist_ctx;
		reflist_ctx.gba = NULL;
		reflist_ctx.reply = reply;
		reply->send_reply(CODE_TEMPORARY, "Received");
		GError *err = meta1_backend_list_references_by_prefix(m1, url,
				reflist_hook, &reflist_ctx);
		reflist_final(&reflist_ctx, err);
	}

	hc_url_clean (url);
	g_free0 (srvtype);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_LISTSERV(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	struct hc_url_s *url = message_extract_url (reply->request);
	gchar *srvtype = message_extract_string_copy (reply->request, NAME_MSGKEY_SRVTYPE);
	gchar *m1url = message_extract_string_copy (reply->request, NAME_MSGKEY_URL);
	reply->subject("%s|%s|%s|%s", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID), srvtype, m1url);
	(void) ignored;

	if (!srvtype)
		reply->send_error (0, NEWERROR(CODE_BAD_REQUEST, "Missing srvtype"));
	else if (m1url)
		reply->send_error (0, NEWERROR(CODE_BAD_REQUEST, "Missing srvurl"));
	else {
		struct reflist_ctx_s reflist_ctx;
		reflist_ctx.gba = NULL;
		reflist_ctx.reply = reply;
		reply->send_reply(CODE_TEMPORARY, "Received");
		GError *err = meta1_backend_list_references_by_service(m1, url,
				srvtype, m1url, reflist_hook, &reflist_ctx);
		reflist_final(&reflist_ctx, err);
	}

	g_free0 (srvtype);
	g_free0 (m1url);
	hc_url_clean (url);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_GET_PREFIX(struct gridd_reply_ctx_s *reply,
	struct meta1_backend_s *m1, gpointer ignored)
{
	(void) ignored;
	struct meta1_prefixes_set_s *m1ps = meta1_backend_get_prefixes(m1);
	gchar **result = result = meta1_prefixes_get_all(m1ps);
	if (result)
		reply->add_body(marshall_stringv_and_clean(&result));
	reply->send_reply(CODE_FINAL_OK, "OK");
	return TRUE;
}

/* ------------------------------------------------------------------------- */

typedef gboolean (*hook) (struct gridd_reply_ctx_s *, gpointer, gpointer);

const struct gridd_request_descr_s *
meta1_gridd_get_requests(void)
{
	static struct gridd_request_descr_s descriptions[] = {

		/* META1 new fashion */
		{NAME_MSGNAME_M1V2_HAS,         (hook) meta1_dispatch_v2_HAS,           NULL},
		{NAME_MSGNAME_M1V2_CREATE,      (hook) meta1_dispatch_v2_CREATE,        NULL},
		{NAME_MSGNAME_M1V2_DESTROY,     (hook) meta1_dispatch_v2_DESTROY,       NULL},
		{NAME_MSGNAME_M1V2_SRVSET,      (hook) meta1_dispatch_v2_SRV_SET,       NULL},
		{NAME_MSGNAME_M1V2_SRVNEW,      (hook) meta1_dispatch_v2_SRV_NEW,       NULL},
		{NAME_MSGNAME_M1V2_SRVSETARG,   (hook) meta1_dispatch_v2_SRV_SETARG,    NULL},
		{NAME_MSGNAME_M1V2_SRVDEL,      (hook) meta1_dispatch_v2_SRV_DELETE,    NULL},
		{NAME_MSGNAME_M1V2_SRVALL,      (hook) meta1_dispatch_v2_SRV_GETALL,    NULL},
		{NAME_MSGNAME_M1V2_SRVALLONM1,  (hook) meta1_dispatch_v2_SRV_GETALLonM1,NULL},
		{NAME_MSGNAME_M1V2_SRVAVAIL,    (hook) meta1_dispatch_v2_SRV_GETAVAIL,  NULL},
		{NAME_MSGNAME_M1V2_CID_PROPGET, (hook) meta1_dispatch_v2_CID_PROPGET,   NULL},
		{NAME_MSGNAME_M1V2_CID_PROPSET, (hook) meta1_dispatch_v2_CID_PROPSET,   NULL},
		{NAME_MSGNAME_M1V2_CID_PROPDEL, (hook) meta1_dispatch_v2_CID_PROPDEL,   NULL},
		{NAME_MSGNAME_M1V2_GETPREFIX,	(hook) meta1_dispatch_v2_GET_PREFIX,    NULL},
		{NAME_MSGNAME_M1V2_LISTBYPREF,  (hook) meta1_dispatch_v2_SRV_LISTPREF,  NULL},
		{NAME_MSGNAME_M1V2_LISTBYSERV,  (hook) meta1_dispatch_v2_SRV_LISTSERV,  NULL},

		/* Old fashoned meta2-orentied requests */
		{NAME_MSGNAME_M1_CREATE,        (hook) meta1_dispatch_v1_CREATE,   NULL},
		{NAME_MSGNAME_M1_CONT_BY_ID,    (hook) meta1_dispatch_v1_BYID,     NULL},

		{NULL, NULL, NULL}
	};

	return descriptions;
}

