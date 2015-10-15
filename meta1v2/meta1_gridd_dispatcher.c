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

static GByteArray *
marshall_stringv_and_clean(gchar ***pv)
{
	GByteArray *result = metautils_encode_lines(*pv);
	g_strfreev(*pv);
	*pv = NULL;
	return result;
}

/* -------------------------------------------------------------------------- */

static gboolean
meta1_dispatch_v2_USERCREATE(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	(void) ignored;
	struct hc_url_s *url = metautils_message_extract_url (reply->request);
	reply->subject("%s|%s", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID));

	GError *err = meta1_backend_user_create(m1, url);
	if (NULL != err)
		reply->send_error(0, err);
	else
		reply->send_reply(CODE_FINAL_OK, "Created");

	hc_url_clean (url);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_USERDESTROY(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	struct hc_url_s *url = metautils_message_extract_url (reply->request);
	gboolean force = metautils_message_extract_flag(reply->request, NAME_MSGKEY_FORCE, FALSE);
	reply->subject("%s|%s|%d", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID), force);
	(void) ignored;

	GError *err = meta1_backend_user_destroy(m1, url, force);
	if (NULL != err)
		reply->send_error(0, err);
	else
		reply->send_reply(CODE_FINAL_OK, "OK");

	hc_url_clean (url);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_USERINFO(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	gchar **info = NULL;
	struct hc_url_s *url = metautils_message_extract_url (reply->request);
	reply->subject("%s|%s", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID));
	(void) ignored;
	
	if (NULL != (err = meta1_backend_user_info(m1, url, &info)))
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
meta1_dispatch_v2_SRV_LINK(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	struct hc_url_s *url = metautils_message_extract_url (reply->request);
	gchar *srvtype = metautils_message_extract_string_copy (reply->request, NAME_MSGKEY_TYPENAME);
	gboolean dryrun = metautils_message_extract_flag(reply->request, NAME_MSGKEY_DRYRUN, FALSE);
	gboolean autocreate = metautils_message_extract_flag(reply->request, NAME_MSGKEY_AUTOCREATE, FALSE);
	reply->subject("%s|%s|%s|%d", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID), srvtype, dryrun);
	(void) ignored;

	gchar **result = NULL;
	GError *err = meta1_backend_services_link (m1, url,
			srvtype, dryrun, autocreate, &result);
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
meta1_dispatch_v2_SRV_POLL(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	struct hc_url_s *url = metautils_message_extract_url (reply->request);
	gboolean ac = metautils_message_extract_flag(reply->request, NAME_MSGKEY_AUTOCREATE, FALSE);
	gboolean dryrun = metautils_message_extract_flag(reply->request, NAME_MSGKEY_DRYRUN, FALSE);
	gchar *srvtype = metautils_message_extract_string_copy (reply->request, NAME_MSGKEY_TYPENAME);
	reply->subject("%s|%s|%s|%d", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID), srvtype, dryrun);
	(void) ignored;

	gchar **result = NULL;
	GError *err = meta1_backend_services_poll(m1, url, srvtype, ac, dryrun, &result);
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
meta1_dispatch_v2_SRV_FORCE(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	gchar *m1url = NULL;
	struct hc_url_s *url = metautils_message_extract_url (reply->request);
	reply->subject("%s|%s|%s", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID), m1url);
	(void) ignored;

	gboolean ac = metautils_message_extract_flag (reply->request, NAME_MSGKEY_AUTOCREATE, FALSE);
	gboolean force = metautils_message_extract_flag (reply->request, NAME_MSGKEY_FORCE, FALSE);
	if (NULL != (err = metautils_message_extract_body_string(reply->request, &m1url)))
		reply->send_error(CODE_BAD_REQUEST, err);
	else if (NULL != (err = meta1_backend_services_set(m1, url, m1url, ac, force)))
		reply->send_error(0, err);
	else
		reply->send_reply(200, "OK");

	g_free0 (m1url);
	hc_url_clean (url);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_CONFIG(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	gchar *m1url = NULL;
	struct hc_url_s *url = metautils_message_extract_url (reply->request);
	reply->subject("%s|%s", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID));
	(void) ignored;

	if (NULL != (err = metautils_message_extract_body_string(reply->request, &m1url)))
		reply->send_error(CODE_BAD_REQUEST, err);
	else if (NULL != (err = meta1_backend_services_config(m1, url, m1url)))
		reply->send_error(0, err);
	else
		reply->send_reply(CODE_FINAL_OK, "OK");

	g_free0 (m1url);
	hc_url_clean (url);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_UNLINK(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	gchar **urlv = NULL;
	GError *err;
	gchar *srvtype = metautils_message_extract_string_copy (reply->request, NAME_MSGKEY_TYPENAME);
	struct hc_url_s *url = metautils_message_extract_url (reply->request);
	reply->subject("%s|%s|%s", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID), srvtype);
	(void) ignored;

	if (!srvtype)
		reply->send_error(CODE_BAD_REQUEST, NEWERROR(CODE_BAD_REQUEST, "Missing srvtype"));
	else if (NULL != (err = metautils_message_extract_body_strv(reply->request, &urlv)))
		reply->send_error(CODE_BAD_REQUEST, err);
	else if (NULL != (err = meta1_backend_services_unlink(m1, url, srvtype, urlv)))
		reply->send_error(0, err);
	else
		reply->send_reply(CODE_FINAL_OK, "OK");

	if (urlv) g_strfreev (urlv);
	hc_url_clean (url);
	g_free0 (srvtype);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_LIST(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	gchar **result = NULL;
	struct hc_url_s *url = metautils_message_extract_url (reply->request);
	gchar *srvtype = metautils_message_extract_string_copy (reply->request, NAME_MSGKEY_TYPENAME);
	reply->subject("%s|%s|%s", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID), srvtype);
	(void) ignored;

	if (NULL != (err = meta1_backend_services_list(m1, url, srvtype, &result)))
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
meta1_dispatch_v2_SRV_ALLONM1(struct gridd_reply_ctx_s *reply,
        struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	gchar **result = NULL;
	struct hc_url_s *url = metautils_message_extract_url (reply->request);
    reply->subject("%s|%s", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID));
    reply->send_reply(CODE_TEMPORARY, "Received");
    (void) ignored;

	if (NULL != (err = meta1_backend_services_all(m1, url, &result)))
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
meta1_dispatch_v2_PROPGET(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	gchar **strv = NULL, **result = NULL;
	struct hc_url_s *url = metautils_message_extract_url (reply->request);
	reply->subject("%s|%s", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID));

	(void) ignored;

	if (NULL != (err = metautils_message_extract_body_strv(reply->request, &strv)))
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
meta1_dispatch_v2_PROPSET(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	gchar **strv = NULL;
	struct hc_url_s *url = metautils_message_extract_url (reply->request);
	gboolean flush = metautils_message_extract_flag(reply->request,
			NAME_MSGKEY_FLUSH, FALSE);
	reply->subject("%s|%s", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID));
	(void) ignored;

	if (NULL != (err = metautils_message_extract_body_strv(reply->request, &strv)))
		reply->send_error(CODE_BAD_REQUEST, err);
	else if (NULL != (err = meta1_backend_set_container_properties(m1, url, strv, flush)))
		reply->send_error(0, err);
	else
		reply->send_reply(CODE_FINAL_OK, "OK");

	if (strv) g_strfreev (strv);
	hc_url_clean (url);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_PROPDEL(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err;
	gchar **strv = NULL;
	struct hc_url_s *url = metautils_message_extract_url (reply->request);
	reply->subject("%s|%s", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID));
	(void) ignored;

	if (NULL != (err = metautils_message_extract_body_strv(reply->request, &strv)))
		reply->send_error(CODE_BAD_REQUEST, err);
	else if (NULL != (err = meta1_backend_del_container_properties(m1, url, strv)))
		reply->send_error(0, err);
	else 
		reply->send_reply(CODE_FINAL_OK, "OK");

	if (strv) g_strfreev (strv);
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

static gboolean
meta1_dispatch_v2_SRVRELINK(struct gridd_reply_ctx_s *reply,
	struct meta1_backend_s *m1, gpointer ignored)
{
	GError *err = NULL;
	gchar *replaced = NULL, *kept = NULL, **newset = NULL;
	struct hc_url_s *url = NULL;
	(void) ignored;

	url = metautils_message_extract_url (reply->request);
	kept = metautils_message_extract_string_copy (reply->request, NAME_MSGKEY_OLD);
	replaced = metautils_message_extract_string_copy (reply->request, NAME_MSGKEY_NOTIN);
	gboolean dryrun = metautils_message_extract_flag (reply->request, NAME_MSGKEY_DRYRUN, FALSE);
	reply->subject("%s|%s", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID));

	if (!url) {
		reply->send_error (0, NEWERROR(CODE_BAD_REQUEST, "Missing field (%s)", "url"));
	} else {
		err = meta1_backend_services_relink (m1, url, kept, replaced, dryrun, &newset);
		if (NULL != err) {
			reply->send_error (0, err);
		} else {
			reply->add_body(marshall_stringv_and_clean(&newset));
			reply->send_reply (CODE_FINAL_OK, "OK");
		}
	}

	hc_url_pclean (&url);
	g_free0 (kept);
	g_free0 (replaced);
	if (newset) g_strfreev (newset);
	return TRUE;
}

/* ------------------------------------------------------------------------- */

typedef gboolean (*hook) (struct gridd_reply_ctx_s *, gpointer, gpointer);

const struct gridd_request_descr_s *
meta1_gridd_get_requests(void)
{
	static struct gridd_request_descr_s descriptions[] = {

		{NAME_MSGNAME_M1V2_USERINFO,    (hook) meta1_dispatch_v2_USERINFO,    NULL},
		{NAME_MSGNAME_M1V2_USERCREATE,  (hook) meta1_dispatch_v2_USERCREATE,  NULL},
		{NAME_MSGNAME_M1V2_USERDESTROY, (hook) meta1_dispatch_v2_USERDESTROY, NULL},

		{NAME_MSGNAME_M1V2_SRVLIST,     (hook) meta1_dispatch_v2_SRV_LIST,    NULL},
		{NAME_MSGNAME_M1V2_SRVLINK,     (hook) meta1_dispatch_v2_SRV_LINK,    NULL},
		{NAME_MSGNAME_M1V2_SRVUNLINK,   (hook) meta1_dispatch_v2_SRV_UNLINK,  NULL},
		{NAME_MSGNAME_M1V2_SRVSET,      (hook) meta1_dispatch_v2_SRV_FORCE,   NULL},
		{NAME_MSGNAME_M1V2_SRVPOLL,     (hook) meta1_dispatch_v2_SRV_POLL,    NULL},
		{NAME_MSGNAME_M1V2_SRVCONFIG,   (hook) meta1_dispatch_v2_SRV_CONFIG,  NULL},

		{NAME_MSGNAME_M1V2_PROPGET,     (hook) meta1_dispatch_v2_PROPGET, NULL},
		{NAME_MSGNAME_M1V2_PROPSET,     (hook) meta1_dispatch_v2_PROPSET, NULL},
		{NAME_MSGNAME_M1V2_PROPDEL,     (hook) meta1_dispatch_v2_PROPDEL, NULL},

		{NAME_MSGNAME_M1V2_SRVALLONM1,  (hook) meta1_dispatch_v2_SRV_ALLONM1, NULL},
		{NAME_MSGNAME_M1V2_GETPREFIX,	(hook) meta1_dispatch_v2_GET_PREFIX,  NULL},

		{NAME_MSGNAME_M1V2_SRVRELINK,   (hook) meta1_dispatch_v2_SRVRELINK, NULL},

		{NULL, NULL, NULL}
	};

	return descriptions;
}

