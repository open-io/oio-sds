/*
OpenIO SDS meta1v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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
#include <server/transport_gridd.h>

#include "./meta1_backend.h"
#include "./meta1_prefixes.h"
#include "./meta1_remote.h"
#include "./meta1_gridd_dispatcher.h"
#include "./internals.h"

static void _strfreev (gchar ***pv) {
	if (pv) {
		g_strfreev(*pv);
		*pv = NULL;
	}
}

static GByteArray *encode_and_clean(GByteArray* (*e)(gchar**), gchar **pv) {
	GByteArray *result = (*e)(pv);
	g_strfreev(pv);
	return result;
}

/* -------------------------------------------------------------------------- */

static gboolean
meta1_dispatch_v2_USERCREATE(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, struct oio_url_s *url)
{
	reply->subject("%s|%s", oio_url_get(url, OIOURL_WHOLE), oio_url_get(url, OIOURL_HEXID));

	gsize length = 0;
	void *body = metautils_message_get_BODY(reply->request, &length);
	gchar **properties = NULL;
	GError *err = KV_decode_buffer(body, length, &properties);
	if (NULL != err) {
		reply->send_error(0, err);
		return TRUE;
	}

	err = meta1_backend_user_create(m1, url, properties);
	g_strfreev(properties);

	if (NULL != err)
		reply->send_error(0, err);
	else
		reply->send_reply(CODE_FINAL_OK, "Created");

	return TRUE;
}

static gboolean
meta1_dispatch_v2_USERDESTROY(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, struct oio_url_s *url)
{
	gboolean force = metautils_message_extract_flag(reply->request, NAME_MSGKEY_FORCE, FALSE);
	reply->subject("%s|%s|%d", oio_url_get(url, OIOURL_WHOLE), oio_url_get(url, OIOURL_HEXID), force);

	GError *err = meta1_backend_user_destroy(m1, url, force);
	if (NULL != err)
		reply->send_error(0, err);
	else
		reply->send_reply(CODE_FINAL_OK, "OK");

	return TRUE;
}

static gboolean
meta1_dispatch_v2_USERINFO(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, struct oio_url_s *url)
{
	reply->subject("%s|%s", oio_url_get(url, OIOURL_WHOLE), oio_url_get(url, OIOURL_HEXID));

	gchar **info = NULL;
	GError *err = meta1_backend_user_info(m1, url, &info);
	if (NULL != err) {
		_strfreev(&info);
		reply->send_error(0, err);
	} else {
		reply->add_body(encode_and_clean(STRV_encode_gba, info));
		reply->send_reply(CODE_FINAL_OK, "OK");
	}

	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_LINK(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, struct oio_url_s *url)
{
	gchar srvtype[LIMIT_LENGTH_SRVTYPE] = "";
	gchar last[1024] = "";

	const gboolean ac = metautils_message_extract_flag(reply->request, NAME_MSGKEY_AUTOCREATE, FALSE);
	metautils_message_extract_string_noerror(reply->request, NAME_MSGKEY_TYPENAME, srvtype, sizeof(srvtype));
	metautils_message_extract_string_noerror(reply->request, NAME_MSGKEY_LAST, last, sizeof(last));

	reply->subject("%s|%s|%s", oio_url_get(url, OIOURL_WHOLE), oio_url_get(url, OIOURL_HEXID), srvtype);

	gchar **result = NULL;
	GError *err = meta1_backend_services_link(m1, url, srvtype, last, ac, &result);
	if (NULL != err) {
		_strfreev(&result);
		reply->send_error(0, err);
	} else {
		reply->add_body(encode_and_clean(STRV_encode_gba, result));
		reply->send_reply(CODE_FINAL_OK, "OK");
	}

	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_RENEW(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, struct oio_url_s *url)
{
	gchar srvtype[LIMIT_LENGTH_SRVTYPE] = "";
	gchar last[1024] = "";

	const gboolean ac = metautils_message_extract_flag(reply->request, NAME_MSGKEY_AUTOCREATE, FALSE);
	metautils_message_extract_string_noerror(reply->request, NAME_MSGKEY_TYPENAME, srvtype, sizeof(srvtype));
	metautils_message_extract_string_noerror(reply->request, NAME_MSGKEY_LAST, last, sizeof(last));

	reply->subject("%s|%s|%s", oio_url_get(url, OIOURL_WHOLE), oio_url_get(url, OIOURL_HEXID), srvtype);

	gchar **result = NULL;
	GError *err = meta1_backend_services_renew(m1, url, srvtype, last, ac, &result);
	if (NULL != err) {
		_strfreev(&result);
		reply->send_error(0, err);
	} else {
		reply->add_body(encode_and_clean(STRV_encode_gba, result));
		reply->send_reply(CODE_FINAL_OK, "OK");
	}

	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_FORCE(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, struct oio_url_s *url)
{
	gboolean ac = metautils_message_extract_flag (reply->request, NAME_MSGKEY_AUTOCREATE, FALSE);
	gboolean force = metautils_message_extract_flag (reply->request, NAME_MSGKEY_FORCE, FALSE);
	reply->subject("%s|%s|?", oio_url_get(url, OIOURL_WHOLE), oio_url_get(url, OIOURL_HEXID));

	gchar *m1url = NULL;
	GError *err = metautils_message_extract_body_string(reply->request, &m1url);
	if (NULL != err)
		reply->send_error(CODE_BAD_REQUEST, err);
	else {
		reply->subject("%s|%s|%s", oio_url_get(url, OIOURL_WHOLE), oio_url_get(url, OIOURL_HEXID), m1url);
		err = meta1_backend_services_set(m1, url, m1url, ac, force);
		g_free0 (m1url);
		if (NULL != err)
			reply->send_error(0, err);
		else
			reply->send_reply(200, "OK");
	}

	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_CONFIG(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, struct oio_url_s *url)
{
	reply->subject("%s|%s", oio_url_get(url, OIOURL_WHOLE), oio_url_get(url, OIOURL_HEXID));

	gchar *m1url = NULL;
	GError *err = metautils_message_extract_body_string(reply->request, &m1url);
	if (NULL != err)
		reply->send_error(CODE_BAD_REQUEST, err);
	else {
		err = meta1_backend_services_config(m1, url, m1url);
		g_free0 (m1url);
		if (NULL != err)
			reply->send_error(0, err);
		else
			reply->send_reply(CODE_FINAL_OK, "OK");
	}

	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_UNLINK(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, struct oio_url_s *url)
{
	gchar srvtype[LIMIT_LENGTH_SRVTYPE] = "";

	metautils_message_extract_string_noerror (reply->request,
			NAME_MSGKEY_TYPENAME, srvtype, sizeof(srvtype));

	reply->subject("%s|%s|%s", oio_url_get(url, OIOURL_WHOLE), oio_url_get(url, OIOURL_HEXID), srvtype);

	if (!*srvtype)
		reply->send_error(CODE_BAD_REQUEST, NEWERROR(CODE_BAD_REQUEST, "Missing srvtype"));
	else {
		gsize length = 0;
		void *body = metautils_message_get_BODY(reply->request, &length);
		gchar **urlv = NULL;
		GError *err = STRV_decode_buffer(body, length, &urlv);
		if (NULL != err)
			reply->send_error(CODE_BAD_REQUEST, err);
		else {
			err = meta1_backend_services_unlink(m1, url, srvtype, urlv);
			if (NULL != err)
				reply->send_error(0, err);
			else
				reply->send_reply(CODE_FINAL_OK, "OK");
			g_strfreev (urlv);
		}
	}

	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_LIST(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, struct oio_url_s *url)
{
	gchar srvtype[LIMIT_LENGTH_SRVTYPE] = "";

	metautils_message_extract_string_noerror(reply->request,
			NAME_MSGKEY_TYPENAME, srvtype, sizeof(srvtype));
	reply->subject("%s|%s|%s", oio_url_get(url, OIOURL_WHOLE), oio_url_get(url, OIOURL_HEXID), srvtype);

	gchar **result = NULL;
	GError *err = meta1_backend_services_list(
			m1, url, srvtype, &result, oio_ext_get_deadline());
	if (NULL != err) {
		_strfreev(&result);
		reply->send_error(0, err);
	} else {
		reply->add_body(encode_and_clean(STRV_encode_gba, result));
		reply->send_reply(CODE_FINAL_OK, "OK");
	}

	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_ALLONM1(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, struct oio_url_s *url)
{
	reply->subject("%s|%s", oio_url_get(url, OIOURL_WHOLE), oio_url_get(url, OIOURL_HEXID));
	reply->send_reply(CODE_TEMPORARY, "Received");

	gchar **result = NULL;
	GError *err = meta1_backend_services_all(m1, url, &result);
	if (NULL != err) {
		_strfreev(&result);
		reply->send_error(0, err);
	} else {
		reply->add_body(encode_and_clean(STRV_encode_gba, result));
		reply->send_reply(CODE_FINAL_OK, "OK");
	}

	return TRUE;
}

static gboolean
meta1_dispatch_v2_PROPGET(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, struct oio_url_s *url)
{
	reply->subject("%s|%s", oio_url_get(url, OIOURL_WHOLE), oio_url_get(url, OIOURL_HEXID));

	gsize length = 0;
	void *body = metautils_message_get_BODY(reply->request, &length);
	gchar **keys = NULL;
	GError *err = STRV_decode_buffer(body, length, &keys);
	if (NULL != err)
		reply->send_error(CODE_BAD_REQUEST, err);
	else {
		gchar **result = NULL;
		err = meta1_backend_get_container_properties(m1, url, keys, &result);
		g_strfreev (keys);
		if (NULL != err) {
			_strfreev(&result);
			reply->send_error(0, err);
		} else {
			reply->add_body(encode_and_clean(KV_encode_gba, result));
			reply->send_reply(CODE_FINAL_OK, "OK");
		}
	}

	return TRUE;
}

static gboolean
meta1_dispatch_v2_PROPSET(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, struct oio_url_s *url)
{
	gboolean flush = metautils_message_extract_flag(reply->request, NAME_MSGKEY_FLUSH, FALSE);
	reply->subject("%s|%s", oio_url_get(url, OIOURL_WHOLE), oio_url_get(url, OIOURL_HEXID));

	gsize length = 0;
	void *body = metautils_message_get_BODY(reply->request, &length);
	gchar **props = NULL;
	GError *err = KV_decode_buffer(body, length, &props);
	if (NULL != err)
		reply->send_error(CODE_BAD_REQUEST, err);
	else {
		err = meta1_backend_set_container_properties(m1, url, props, flush);
		g_strfreev (props);
		if (NULL != err)
			reply->send_error(0, err);
		else
			reply->send_reply(CODE_FINAL_OK, "OK");
	}

	return TRUE;
}

static gboolean
meta1_dispatch_v2_PROPDEL(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, struct oio_url_s *url)
{
	reply->subject("%s|%s", oio_url_get(url, OIOURL_WHOLE), oio_url_get(url, OIOURL_HEXID));

	gchar **keys = NULL;
	gsize length = 0;
	void *body = metautils_message_get_BODY(reply->request, &length);
	GError *err = STRV_decode_buffer(body, length, &keys);

	if (NULL != err)
		reply->send_error(CODE_BAD_REQUEST, err);
	else {
		err = meta1_backend_del_container_properties(m1, url, keys);
		if (err)
			reply->send_error(0, err);
		else
			reply->send_reply(CODE_FINAL_OK, "OK");
		g_strfreev (keys);
	}

	return TRUE;
}

static gboolean
meta1_dispatch_v2_GET_PREFIX(struct gridd_reply_ctx_s *reply,
	struct meta1_backend_s *m1, gpointer ignored UNUSED)
{
	gchar **result = meta1_prefixes_get_all(meta1_backend_get_prefixes(m1));
	if (result)
		reply->add_body(encode_and_clean(STRV_encode_gba, result));
	reply->send_reply(CODE_FINAL_OK, "OK");
	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRVRELINK(struct gridd_reply_ctx_s *reply,
	struct meta1_backend_s *m1, struct oio_url_s *url)
{
	gchar *kept = metautils_message_extract_string_copy (reply->request, NAME_MSGKEY_OLD);
	gchar *replaced = metautils_message_extract_string_copy (reply->request, NAME_MSGKEY_NOTIN);
	gboolean dryrun = metautils_message_extract_flag (reply->request, NAME_MSGKEY_DRYRUN, FALSE);
	reply->subject("%s|%s", oio_url_get(url, OIOURL_WHOLE), oio_url_get(url, OIOURL_HEXID));

	if (!url) {
		reply->send_error (0, NEWERROR(CODE_BAD_REQUEST, "Missing field (%s)", "url"));
	} else {
		gchar **newset = NULL;
		GError *err = meta1_backend_services_relink (m1, url, kept, replaced, dryrun, &newset);
		if (NULL != err) {
			_strfreev(&newset);
			reply->send_error (0, err);
		} else {
			reply->add_body(encode_and_clean(STRV_encode_gba, newset));
			reply->send_reply (CODE_FINAL_OK, "OK");
		}
	}

	g_free0 (kept);
	g_free0 (replaced);
	return TRUE;
}

/* ------------------------------------------------------------------------- */

typedef gboolean (*hook) (struct gridd_reply_ctx_s *, gpointer, gpointer);


typedef gboolean (*action) (struct gridd_reply_ctx_s *, struct meta1_backend_s *, struct oio_url_s *u);


static gboolean meta1_dispatch_all(struct gridd_reply_ctx_s *reply,
                                   struct meta1_backend_s *m1, gpointer callback)
{
	struct oio_url_s *url = metautils_message_extract_url(reply->request);

	const gchar *_err;
	if (!oio_url_check(url, NULL, &_err)) {
		reply->send_error(0, BADREQ("Invalid %s", _err));
		oio_url_pclean(&url);
		return TRUE;
	}

    action ptr = callback;
    gboolean ret = (*ptr)(reply, m1, url);
    oio_url_pclean(&url);

    return ret;
}

const struct gridd_request_descr_s *
meta1_gridd_get_requests(void)
{
	static struct gridd_request_descr_s descriptions[] = {

		{NAME_MSGNAME_M1V2_USERINFO,    (hook) meta1_dispatch_all, meta1_dispatch_v2_USERINFO},
		{NAME_MSGNAME_M1V2_USERCREATE,  (hook) meta1_dispatch_all, meta1_dispatch_v2_USERCREATE},
		{NAME_MSGNAME_M1V2_USERDESTROY, (hook) meta1_dispatch_all, meta1_dispatch_v2_USERDESTROY},

		{NAME_MSGNAME_M1V2_SRVLIST,     (hook) meta1_dispatch_all, meta1_dispatch_v2_SRV_LIST},
		{NAME_MSGNAME_M1V2_SRVLINK,     (hook) meta1_dispatch_all, meta1_dispatch_v2_SRV_LINK},
		{NAME_MSGNAME_M1V2_SRVUNLINK,   (hook) meta1_dispatch_all, meta1_dispatch_v2_SRV_UNLINK},
		{NAME_MSGNAME_M1V2_SRVFORCE,    (hook) meta1_dispatch_all, meta1_dispatch_v2_SRV_FORCE},
		{NAME_MSGNAME_M1V2_SRVRENEW,    (hook) meta1_dispatch_all, meta1_dispatch_v2_SRV_RENEW},
		{NAME_MSGNAME_M1V2_SRVCONFIG,   (hook) meta1_dispatch_all, meta1_dispatch_v2_SRV_CONFIG},

		{NAME_MSGNAME_M1V2_PROPGET,     (hook) meta1_dispatch_all, meta1_dispatch_v2_PROPGET},
		{NAME_MSGNAME_M1V2_PROPSET,     (hook) meta1_dispatch_all, meta1_dispatch_v2_PROPSET},
		{NAME_MSGNAME_M1V2_PROPDEL,     (hook) meta1_dispatch_all, meta1_dispatch_v2_PROPDEL},

		{NAME_MSGNAME_M1V2_SRVALLONM1,  (hook) meta1_dispatch_all, meta1_dispatch_v2_SRV_ALLONM1},
		{NAME_MSGNAME_M1V2_GETPREFIX,	(hook) meta1_dispatch_all, meta1_dispatch_v2_GET_PREFIX},

		{NAME_MSGNAME_M1V2_SRVRELINK,   (hook) meta1_dispatch_all, meta1_dispatch_v2_SRVRELINK},

		{NULL, NULL, NULL}
	};

	return descriptions;
}

