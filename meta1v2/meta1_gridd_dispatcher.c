/*
OpenIO SDS meta1v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021-2024 OVH SAS

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
#include <server/network_server.h>
#include <server/transport_gridd.h>

#include "./meta1_backend.h"
#include "./meta1_prefixes.h"
#include "./meta1_remote.h"
#include "./meta1_gridd_dispatcher.h"
#include "./internals.h"


static gboolean
meta1_dispatch_v2_USERCREATE(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, struct oio_url_s *url)
{
	reply->subject("url:%s\thexid:%s", oio_url_get(url, OIOURL_WHOLE), oio_url_get(url, OIOURL_HEXID));

	gsize length = 0;
	void *body = metautils_message_get_BODY(reply->request, &length);

	gchar **properties = NULL;
	GError *err = KV_decode_buffer(body, length, &properties);
	if (NULL != err) {
		reply->send_error(CODE_BAD_REQUEST, err);
	} else {
		err = meta1_backend_user_create(m1, url, properties);
		if (NULL != err) {
			reply->send_error(0, err);
		} else {
			reply->send_reply(CODE_FINAL_OK, "Created");
		}
	}
	g_strfreev(properties);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_USERDESTROY(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, struct oio_url_s *url)
{
	gboolean force = metautils_message_extract_flag(reply->request, NAME_MSGKEY_FORCE, FALSE);
	reply->subject("url:%s\thexid:%s\tforce_bool:%s",
	               oio_url_get(url, OIOURL_WHOLE),
	               oio_url_get(url, OIOURL_HEXID),
	               force ? "true" : "false");

	GError *err = meta1_backend_user_destroy(m1, url, force);
	if (NULL != err) {
		reply->send_error(0, err);
	} else {
		reply->send_reply(CODE_FINAL_OK, "OK");
	}

	return TRUE;
}

static gboolean
meta1_dispatch_v2_USERINFO(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, struct oio_url_s *url)
{
	reply->subject("url:%s\thexid:%s", oio_url_get(url, OIOURL_WHOLE), oio_url_get(url, OIOURL_HEXID));

	gchar **info = NULL;
	GError *err = meta1_backend_user_info(m1, url, &info);
	if (NULL != err) {
		reply->send_error(0, err);
	} else {
		reply->add_body(STRV_encode_gba(info));
		reply->send_reply(CODE_FINAL_OK, "OK");
	}

	g_strfreev(info);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_LINK(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, struct oio_url_s *url)
{
	gchar *srvtype = metautils_message_extract_string_copy(reply->request, NAME_MSGKEY_TYPENAME);
	gboolean dryrun = metautils_message_extract_flag(reply->request, NAME_MSGKEY_DRYRUN, FALSE);
	gboolean autocreate = metautils_message_extract_flag(reply->request, NAME_MSGKEY_AUTOCREATE, FALSE);
	reply->subject("url:%s\thexid:%s\tsrv_type:%s\tdryrun_bool:%s",
	                oio_url_get(url, OIOURL_WHOLE),
	                oio_url_get(url, OIOURL_HEXID),
	                srvtype, dryrun ? "true" : "false");

	gchar **result = NULL;
	gboolean flawed = FALSE;
	GError *err = meta1_backend_services_link(m1, url, srvtype, dryrun,
			autocreate, &result, &flawed);
	if (NULL != err) {
		reply->send_error(0, err);
	} else {
		if (flawed) {
			reply->subject("flawed:true");
			gchar metric_name[256] = {0};
			g_snprintf(metric_name, sizeof(metric_name),
					"lb.constraints.%s.flawed.count", srvtype);
			network_server_incr_stat(reply->client->server, metric_name);
		} else {
			reply->subject("flawed:false");
		}
		reply->add_body(STRV_encode_gba(result));
		reply->send_reply(CODE_FINAL_OK, "OK");
	}

	g_strfreev(result);
	g_free(srvtype);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_RENEW(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, struct oio_url_s *url)
{
	gboolean ac = metautils_message_extract_flag(reply->request, NAME_MSGKEY_AUTOCREATE, FALSE);
	gboolean dryrun = metautils_message_extract_flag(reply->request, NAME_MSGKEY_DRYRUN, FALSE);
	gchar *srvtype = metautils_message_extract_string_copy(reply->request, NAME_MSGKEY_TYPENAME);
	reply->subject("url:%s\thexid:%s\tsrv_type:%s\tdryrun_bool:%s",
	                oio_url_get(url, OIOURL_WHOLE),
	                oio_url_get(url, OIOURL_HEXID),
	                srvtype, dryrun ? "true" : "false");

	gchar **result = NULL;
	gboolean flawed = FALSE;
	GError *err = meta1_backend_services_poll(m1, url, srvtype, ac, dryrun,
			&result, &flawed);
	if (NULL != err) {
		reply->send_error(0, err);
	} else {
		if (flawed) {
			reply->subject("flawed:true");
			gchar metric_name[256] = {0};
			g_snprintf(metric_name, sizeof(metric_name),
					"lb.constraints.%s.flawed.count", srvtype);
			network_server_incr_stat(reply->client->server, metric_name);
		} else {
			reply->subject("flawed:false");
		}
		reply->add_body(STRV_encode_gba(result));
		reply->send_reply(CODE_FINAL_OK, "OK");
	}

	g_strfreev(result);
	g_free(srvtype);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_FORCE(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, struct oio_url_s *url)
{
	gboolean ac = metautils_message_extract_flag(reply->request, NAME_MSGKEY_AUTOCREATE, FALSE);
	gboolean force = metautils_message_extract_flag(reply->request, NAME_MSGKEY_FORCE, FALSE);
	reply->subject("url:%s\thexid:%s", oio_url_get(url, OIOURL_WHOLE), oio_url_get(url, OIOURL_HEXID));

	gchar *m1url = NULL;
	GError *err = metautils_message_extract_body_string(reply->request, &m1url);
	if (NULL != err) {
		reply->send_error(CODE_BAD_REQUEST, err);
	} else {
		reply->subject("url:%s\thexid:%s\tm1_url:%s", oio_url_get(url, OIOURL_WHOLE), oio_url_get(url, OIOURL_HEXID), m1url);
		err = meta1_backend_services_set(m1, url, m1url, ac, force);
		if (NULL != err) {
			reply->send_error(0, err);
		} else {
			reply->send_reply(CODE_FINAL_OK, "OK");
		}
	}

	g_free(m1url);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_CONFIG(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, struct oio_url_s *url)
{
	reply->subject("url:%s\thexid:%s", oio_url_get(url, OIOURL_WHOLE), oio_url_get(url, OIOURL_HEXID));

	gchar *m1url = NULL;
	GError *err = metautils_message_extract_body_string(reply->request, &m1url);
	if (NULL != err) {
		reply->send_error(CODE_BAD_REQUEST, err);
	} else {
		err = meta1_backend_services_config(m1, url, m1url);
		if (NULL != err) {
			reply->send_error(0, err);
		} else {
			reply->send_reply(CODE_FINAL_OK, "OK");
		}
	}

	g_free(m1url);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_UNLINK(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, struct oio_url_s *url)
{
	gchar **urlv = NULL;
	gchar *srvtype = metautils_message_extract_string_copy(reply->request, NAME_MSGKEY_TYPENAME);
	reply->subject("url:%s\thexid:%s\tsrv_type:%s", oio_url_get(url, OIOURL_WHOLE), oio_url_get(url, OIOURL_HEXID), srvtype);

	if (!srvtype) {
		reply->send_error(0, BADREQ("Missing srvtype"));
	} else {
		gsize length = 0;
		void *body = metautils_message_get_BODY(reply->request, &length);
		GError *err = STRV_decode_buffer(body, length, &urlv);
		if (NULL != err) {
			reply->send_error(CODE_BAD_REQUEST, err);
		} else {
			err = meta1_backend_services_unlink(m1, url, srvtype, urlv);
			if (NULL != err) {
				reply->send_error(0, err);
			} else {
				reply->send_reply(CODE_FINAL_OK, "OK");
			}
		}
	}

	g_strfreev(urlv);
	g_free(srvtype);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRV_LIST(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, struct oio_url_s *url)
{
	gchar *srvtype = metautils_message_extract_string_copy(reply->request, NAME_MSGKEY_TYPENAME);
	gboolean extended = metautils_message_extract_flag(reply->request, NAME_MSGKEY_EXTEND, FALSE);
	reply->subject("url:%s\thexid:%s\tsrv_type:%s", oio_url_get(url, OIOURL_WHOLE), oio_url_get(url, OIOURL_HEXID), srvtype);

	gchar **result = NULL;
	GError *err = meta1_backend_services_list(
			m1, url, srvtype, &result, oio_ext_get_deadline(), extended);
	if (NULL != err) {
		reply->send_error(0, err);
	} else {
		reply->add_body(STRV_encode_gba(result));
		reply->send_reply(CODE_FINAL_OK, "OK");
	}

	g_strfreev(result);
	g_free(srvtype);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_PROPGET(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, struct oio_url_s *url)
{
	reply->subject("url:%s\thexid:%s", oio_url_get(url, OIOURL_WHOLE), oio_url_get(url, OIOURL_HEXID));

	gsize length = 0;
	void *body = metautils_message_get_BODY(reply->request, &length);

	gchar **result = NULL;
	gchar **keys = NULL;
	GError *err = STRV_decode_buffer(body, length, &keys);
	if (NULL != err) {
		reply->send_error(CODE_BAD_REQUEST, err);
	} else {
		err = meta1_backend_get_container_properties(m1, url, keys, &result);
		if (NULL != err) {
			reply->send_error(0, err);
		} else {
			reply->add_body(KV_encode_gba(result));
			reply->send_reply(CODE_FINAL_OK, "OK");
		}
	}

	g_strfreev(keys);
	g_strfreev(result);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_PROPSET(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, struct oio_url_s *url)
{
	gboolean flush = metautils_message_extract_flag(reply->request, NAME_MSGKEY_FLUSH, FALSE);
	reply->subject("url:%s\thexid:%s", oio_url_get(url, OIOURL_WHOLE), oio_url_get(url, OIOURL_HEXID));

	gsize length = 0;
	void *body = metautils_message_get_BODY(reply->request, &length);

	gchar **props = NULL;
	GError *err = KV_decode_buffer(body, length, &props);
	if (NULL != err) {
		reply->send_error(CODE_BAD_REQUEST, err);
	} else {
		err = meta1_backend_set_container_properties(m1, url, props, flush);
		if (NULL != err) {
			reply->send_error(0, err);
		} else {
			reply->send_reply(CODE_FINAL_OK, "OK");
		}
	}

	g_strfreev(props);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_PROPDEL(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, struct oio_url_s *url)
{
	reply->subject("url:%s\thexid:%s", oio_url_get(url, OIOURL_WHOLE), oio_url_get(url, OIOURL_HEXID));

	gchar **keys = NULL;
	gsize length = 0;
	void *body = metautils_message_get_BODY(reply->request, &length);
	GError *err = STRV_decode_buffer(body, length, &keys);

	if (NULL != err) {
		reply->send_error(CODE_BAD_REQUEST, err);
	} else {
		err = meta1_backend_del_container_properties(m1, url, keys);
		if (err) {
			reply->send_error(0, err);
		} else {
			reply->send_reply(CODE_FINAL_OK, "OK");
		}
	}

	g_strfreev(keys);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_GET_PREFIX(struct gridd_reply_ctx_s *reply,
	struct meta1_backend_s *m1, gpointer ignored UNUSED)
{
	gchar **result = meta1_prefixes_get_all(meta1_backend_get_prefixes(m1));
	if (result)
		reply->add_body(STRV_encode_gba(result));
	reply->send_reply(CODE_FINAL_OK, "OK");
	g_strfreev(result);
	return TRUE;
}

static gboolean
meta1_dispatch_v2_SRVRELINK(struct gridd_reply_ctx_s *reply,
	struct meta1_backend_s *m1, struct oio_url_s *url)
{
	gchar **newset = NULL;
	gchar *kept = metautils_message_extract_string_copy(reply->request, NAME_MSGKEY_OLD);
	gchar *replaced = metautils_message_extract_string_copy(reply->request, NAME_MSGKEY_NOTIN);
	gboolean dryrun = metautils_message_extract_flag(reply->request, NAME_MSGKEY_DRYRUN, FALSE);
	reply->subject("url:%s\thexid:%s", oio_url_get(url, OIOURL_WHOLE), oio_url_get(url, OIOURL_HEXID));

	if (!url) {
		reply->send_error(0, BADREQ("Missing field (%s)", "url"));
	} else {
		gboolean flawed = FALSE;
		GError *err = meta1_backend_services_relink(m1, url, kept, replaced, dryrun, &newset, &flawed);
		if (NULL != err) {
			reply->send_error(0, err);
		} else {
			if (flawed) {
				reply->subject("flawed:true");
				struct meta1_service_url_s *meta1_url = meta1_unpack_url(kept);
				if (!meta1_url) {
					meta1_url = meta1_unpack_url(replaced);
				}
				gchar metric_name[256] = {0};
				g_snprintf(metric_name, sizeof(metric_name),
						"lb.constraints.%s.flawed.count", meta1_url->srvtype);
				network_server_incr_stat(reply->client->server, metric_name);
				g_free(meta1_url);
			} else {
				reply->subject("flawed:false");
			}
			reply->add_body(STRV_encode_gba(newset));
			reply->send_reply(CODE_FINAL_OK, "OK");
		}
	}

	g_free(kept);
	g_free(replaced);
	g_strfreev(newset);
	return TRUE;
}

/* ------------------------------------------------------------------------- */

typedef gboolean (*hook) (struct gridd_reply_ctx_s *, gpointer, gpointer);


typedef gboolean (*action) (struct gridd_reply_ctx_s *, struct meta1_backend_s *, struct oio_url_s *u);


static gboolean meta1_dispatch_all(struct gridd_reply_ctx_s *reply,
		struct meta1_backend_s *m1, gpointer callback)
{
	gboolean force_master = FALSE;
	GError *err = NULL;

	/* Extract force master */
	err = metautils_message_extract_boolean(reply->request,
			NAME_MSGKEY_FORCE_MASTER, FALSE, &force_master);
	if (err) {
		reply->send_error(0, err);
		return TRUE;
	}
	oio_ext_set_force_master(force_master);

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

	oio_ext_set_force_master(FALSE);
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

		{NAME_MSGNAME_M1V2_GETPREFIX,	(hook) meta1_dispatch_all, meta1_dispatch_v2_GET_PREFIX},

		{NAME_MSGNAME_M1V2_SRVRELINK,   (hook) meta1_dispatch_all, meta1_dispatch_v2_SRVRELINK},

		{NULL, NULL, NULL}
	};

	return descriptions;
}

