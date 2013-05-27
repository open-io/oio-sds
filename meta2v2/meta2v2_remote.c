/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "m2.remote"
#endif

#include <errno.h>
#include <strings.h>

#include "../metautils/lib/metacomm.h"
#include "../metautils/lib/metautils.h"
#include "../metautils/lib/metatypes.h"
#include "../metautils/lib/hc_url.h"
#include "../metautils/lib/gridd_client.h"

#include "./meta2_macros.h"
#include "./meta2v2_remote.h"
#include "./meta2_bean.h"

#define GBA_POOL_CLEAN(P) g_slist_free_full((P), (GDestroyNotify)metautils_gba_unref)

static GByteArray *
gba_poolify(GSList **pool, GByteArray *gba)
{
	if (!gba)
		return NULL;
	*pool = g_slist_prepend(*pool, gba);
	return gba;
}

static GByteArray *
_url_2_gba(struct hc_url_s *url)
{
	GByteArray *gba = g_byte_array_new();
	if (hc_url_get_id(url))
		g_byte_array_append(gba, hc_url_get_id(url), hc_url_get_id_size(url));
	return gba;
}

static MESSAGE
_m2v2_build_request(const gchar *name, GByteArray *sid,
		struct hc_url_s *url, GByteArray *body)
{
	struct message_s *msg;
	GSList *pool = NULL;

	ASSERT_EXTRA(url != NULL);
	msg = message_create_request(NULL, sid, name,
			body ? gba_poolify(&pool, body) : NULL,
			"HC_URL", gba_poolify(&pool,
				metautils_gba_from_string(hc_url_get(url, HCURL_WHOLE))),
			"NAMESPACE", gba_poolify(&pool,
				metautils_gba_from_string(hc_url_get(url, HCURL_NS))),
			"CONTAINER_ID", gba_poolify(&pool,
				_url_2_gba(url)),
			NULL);
	GBA_POOL_CLEAN(pool);

	return msg;
}

static GByteArray *
_m2v2_pack_request(const gchar *name, GByteArray *sid,
		struct hc_url_s *url, GByteArray *body)
{
	return message_marshall_gba_and_clean(
			_m2v2_build_request(name, sid, url, body));
}

static GByteArray *
_m2v2_pack_request_with_flags(const gchar *name, GByteArray *sid,
		struct hc_url_s *url, GByteArray *body, guint32 flags)
{
	struct message_s *msg;

	msg = _m2v2_build_request(name, sid, url, body);
	flags = g_htonl(flags);
	(void) message_add_field(msg, "FLAGS", sizeof("FLAGS")-1,
			&flags, sizeof(flags), NULL);
	return message_marshall_gba_and_clean(msg);
}

GByteArray*
m2v2_remote_pack_CREATE(GByteArray *sid, struct hc_url_s *url,
		struct m2v2_create_params_s *pols)
{
	struct message_s *msg;

	msg = _m2v2_build_request("M2V2_CREATE", sid, url, NULL);
	if (pols->storage_policy) {
		(void) message_add_field(msg,
				M2_KEY_STORAGE_POLICY, sizeof(M2_KEY_STORAGE_POLICY)-1,
				pols->storage_policy, strlen(pols->storage_policy),
				NULL);
	}
	if (pols->version_policy) {
		(void) message_add_field(msg,
				M2_KEY_VERSION_POLICY, sizeof(M2_KEY_VERSION_POLICY)-1,
				pols->version_policy, strlen(pols->version_policy),
				NULL);
	}
	return message_marshall_gba_and_clean(msg);
}

GByteArray*
m2v2_remote_pack_DESTROY(GByteArray *sid, struct hc_url_s *url)
{
	return _m2v2_pack_request("M2V2_DESTROY", sid, url, NULL);
}

GByteArray*
m2v2_remote_pack_OPEN(GByteArray *sid, struct hc_url_s *url)
{
	return _m2v2_pack_request("M2V2_OPEN", sid, url, NULL);
}

GByteArray*
m2v2_remote_pack_CLOSE(GByteArray *sid, struct hc_url_s *url)
{
	return _m2v2_pack_request("M2V2_CLOSE", sid, url, NULL);
}

GByteArray*
m2v2_remote_pack_HAS(GByteArray *sid, struct hc_url_s *url)
{
	return _m2v2_pack_request("M2V2_HAS", sid, url, NULL);
}

GByteArray*
m2v2_remote_pack_PURGE(GByteArray *sid, struct hc_url_s *url)
{
	return _m2v2_pack_request("M2V2_PURGE", sid, url, NULL);
}

GByteArray*
m2v2_remote_pack_DEDUP(GByteArray *sid, struct hc_url_s *url)
{
	return _m2v2_pack_request("M2V2_DEDUP", sid, url, NULL);
}

GByteArray*
m2v2_remote_pack_PUT(GByteArray *sid, struct hc_url_s *url, GSList *beans)
{
	GByteArray *body = bean_sequence_marshall(beans);
	return _m2v2_pack_request("M2V2_PUT", sid, url, body);
}

GByteArray*
m2v2_remote_pack_APPEND(GByteArray *sid, struct hc_url_s *url, GSList *beans)
{
	GByteArray *body = bean_sequence_marshall(beans);
	return _m2v2_pack_request("M2V2_APPEND", sid, url, body);
}

GByteArray*
m2v2_remote_pack_DEL(GByteArray *sid, struct hc_url_s *url)
{
	return _m2v2_pack_request("M2V2_DEL", sid, url, NULL);
}

GByteArray*
m2v2_remote_pack_GET(GByteArray *sid, struct hc_url_s *url, guint32 flags)
{
	return _m2v2_pack_request_with_flags("M2V2_GET", sid, url, NULL, flags);
}

GByteArray*
m2v2_remote_pack_LIST(GByteArray *sid, struct hc_url_s *url, guint32 flags)
{
	return _m2v2_pack_request_with_flags("M2V2_LIST", sid, url, NULL, flags);
}

GByteArray*
m2v2_remote_pack_PROP_SET(GByteArray *sid, struct hc_url_s *url, GSList *beans)
{
	GByteArray *body = bean_sequence_marshall(beans);
	return _m2v2_pack_request("M2V2_PROP_SET", sid, url, body);
}

GByteArray*
m2v2_remote_pack_PROP_GET(GByteArray *sid, struct hc_url_s *url, guint32 flags)
{
	return _m2v2_pack_request_with_flags("M2V2_PROP_GET", sid, url, NULL, flags);
}

GByteArray*
m2v2_remote_pack_BEANS(GByteArray *sid, struct hc_url_s *url,
		const gchar *pol, gint64 size, gboolean append)
{
	gchar strsize[128];
	struct message_s *msg;

	g_snprintf(strsize, sizeof(strsize), "%"G_GINT64_FORMAT, size);

	msg = _m2v2_build_request("M2V2_BEANS", sid, url, NULL);
	if(!append) {
		message_add_fields_str(msg,
				NAME_MSGKEY_CONTENTLENGTH, strsize,
				"STORAGE_POLICY", pol, NULL);
	} else {
		message_add_fields_str(msg,
				NAME_MSGKEY_CONTENTLENGTH, strsize,
				"APPEND", "true",
				"STORAGE_POLICY", pol, NULL);
	}
	/* si policy est NULL, le paramètre ne sera pas ajouté. On profite que
	 * ce soit ldernier argument de la liste */
	return message_marshall_gba_and_clean(msg);
}

GByteArray*
m2v2_remote_pack_STGPOL(GByteArray *sid, struct hc_url_s *url,
		const gchar *pol)
{
	struct message_s *msg;

	msg = _m2v2_build_request("M2V2_STGPOL", sid, url, NULL);
	message_add_fields_str(msg, "STORAGE_POLICY", pol, NULL);
	return message_marshall_gba_and_clean(msg);
}

/* ------------------------------------------------------------------------- */

static GError*
_m2v2_request(const gchar *url, GByteArray *req, GSList **out)
{
	GError *err;
	struct client_s *client;
	
	auto gboolean _cb(gpointer ctx, struct message_s *reply);

	gboolean _cb(gpointer ctx, struct message_s *reply) {
		GSList *l = NULL;
		GError *e = NULL;
		if (0 < message_has_BODY(reply, NULL)) {
			e = message_extract_body_encoded(reply, &l, bean_sequence_decoder);
		}
		if (!e) {
			if (l) {
				*((GSList**)ctx) = g_slist_concat(*((GSList**)ctx), l);
			}
			return TRUE;
		}
		else {
			GRID_DEBUG("Callback error : %s", e->message);
			err = e;
			return FALSE;
		}
	}

	ASSERT_EXTRA(url != NULL);
	ASSERT_EXTRA(req != NULL);

	client = gridd_client_create_idle(url);
	if (!client) {
		err = g_error_new(g_quark_from_static_string(G_LOG_DOMAIN),
				2, "errno=%d %s", errno, strerror(errno));
	}
	else {
		gridd_client_start(client);
		err = gridd_client_request(client, req, out, out ? _cb : NULL);
		if (!err) {
			if (!(err = gridd_client_loop(client))) {
				err = gridd_client_error(client);
			}
		}
		gridd_client_free(client);
	}

	return err;
}

GError*
m2v2_remote_execute_CREATE(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, struct m2v2_create_params_s *pols)
{
	return _m2v2_request(target, m2v2_remote_pack_CREATE(sid, url, pols), NULL);
}

GError*
m2v2_remote_execute_DESTROY(const gchar *target, GByteArray *sid,
		struct hc_url_s *url)
{
	return _m2v2_request(target, m2v2_remote_pack_DESTROY(sid, url), NULL);
}

GError*
m2v2_remote_execute_OPEN(const gchar *target, GByteArray *sid,
		struct hc_url_s *url)
{
	return _m2v2_request(target, m2v2_remote_pack_OPEN(sid, url), NULL);
}

GError*
m2v2_remote_execute_CLOSE(const gchar *target, GByteArray *sid,
		struct hc_url_s *url)
{
	return _m2v2_request(target, m2v2_remote_pack_CLOSE(sid, url), NULL);
}

GError*
m2v2_remote_execute_HAS(const gchar *target, GByteArray *sid,
		struct hc_url_s *url)
{
	return _m2v2_request(target, m2v2_remote_pack_HAS(sid, url), NULL);
}

GError*
m2v2_remote_execute_BEANS(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, const gchar *pol, gint64 size,
		gboolean append, GSList **out) 
{
	return _m2v2_request(target, m2v2_remote_pack_BEANS(sid, url, pol, size, append), out);
}

GError*
m2v2_remote_execute_STGPOL(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, const char *pol, GSList **out)
{
	return _m2v2_request(target, m2v2_remote_pack_STGPOL(sid, url, pol), out);
}

GError*
m2v2_remote_execute_PUT(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, GSList *in, GSList **out)
{
	return _m2v2_request(target, m2v2_remote_pack_PUT(sid, url, in), out);
}

GError*
m2v2_remote_execute_APPEND(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, GSList *in, GSList **out)
{
	return _m2v2_request(target, m2v2_remote_pack_APPEND(sid, url, in), out);
}

GError*
m2v2_remote_execute_PURGE(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, GSList **out)
{
        return _m2v2_request(target, m2v2_remote_pack_PURGE(sid, url), out);
}

GError*
m2v2_remote_execute_DEDUP(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, gchar **out)
{
	struct client_s *client;
	GError *err = NULL;
	
	auto gboolean _cb(gpointer ctx, struct message_s *reply);

	gboolean _cb(gpointer ctx, struct message_s *reply) {
		GError *e = NULL;
		if (0 < message_has_BODY(reply, NULL)) {
			e = message_extract_body_string(reply, (gchar**)ctx);
		}
		if (!e)
			return TRUE;
		else {
			err = e;
			return FALSE;
		}
	}

	client = gridd_client_create_idle(target);
	if (!client) {
		err = g_error_new(g_quark_from_static_string(G_LOG_DOMAIN),
				2, "errno=%d %s", errno, strerror(errno));
	}
	else {
		gridd_client_start(client);
		err = gridd_client_request(client, m2v2_remote_pack_DEDUP(sid, url), out, out ? _cb : NULL);
		if (!err) {
			if (!(err = gridd_client_loop(client))) {
				err = gridd_client_error(client);
			}
		}
		gridd_client_free(client);
	}

#if 0
	/* There should be only one result */
	if (_out != NULL && _out->data != NULL) {
		gchar buf[1024];
		memset(buf, '\0', 1024);
		metautils_gba_data_to_string(_out->data, buf, 1024);
		*out = g_strdup(buf);
	}
	g_slist_free(_out);
#endif
	return err;
}

GError*
m2v2_remote_execute_GET(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, guint32 flags, GSList **out)
{
	return _m2v2_request(target, m2v2_remote_pack_GET(sid, url, flags), out);
}

GError*
m2v2_remote_execute_DEL(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, GSList **out)
{
	return _m2v2_request(target, m2v2_remote_pack_DEL(sid, url), out);
}

GError*
m2v2_remote_execute_LIST(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, guint32 flags, GSList **out)
{
	return _m2v2_request(target, m2v2_remote_pack_LIST(sid, url, flags), out);
}

GError*
m2v2_remote_execute_PROP_SET(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, GSList *in)
{
	return _m2v2_request(target, m2v2_remote_pack_PROP_SET(sid, url, in), NULL);
}

GError*
m2v2_remote_execute_PROP_GET(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, guint32 flags, GSList **out)
{
	return _m2v2_request(target, m2v2_remote_pack_PROP_GET(sid, url, flags), out);
}
