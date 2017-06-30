/*
OpenIO SDS cluster
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

#define MODULE_NAME "conscience"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fnmatch.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <glob.h>

#include <zmq.h>
#include <glib.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/common_variables.h>

#include <gridd/main/plugin.h>
#include <gridd/main/message_handler.h>
#include <gridd/main/srvalert.h>
#include <gridd/main/srvtimer.h>
#include <gridd/main/srvstats.h>

#include <cluster/lib/gridcluster.h>
#include <cluster/conscience/conscience.h>

#include "alerting.h"
#include "module.h"

#define SRVID_OF_ADDR(A) ((struct conscience_srvid_s*)(A))

struct conscience_request_counters
{
	guint64 info;
	guint64 get;
	guint64 list;
	guint64 remove;
	guint64 push;
};

struct srvget_s
{
	gboolean full;
	struct conscience_srvtype_s *srvtype;
	GByteArray *gba_body;
	guint srv_list_size;
	guint total_size;
	gchar str_ns[LIMIT_LENGTH_NSNAME];

	gboolean an_error_happened;

	/** List of all successive bodies to send */
	GSList *response_bodies;
};

typedef gint(*_cmd_handler_f) (struct request_context_s *);

struct cmd_s
{
	char *c;
	_cmd_handler_f h;
	guint64 *req_counter;
};

/* ------------------------------------------------------------------------- */

static gboolean flag_serialize_srvinfo_stats = DEF_SERIALIZE_SRVINFO_STATS;
static gboolean flag_serialize_srvinfo_tags = DEF_SERIALIZE_SRVINFO_TAGS;

static time_t time_default_alert_frequency = TIME_DEFAULT_ALERT_LIMIT;

static struct conscience_s *conscience = NULL;

static struct conscience_request_counters stats;

static GRecMutex counters_mutex;

static GRecMutex conscience_nsinfo_mutex;

static void
_reply_ctx_set_error(struct reply_context_s *ctx)
{
	reply_context_clear(ctx, FALSE);
	reply_context_set_message(ctx, gerror_get_code(ctx->warning), gerror_get_message(ctx->warning));
}

static void
_alert_service_with_zeroed_score(struct conscience_srv_s *srv)
{
	gsize str_id_size, i;
	gchar str_id[sizeof("conscience.%.*s.score") + LIMIT_LENGTH_SRVTYPE];
	time_t now = oio_ext_monotonic_seconds ();

	if (srv->time_last_alert < now - srv->srvtype->alert_frequency_limit) {
		str_id_size = g_snprintf(str_id, sizeof(str_id),"conscience.%.*s.score",
				LIMIT_LENGTH_SRVTYPE, srv->srvtype->type_name);

		/* ensure the service_type is in lowercase */
		for (i=sizeof("conscience.")-1; i<str_id_size ;i++) {
			gchar c = str_id[i];
			if (c=='.')
				break;
			str_id[i] = g_ascii_tolower(c);
		}

		SRV_SEND_ERROR(str_id,"[NS=%s][%s][SCORE=0] service=%.*s",
				conscience_get_nsname(conscience), srv->srvtype->type_name,
				sizeof(srv->description), srv->description);
		srv->time_last_alert = now;
	}
}

static void
init_reply_ctx_with_request(struct request_context_s *req, struct reply_context_s *rep)
{
	if (rep) {
		memset(rep, 0x00, sizeof(struct reply_context_s));
		rep->req_ctx = req;
	}
}

static void
save_counters(gpointer u)
{
#define CONSCIENCE_COUNTER_PREFIX "counter req.hits."
#define SAVE_COUNTER(N,F) do { srvstat_set_u64(CONSCIENCE_COUNTER_PREFIX N, stats.F); } while (0)
	(void)u;
	guint64 d = oio_ext_real_seconds ();
	srvstat_set_u64(CONSCIENCE_COUNTER_PREFIX "timestamp", d);

	SAVE_COUNTER(NAME_MSGNAME_CS_GET_NSINFO, info);
	SAVE_COUNTER(NAME_MSGNAME_CS_GET_SRV, get);
	SAVE_COUNTER(NAME_MSGNAME_CS_GET_SRVNAMES, list);
	SAVE_COUNTER(NAME_MSGNAME_CS_RM_SRV, remove);
	SAVE_COUNTER(NAME_MSGNAME_CS_PUSH_SRV, push);
}

static gboolean
service_expiration_notifier(struct conscience_srv_s *srv, gpointer u)
{
	(void) u;
	if (srv) GRID_INFO("Service expired [%s] (score=%d)",
			srv->description, srv->score.value);
	return TRUE;
}

static void
timer_expire_services(gpointer u)
{
	GSList *list_type_names;
	GError *error_local = NULL;
	struct conscience_s *cs = u;

	/* XXX start of critical section */
	conscience_lock_srvtypes(cs, 'r');
	list_type_names = conscience_get_srvtype_names(cs, NULL);
	conscience_unlock_srvtypes(cs);
	/* XXX end of critical section */

	if (!list_type_names) {
		if (error_local) {
			ERROR("[NS=%s] Failed to collect the service types names: %s",
				conscience_get_nsname(cs), gerror_get_message(error_local));
			g_error_free(error_local);
		}
		return;
	}

	for (GSList *l = list_type_names; l; l = g_slist_next(l)) {
		if (!l->data)
			continue;

		const char *str_name = l->data;
		guint count = 0;

		/* XXX start of critical section */
		struct conscience_srvtype_s *srvtype =
			conscience_get_locked_srvtype(cs, NULL, str_name, MODE_STRICT, 'r');
		if (!srvtype) {
			WARN("[NS=%s][SRVTYPE=%s] srvtype disappeared very quickly",
				conscience_get_nsname(cs), str_name);
			continue;
		}
		count = conscience_srvtype_zero_expired(srvtype,
				service_expiration_notifier, NULL);
		conscience_release_locked_srvtype(srvtype);
		/* XXX end of critical section */

		if (count)
			NOTICE("Expired [%u] [%s] services", count, str_name);
	}

	g_slist_foreach(list_type_names, g_free1, NULL);
	g_slist_free(list_type_names);
}

/* ------------------------------------------------------------------------- */

static GByteArray *
_conscience_srv_serialize(struct conscience_srv_s *srv)
{
	GError *err = NULL;
	GByteArray *gba;
	GPtrArray *tags = NULL;
	struct service_info_s *si;

	/* prepare the srvinfo */
	si = g_malloc0(sizeof(struct service_info_s));
	conscience_srv_fill_srvinfo(si, srv);

	if ((!flag_serialize_srvinfo_stats && !flag_serialize_srvinfo_tags)
			|| !si->tags || si->tags->len <= 0) {
		/* ignore all the tags */
		tags = si->tags;
		si->tags = NULL;
	}
	else if (flag_serialize_srvinfo_stats ^ flag_serialize_srvinfo_tags) {
		/* filter the tags */
		guint u;
		for (u=0; u < si->tags->len ;) {
			register gboolean _t, _s;
			struct service_tag_s *tag;

			tag = si->tags->pdata[u];
			_t = !flag_serialize_srvinfo_tags && g_str_has_prefix(tag->name, "tag.");
			_s = !flag_serialize_srvinfo_stats && g_str_has_prefix(tag->name, "stat.");
			if (_t || _s) {
				service_tag_destroy(tag);
				g_ptr_array_remove_index_fast(si->tags, u);
			}
			else
				u++;
		}
	}

	/* encode it and append to the pending body */
	if (!(gba = service_info_marshall_1(si, &err))) {
		WARN("service_info serialization error : %s", gerror_get_message(err));
		g_clear_error(&err);
	}

	if (tags)
		si->tags = tags;
	service_info_clean(si);
	return gba;
}

static void
_conscience_srv_prepare_cache(struct conscience_srv_s *srv)
{
	GByteArray *gba = _conscience_srv_serialize(srv);
	conscience_srv_clean_udata(srv);
	srv->app_data_type = SAD_PTR;
	srv->app_data.pointer.value = gba;
	srv->app_data.pointer.cleaner = metautils_gba_unref;
}

/* ------------------------------------------------------------------------- */

static volatile gboolean hub_running = FALSE;
static void *hub_zctx = NULL;
static void *hub_zpub = NULL;
static void *hub_zsub = NULL;
static GAsyncQueue *hub_queue = NULL;
static GThread *hub_thread_pub = NULL;
static GThread *hub_thread_sub = NULL;

static void
_et_bim_cest_dans_le_hub (gchar *m)
{
	if (*m) {
		zmq_send (hub_zpub, m, 1, ZMQ_SNDMORE);
		int rc = zmq_send (hub_zpub, m+1, strlen(m+1), ZMQ_DONTWAIT);
		if (rc > 0) {
			GRID_TRACE2("HUB published 1 service / %d bytes", rc);
		} else {
			GRID_INFO("HUB publish failed: (%d) %s", errno, strerror(errno));
		}
	}
	g_free (m);
}

static gpointer
hub_worker_pub (gpointer p)
{
	while (hub_running) {
		gchar *m = g_async_queue_timeout_pop (hub_queue, G_TIME_SPAN_SECOND);
		if (!m) continue;
		_et_bim_cest_dans_le_hub (m);
	}

	GRID_INFO("HUB worker waiting for the last events");
	for (;;) {
		gchar *m = g_async_queue_try_pop (hub_queue);
		if (!m) break;
		_et_bim_cest_dans_le_hub (m);
	}

	GRID_INFO("HUB worker exiting");
	return p;
}

static void
push_service(struct conscience_s *cs, struct service_info_s *si)
{
	/* XXX start of critical section */
	struct conscience_srvtype_s *srvtype =
		conscience_get_locked_srvtype(cs, NULL, si->type, MODE_STRICT, 'w');
	if (!srvtype) {
		ERROR("Service type [%s/%s] not found", conscience_get_nsname(cs), si->type);
	} else {
		struct conscience_srv_s *srv = conscience_srvtype_refresh(srvtype, si);
		if (srv) {
			/* shortcut for services tagged DOWN */
			if (!srv->locked) {
				gboolean bval = FALSE;
				struct service_tag_s *tag = service_info_get_tag(si->tags, NAME_TAGNAME_RAWX_UP);
				if (tag && service_tag_get_value_boolean(tag, &bval, NULL) && !bval) {
					srv->score.value = 0;
					_alert_service_with_zeroed_score(srv);
				}
			}
			/* Prepare the serialized form of the service */
			_conscience_srv_prepare_cache (srv);
		}
		conscience_release_locked_srvtype(srvtype);
		/* XXX end of critical section */
	}
}

static void
rm_service(struct conscience_s *cs, struct service_info_s *si)
{
	int str_desc_len;
	gchar str_desc[LIMIT_LENGTH_NSNAME + LIMIT_LENGTH_SRVTYPE + STRLEN_ADDRINFO];
	GError *error_local;
	struct conscience_srvid_s srvid;
	struct conscience_srvtype_s *srvtype;

	if (INFO_ENABLED()) {
		str_desc_len = g_snprintf(str_desc, sizeof(str_desc), "%s/%s/", conscience_get_nsname(cs), si->type);
		grid_addrinfo_to_string(&(si->addr), str_desc + str_desc_len, sizeof(str_desc) - str_desc_len);
		memcpy(&(srvid.addr), &(si->addr), sizeof(addr_info_t));
	}

	error_local = NULL;
	/* XXX start of critical section */
	srvtype = conscience_get_locked_srvtype(cs, &error_local, si->type, MODE_STRICT, 'w');
	if (!srvtype) {
		ERROR("Service type [%s] not found : %s", str_desc, gerror_get_message(error_local));
		if (error_local)
			g_error_free(error_local);
	}
	else {
		conscience_srvtype_remove_srv(srvtype, &srvid);
		conscience_release_locked_srvtype(srvtype);
		INFO("Service [%s] removed", str_desc);
	}
	/* XXX end of critical section */
}

static void
_on_push (const guint8 *b, gsize l)
{
	struct service_info_s *si = NULL;
	gchar *tmp = g_strndup ((gchar*)b, l);
	GError *err = service_info_load_json (tmp, &si, FALSE);
	g_free (tmp);
	if (err) {
		GRID_WARN("HUB: decoder error: (%d) %s", err->code, err->message);
		g_clear_error (&err);
	} else if (si) {
		push_service (conscience, si);
		service_info_clean (si);
	} else {
		g_assert_not_reached ();
	}
}

static void
_on_remove (const guint8 *b, gsize l)
{
	struct service_info_s *si = NULL;
	gchar *tmp = g_strndup ((gchar*)b, l);
	GError *err = service_info_load_json (tmp, &si, FALSE);
	g_free (tmp);

	if (err) {
		GRID_WARN("HUB: decoder error: (%d) %s",
				err->code, err->message);
		g_clear_error (&err);
	} else if (si) {
		rm_service (conscience, si);
		service_info_clean (si);
	} else {
		g_assert_not_reached ();
	}
}

static void
_on_flush (const guint8 *b, gsize l)
{
	gchar *tmp = g_strndup ((gchar*)b, l);
	/* XXX start of critical section */
	struct conscience_srvtype_s *srvtype =
		conscience_get_locked_srvtype(conscience, NULL, tmp, MODE_STRICT,'w');
	if (!srvtype) {
		GRID_ERROR("[NS=%s][SRVTYPE=%s] not found", conscience_get_nsname(conscience), tmp);
	} else {
		conscience_srvtype_flush(srvtype);
		conscience_release_locked_srvtype(srvtype);
	}
	/* XXX end ofcritical section */

	GRID_NOTICE("[NS=%s][SRVTYPE=%s] flush done!", conscience_get_nsname(conscience), srvtype->type_name);
	g_free (tmp);
}

static void
_on_each_message (void *zin, void (*hook) (const guint8 *, gsize))
{
	int rc;
	zmq_msg_t msg;
	zmq_msg_init (&msg);
	do {
		rc = zmq_msg_recv (&msg, zin, ZMQ_DONTWAIT);
		if (rc > 0 && hook)
			hook (zmq_msg_data(&msg), zmq_msg_size(&msg));
	} while (rc >= 0 && zmq_msg_more(&msg));
	zmq_msg_close (&msg);
}

static gpointer
hub_worker_sub (gpointer p)
{
	while (hub_running) {

		/* poll incoming messages */
		zmq_pollitem_t items[1] = {
			{hub_zsub, -1, ZMQ_POLLIN, 0},
		};
		int rc = zmq_poll (items, 1, 1000);
		if (rc == 0) continue;
		if (rc < 0) {
			if (errno == ETERM) break;
			if (errno == EINTR || errno == EAGAIN) continue;
			GRID_WARN("ZMQ poll error: (%d) %s", errno, strerror(errno));
			break;
		}
		GRID_TRACE2("HUB activity!");

		/* manage them */
		for (guint i=0; i<1024 ;++i) {
			zmq_msg_t msg;
			zmq_msg_init (&msg);
			rc = zmq_msg_recv (&msg, hub_zsub, ZMQ_DONTWAIT);
			if (rc < 0) {
				if (errno == ETERM) break;
				if (errno == EINTR || errno == EAGAIN) continue;
				GRID_WARN("ZMQ recv error: (%d) %s", errno, strerror(errno));
				break;
			}
			const char *action = (const char*) zmq_msg_data(&msg);
			const int more = zmq_msg_more(&msg);
			GRID_TRACE2 ("HUB message size=%d more=%d action=%c",
					rc, more, rc>0 ? *action : ' ');
			if (rc > 0) {
				if (more) {
					switch (*action) {
						case 'P':
							_on_each_message (hub_zsub, _on_push);
							break;
						case 'R':
							_on_each_message (hub_zsub, _on_remove);
							break;
						case 'F':
							_on_each_message (hub_zsub, _on_flush);
							break;
						default:
							_on_each_message (hub_zsub, NULL);
							break;
					}
				}
			}
			zmq_msg_close (&msg);
		}
	}

	return p;
}

static void
hub_publish_service (const struct service_info_s *si)
{
	if (!hub_queue)
		return;
	GString *encoded = g_string_sized_new (256);
	g_string_append_c (encoded, 'P');
	service_info_encode_json (encoded, si, TRUE);
	g_async_queue_push (hub_queue, g_string_free (encoded, FALSE));
}

static void
hub_remove_service (const struct service_info_s *si)
{
	if (!hub_queue)
		return;
	GString *encoded = g_string_sized_new (256);
	g_string_append_c (encoded, 'R');
	service_info_encode_json (encoded, si, TRUE);
	g_async_queue_push (hub_queue, g_string_free (encoded, FALSE));
}

static void
hub_flush_srvtype (const char *name)
{
	if (!hub_queue)
		return;
	GString *encoded = g_string_sized_new (256);
	g_string_append_c (encoded, 'F');
	g_string_append (encoded, name);
	g_async_queue_push (hub_queue, g_string_free (encoded, FALSE));
}

/* ------------------------------------------------------------------------- */

static GByteArray *
_conscience_srv_serialize_full(struct conscience_srv_s *srv)
{
	GError *err = NULL;
	GByteArray *gba;
	struct service_info_s *si;

	si = g_malloc0(sizeof(struct service_info_s));
	conscience_srv_fill_srvinfo(si, srv);

	if (!(gba = service_info_marshall_1(si, &err))) {
		WARN("service_info serialization error : %s", gerror_get_message(err));
		g_clear_error(&err);
	}

	service_info_clean(si);
	return gba;
}

static gboolean
_srvinfo_append(struct srvget_s *sg, struct conscience_srv_s *srv)
{
	GByteArray *gba;

	/* Serialize the service including its tags and stats */
	if (sg->full) {
		gba = _conscience_srv_serialize_full(srv);
		if (gba) {
			g_byte_array_append(sg->gba_body, gba->data, gba->len);
			g_byte_array_free(gba, TRUE);
			return TRUE;
		}
	}
	/* Reuse the serialized version of the service
	 * that was made at registration time (saves CPU) */
	else if (srv->app_data_type == SAD_PTR
		&& NULL != (gba = srv->app_data.pointer.value))
	{
		if (gba->len > 0) {
			g_byte_array_append(sg->gba_body, gba->data, gba->len);
			return TRUE;
		}
	}
	/* Serialize the service without its tags and stats */
	else if (NULL != (gba = _conscience_srv_serialize(srv))) {
		g_byte_array_append(sg->gba_body, gba->data, gba->len);
		sg->srv_list_size++;
		g_byte_array_free(gba, TRUE);
		return TRUE;
	}

	return FALSE;
}

static void
_srvget_reset_body(struct srvget_s *sg)
{
	static const guint8 header[] = { 0x30, 0x80 };

	if (!sg->gba_body)
		sg->gba_body = g_byte_array_sized_new(512);

	g_byte_array_set_size(sg->gba_body, 0);
	g_byte_array_append(sg->gba_body, header, sizeof(header));
}

static void
_srvget_close_body(struct srvget_s *sg)
{
	static const guint8 footer[] = { 0x00, 0x00 };
	g_byte_array_append(sg->gba_body, footer, sizeof(footer));
}

static gboolean
prepare_response_bodies(struct conscience_srv_s *srv, gpointer u)
{
	struct srvget_s *sg;

	if (!(sg = u))
		return FALSE;

	/* Lazy init */
	if (!sg->gba_body)
		_srvget_reset_body(sg);

	/* Append the given service if not NULL */
	if (srv && _srvinfo_append(sg, srv))
		sg->srv_list_size++;

	if (sg->srv_list_size >= NB_SRV_ELEMENTS || !srv) {

		_srvget_close_body(sg);

		/*
		 * Previously we used to answer to the client directly.
		 * But we are under a reader lock, and if the client is slow or
		 * times out, all other clients will wait for the lock (if there are
		 * writers, other readers are also blocked).
		 */
		sg->response_bodies = g_slist_prepend(sg->response_bodies,
				metautils_gba_dup(sg->gba_body));

		/* finally clean what have been replied */
		sg->total_size += sg->srv_list_size;
		sg->srv_list_size = 0;
		_srvget_reset_body(sg);
	}
	return TRUE;
}

static gboolean
reply_services(struct reply_context_s *reply_ctx, GSList *response_bodies)
{
	for (GSList *l = response_bodies; l; l = l->next) {
		GByteArray *body = l->data;
		reply_context_clear(reply_ctx, TRUE);
		reply_context_set_body(reply_ctx, body->data,
				body->len, REPLYCTX_DESTROY_ON_CLEAN|REPLYCTX_COPY);

		reply_context_set_message(reply_ctx, CODE_PARTIAL_CONTENT, "Partial content");

		if (!reply_context_reply(reply_ctx, &(reply_ctx->warning))) {
			return FALSE;
		}
	}

	reply_context_clear(reply_ctx, TRUE);
	reply_context_set_message(reply_ctx, CODE_FINAL_OK, "OK");
	return BOOL(reply_context_reply(reply_ctx, &(reply_ctx->warning)));
}

static gint
handler_get_service(struct request_context_s *req_ctx)
{
	gboolean rc = 0;

	struct srvget_s sg;
	memset(&sg, 0x00, sizeof(sg));
	sg.full = metautils_message_extract_flag(req_ctx->request, NAME_MSGKEY_FULL, FALSE);

	struct reply_context_s reply_ctx;
	init_reply_ctx_with_request(req_ctx, &reply_ctx);

	gsize data_size = 0;
	void *data = metautils_message_get_field(req_ctx->request, NAME_MSGKEY_TYPENAME, &data_size);
	if (!data) {
		GSETCODE(&(reply_ctx.warning), CODE_BAD_REQUEST, "Bad request: no/invalid TYPENAME field");
	} else {
		gchar **array_types = buffer_split(data, data_size, ",", 0);
		g_strlcpy(sg.str_ns, conscience_get_nsname(conscience), sizeof(sg.str_ns));

		/* XXX start of critical section */
		rc = conscience_run_srvtypes(conscience, &(reply_ctx.warning),
				SRVTYPE_FLAG_ADDITIONAL_CALL|SRVTYPE_FLAG_LOCK_ENABLE,
				array_types, prepare_response_bodies, &sg);
		/* XXX end of critical section */

		if (rc)
			rc = reply_services(&reply_ctx, sg.response_bodies);
		g_strfreev(array_types);
	}

	if (!rc) {
		ERROR("An error occured: %s", gerror_get_message(reply_ctx.warning));
		_reply_ctx_set_error(&(reply_ctx));
		reply_context_reply(&(reply_ctx),NULL);
	}

	if (sg.gba_body)
		g_byte_array_free(sg.gba_body, TRUE);
	g_slist_free_full(sg.response_bodies, metautils_gba_unref);
	if (reply_ctx.warning)
		reply_context_log_access(&reply_ctx, NULL);
	reply_context_clear(&(reply_ctx), TRUE);
	return 1;
}

/* ------------------------------------------------------------------------- */

static gint
handler_push_service(struct request_context_s *req_ctx)
{
	GSList *list_srvinfo = NULL;
	struct reply_context_s ctx = {0};
	init_reply_ctx_with_request(req_ctx, &(ctx));

	gsize data_size = 0;
	void *data = metautils_message_get_BODY(req_ctx->request, &data_size);
	if (!data) {
		ctx.warning = BADREQ("Missing body");
		goto errorLabel;
	}
	if (0 >= service_info_unmarshall(&list_srvinfo, data, data_size, NULL)) {
		ctx.warning = BADREQ("invalid ASN.1 body");
		goto errorLabel;
	}

	/*Now push each service and reply the success */
	guint count = 0;
	for (GSList *l = list_srvinfo; l; l = g_slist_next(l)) {
		struct service_info_s *si = l->data;
		if (!si || !metautils_addr_valid_for_connect(&si->addr)
				|| !oio_str_is_set(si->type))
			continue;
		push_service (conscience, si);
		hub_publish_service (si);
		++ count;
	}
	GRID_DEBUG("Pushed %u items", count);
	g_slist_free_full (list_srvinfo, (GDestroyNotify) service_info_clean);

	reply_context_set_message(&ctx, CODE_FINAL_OK, "OK");
	reply_context_reply(&ctx, NULL);
	reply_context_clear(&ctx, TRUE);
	return 1;
errorLabel:
	ERROR("An error occured : %s", gerror_get_message(ctx.warning));
	_reply_ctx_set_error(&ctx);
	reply_context_reply(&ctx, NULL);
	reply_context_log_access(&ctx, NULL);
	reply_context_clear(&ctx, TRUE);
	return 1;
}

static gint
handler_get_ns_info(struct request_context_s *req_ctx)
{
	struct reply_context_s ctx;
	GByteArray* gba = NULL;

	init_reply_ctx_with_request(req_ctx, &ctx);

	g_rec_mutex_lock(&conscience_nsinfo_mutex);
	gba = namespace_info_marshall(&(conscience->ns_info), &(ctx.warning));
	g_rec_mutex_unlock(&conscience_nsinfo_mutex);

	if (gba == NULL) {
		reply_context_set_message(&ctx, CODE_INTERNAL_ERROR, "BUG");
		reply_context_reply(&ctx, NULL);
		reply_context_log_access(&ctx, NULL);
	} else {
		reply_context_set_message(&ctx, CODE_FINAL_OK, "OK");
		reply_context_set_body(&ctx, gba->data, gba->len, REPLYCTX_DESTROY_ON_CLEAN);
		g_byte_array_free(gba, FALSE);
		reply_context_reply(&ctx, NULL);
	}

	reply_context_clear(&ctx, TRUE);
	return 1;
}

static gint
handler_get_services_types(struct request_context_s *req_ctx)
{
	struct reply_context_s ctx;
	GHashTableIter iterator;
	gpointer k, v;
	GByteArray *gba_names;

	init_reply_ctx_with_request(req_ctx, &(ctx));

	/* We avoid calling the similar feature from the conscience because
	 * it makes a deep copy of the list. We do not perform any blocking
	 * operation on the list, so we build ourselves a hollow copy and we
	 * marshal it. */

	GSList *namel = NULL;
	/* start of critical section */
	conscience_lock_srvtypes(conscience,'r');
	g_hash_table_iter_init(&iterator, conscience->srvtypes);
	while (g_hash_table_iter_next(&iterator, &k, &v)) {
		if (k) {
			/* no copy, this only works because the types of services are
			 * stable and never destroyed */
			namel = g_slist_prepend(namel, k);
		}
	}
	conscience_unlock_srvtypes(conscience);
	/* end of critical section */

	/* do not free the pointers, they haven't been copied */
	gchar **namev = (gchar**) metautils_list_to_array(namel);
	g_slist_free (namel);
	gba_names = STRV_encode_gba(namev);
	g_free(namev);

	/* Now we can manage the potential error and reply */
	if (!gba_names) {
		reply_context_set_message(&ctx, CODE_INTERNAL_ERROR,
				gerror_get_message(ctx.warning));
		reply_context_reply(&ctx, NULL);
		reply_context_log_access(&ctx, NULL);
	} else {
		reply_context_set_body(&ctx, gba_names->data, gba_names->len,
				REPLYCTX_DESTROY_ON_CLEAN);
		g_byte_array_free(gba_names, FALSE);
		reply_context_set_message(&ctx, CODE_FINAL_OK, "OK");
		reply_context_reply(&ctx, NULL);
	}

	reply_context_clear(&ctx, TRUE);
	return 1;
}

static gint
handler_rm_service(struct request_context_s *req_ctx)
{
	struct reply_context_s ctx = {0};

	init_reply_ctx_with_request(req_ctx, &(ctx));

	/*Get the body and unpack it as a list of services */
	if (metautils_message_has_BODY(req_ctx->request)) {
		GSList *list_srvinfo = NULL;

		gsize data_size = 0;
		void *data = metautils_message_get_BODY(req_ctx->request, &data_size);
		if (!data) {
			GSETCODE(&(ctx.warning), CODE_BAD_REQUEST, "No body");
			goto errorLabel;
		}
		if (0 >= service_info_unmarshall(&list_srvinfo, data, data_size, &(ctx.warning))) {
			GSETCODE(&(ctx.warning), CODE_BAD_REQUEST, "Invalid body: deserialization error");
			goto errorLabel;
		}

		NOTICE("[NS=%s] [%d] services to be removed", conscience_get_nsname(conscience), g_slist_length(list_srvinfo));

		/*Now push each service and reply the success */
		for (GSList *l = list_srvinfo; l; l = g_slist_next(l)) {
			if (l->data) {
				rm_service (conscience, l->data);
				hub_remove_service (l->data);
			}
		}
		g_slist_free_full (list_srvinfo, (GDestroyNotify) service_info_clean);
		reply_context_set_message(&ctx, CODE_FINAL_OK, "OK");
	}
	else {
		/* if a srvtype is present in headers, remove all services of that type. */
		gchar *strtype = metautils_message_extract_string_copy(req_ctx->request, NAME_MSGKEY_TYPENAME);
		if (strtype) {
			_on_flush ((guint8*)strtype, strlen(strtype));
			hub_flush_srvtype (strtype);
			reply_context_set_message(&ctx, CODE_FINAL_OK, "OK");
			g_free (strtype);
		} else {
			GSETCODE(&(ctx.warning), CODE_BAD_REQUEST, "Missing BODY or SRVTYPE");
			goto errorLabel;
		}
	}

	reply_context_reply(&ctx, NULL);
	reply_context_clear(&ctx, TRUE);
	return 1;

errorLabel:
	ERROR("Failed to remove the service : %s", gerror_get_message(ctx.warning));
	_reply_ctx_set_error(&ctx);
	reply_context_reply(&ctx, NULL);
	reply_context_log_access(&ctx, NULL);
	reply_context_clear(&ctx, TRUE);
	return 1;
}

/* ------------------------------------------------------------------------- */

static struct cmd_s *
module_find_handler(gchar * n, gsize l)
{
	static struct cmd_s CMD[] = {
		{NAME_MSGNAME_CS_GET_NSINFO, handler_get_ns_info, &(stats.info)},
		{NAME_MSGNAME_CS_GET_SRV, handler_get_service, &(stats.get)},
		{NAME_MSGNAME_CS_GET_SRVNAMES, handler_get_services_types, &(stats.list)},
		{NAME_MSGNAME_CS_PUSH_SRV, handler_push_service, &(stats.push)},
		{NAME_MSGNAME_CS_RM_SRV, handler_rm_service, &(stats.remove)},
		{NULL, NULL, NULL}
	};

	if (!n || !l)
		return NULL;

	for (struct cmd_s *c = CMD; c->c; c++) {
		if (0 == g_ascii_strncasecmp(c->c, n, l))
			return c;
	}

	return NULL;
}

static gint
plugin_matcher(MESSAGE m, void *param, GError ** err)
{
	(void)param, (void)err;
	EXTRA_ASSERT (m != NULL);

	gsize nameLen = 0;
	gchar *name = metautils_message_get_NAME(m, &nameLen);
	struct cmd_s *c = module_find_handler(name, nameLen);
	return c != NULL;
}

static gint
plugin_handler(MESSAGE m, gint cnx, void *param, GError ** err)
{
	(void)param, (void) err;
	EXTRA_ASSERT (m != NULL);

	gsize nameLen = 0;
	gchar *name = metautils_message_get_NAME(m, &nameLen);
	struct cmd_s *c = module_find_handler(name, nameLen);
	EXTRA_ASSERT (c != NULL);

	struct request_context_s ctx = {0};
	ctx.request = m;
	ctx.fd = cnx;
	gettimeofday(&(ctx.tv_start), NULL);

	g_rec_mutex_lock(&counters_mutex);
	*(c->req_counter) = *(c->req_counter) + 1;
	g_rec_mutex_unlock(&counters_mutex);

	return c->h(&ctx);
}

/* ------------------------------------------------------------------------- */

static gboolean
module_configure_srvtype(struct conscience_s *cs, GError ** err,
		const gchar * type, const gchar * what, const gchar * value)
{
	struct conscience_srvtype_s *srvtype;

	if (!what || !value) {
		GSETERROR(err, "Invalid Key/Value pair: %s/%s", what, value);
		return FALSE;
	}

	/*find the service type */
	if (0 == g_ascii_strcasecmp(type, "default"))
		srvtype = conscience_get_default_srvtype(cs);
	else
		srvtype = conscience_get_srvtype(cs, err, type, MODE_AUTOCREATE);
	if (!srvtype) {
		GSETERROR(err, "Failed to init a ServiceType");
		return FALSE;
	}

	/*adjust the parameter */
	if (0 == g_ascii_strcasecmp(what, KEY_SCORE_TIMEOUT)) {
		srvtype->score_expiration = g_ascii_strtoll(value, NULL, 10);
		INFO("[NS=%s][SRVTYPE=%s] score expiration set to [%ld] seconds",
				cs->ns_info.name, srvtype->type_name,
				srvtype->score_expiration);
		return TRUE;
	}
	else if (0 == g_ascii_strcasecmp(what, KEY_SCORE_VARBOUND)) {
		srvtype->score_variation_bound = g_ascii_strtoll(value, NULL, 10);
		INFO("[NS=%s][SRVTYPE=%s] score variation bound set to [%d]",
				cs->ns_info.name, srvtype->type_name,
				srvtype->score_variation_bound);
		return TRUE;
	}
	else if (0 == g_ascii_strcasecmp(what, KEY_SCORE_EXPR)) {
		if (conscience_srvtype_set_type_expression(srvtype, err, value)) {
			INFO("[NS=%s][SRVTYPE=%s] score expression set to [%s]",
					cs->ns_info.name, srvtype->type_name, value);
			return TRUE;
		}
		return FALSE;
	}
	else if (0 == g_ascii_strcasecmp(what, KEY_SCORE_LOCK)) {
		srvtype->lock_at_first_register = oio_str_parse_bool(value, TRUE);
		INFO("[NS=%s][SRVTYPE=%s] lock at first register: %s",
				cs->ns_info.name, srvtype->type_name,
				srvtype->lock_at_first_register? "yes":"no");
		return TRUE;
	}
	else if (0 == g_ascii_strcasecmp(what, KEY_ALERT_LIMIT)) {
		srvtype->alert_frequency_limit = g_ascii_strtoll(value, NULL, 10);
		INFO("[NS=%s][SRVTYPE=%s] Alert limit set to %ld", cs->ns_info.name,
				srvtype->type_name, srvtype->alert_frequency_limit);
	}

	WARN("[NS=%s][SRVTYPE=%s] parameter not recognized [%s] (ignored!)",
			cs->ns_info.name, srvtype->type_name, what);
	return TRUE;
}

static void
module_configure_srvpool(struct conscience_s *cs, GError ** err,
		const gchar *pool, const gchar * what, const gchar * value)
{
	EXTRA_ASSERT(pool != NULL);
	EXTRA_ASSERT(what != NULL && *what != '\0');

	if (!value || !*value) {
		GSETERROR(err, "value is empty");
		return;
	}

	GHashTable *svc_pools = cs->ns_info.service_pools;
	GByteArray *gba = g_hash_table_lookup(svc_pools, pool);
	if (!strcmp(what, KEY_POOL_TARGETS)) {
		/* Targets are passed without key, but must start with a digit */
		if (*value < '0' || *value > '9')
			return;
		if (!gba) {
			gba = metautils_gba_from_string(value);
			g_hash_table_insert(svc_pools, g_strdup(pool), gba);
		} else {
			g_byte_array_append(gba, (guint8*)";", 1);
			g_byte_array_append(gba, (guint8*)value, strlen(value));
		}
	} else {
		if (!gba) {
			gchar buf[256] = {0};
			g_snprintf(buf, sizeof(buf), "%s=%s", what, value);
			gba = metautils_gba_from_string(buf);
			g_hash_table_insert(svc_pools, g_strdup(pool), gba);
		} else {
			g_byte_array_append(gba, (guint8*)";", 1);
			g_byte_array_append(gba, (guint8*)what, strlen(what));
			g_byte_array_append(gba, (guint8*)"=", 1);
			g_byte_array_append(gba, (guint8*)value, strlen(value));
		}
	}
}

static GError *
fill_hashtable_with_group(GHashTable *ht, GKeyFile *conf_file, const gchar *group_name)
{
	gchar **keys = NULL;
	gchar *v = NULL;
	gsize size;
	GError *e = NULL;

	if (!g_key_file_has_group (conf_file, group_name)) {
		GSETCODE(&e, CODE_INTERNAL_ERROR, "No '%s' group in configuration", group_name);
		return e;
	}

	keys = g_key_file_get_keys (conf_file, group_name, &size, &e);
	if ( NULL != keys) {
		for (uint i = 0; i < g_strv_length(keys); i++) {
			v = g_key_file_get_value (conf_file, group_name, keys[i], &e);
			if (!v) {
				GSETERROR (&e, "Cannot get the value for [%s][%s]", group_name, keys[i]);
				break;
			}
			if (NULL != g_hash_table_lookup(ht, keys[i])) {
				WARN("Duplicate key [%s][%s], new value [%s]", group_name, keys[i], v);
			}
			g_hash_table_insert (ht, g_strdup(keys[i]), metautils_gba_from_string(v));
			g_free(v);
		}
		g_strfreev(keys);
		return e;
	}
	GSETCODE(&e, CODE_INTERNAL_ERROR, "Cannot get all keys of group '%s'", group_name);
	return e;
}

static GError *
module_init_storage_conf(struct conscience_s *cs, const gchar *filepath)
{
	GKeyFile *stg_conf_file = g_key_file_new();
	GError *e = NULL;

	// Case-insensitive comparison (reason for not using g_hash_table_lookup)
	void _check_for_keyword(gchar *key, gpointer value, gchar **what) {
		NOTICE("%s %s", what[1], key);
		(void) value;
		if (!g_ascii_strcasecmp(what[0], key)) {
			WARN("Redefining '%s' %s, this may not be taken into account",
					key, what[1]);
		}
	}

	if (!filepath || !g_key_file_load_from_file (stg_conf_file, filepath, G_KEY_FILE_NONE, &e)) {
		GSETERROR(&e, "Cannot parse storage configuration from file [%s]", filepath);
		g_key_file_free(stg_conf_file);
		return e;
	}

	// POLICIES
	cs->ns_info.storage_policy = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, metautils_gba_unref);
	e = fill_hashtable_with_group(cs->ns_info.storage_policy, stg_conf_file, NAME_GROUPNAME_STORAGE_POLICY);
	if (NULL != e) {
		g_prefix_error(&e, "Error collecting storage policy rules from file [%s]", filepath);
		g_key_file_free(stg_conf_file);
		return e;
	}
	g_hash_table_foreach(cs->ns_info.storage_policy,
			(GHFunc)_check_for_keyword, (gchar*[2]){STORAGE_POLICY_NONE, "storage policy"});

	// SECURITY
	cs->ns_info.data_security = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, metautils_gba_unref);
	e = fill_hashtable_with_group(cs->ns_info.data_security, stg_conf_file, NAME_GROUPNAME_DATA_SECURITY);
	if( NULL != e) {
		WARN("Data security rules not correctly loaded from file [%s] : %s", filepath, e->message);
		return e;
	}
	g_hash_table_foreach(cs->ns_info.data_security, (GHFunc)_check_for_keyword,
			(gchar*[2]){DATA_SECURITY_NONE, "data security"});

	INFO("[NS=%s] storage conf loaded successfully from file [%s]",
			cs->ns_info.name, filepath);
	g_key_file_free(stg_conf_file);
	return NULL;
}

static GError *
_load_service_type_section(struct conscience_s *cs, GKeyFile *svc_conf_file,
		const gchar *section)
{
	/*** sample **************************************************************
	[type:meta0]
	score_expr = root(3,((num stat.cpu)*(num stat.space)*(num stat.io)))
	score_variation_bound = 5
	score_timeout = 300
	lock_at_first_register = false
	*************************************************************************/
	const char *svc = section + strlen(GROUP_PREFIX_TYPE);
	GHashTable *content = g_hash_table_new_full(
			g_str_hash, g_str_equal, g_free, metautils_gba_unref);
	GError *err = fill_hashtable_with_group(content, svc_conf_file, section);
	if (err) {
		g_hash_table_destroy(content);
		return err;
	}
	void _configure_section(gchar *key, GByteArray *gba, gpointer u UNUSED) {
		GError *local_err = NULL;
		module_configure_srvtype(cs, &local_err, svc, key,
				(const char*)gba->data);  // FIXME: no '\0'
		if (local_err) {
			GRID_WARN("Failed to set %s for %s: %s",
					key, svc, local_err->message);
			g_clear_error(&local_err);
		}
	}
	g_hash_table_foreach(content, (GHFunc)_configure_section, NULL);
	g_hash_table_destroy(content);
	return err;
}

static GError *
_load_service_pool_section(struct conscience_s *cs, GKeyFile *svc_conf_file,
		const gchar *section)
{
	/*** sample **************************************************************
	[pool:rawx3]
	targets = 1,rawx-even,rawx;1,rawx-odd,rawx;1,rawx
	mask = FFFFFFFFFFFF0000
	mask_max_shift = 16
	nearby_mode=false
	*************************************************************************/
	const char *pool = section + strlen(GROUP_PREFIX_POOL);
	GHashTable *content = g_hash_table_new_full(
			g_str_hash, g_str_equal, g_free, metautils_gba_unref);
	GError *err = fill_hashtable_with_group(content, svc_conf_file, section);
	if (err) {
		g_hash_table_destroy(content);
		return err;
	}
	void _configure_section(gchar *key, GByteArray *gba, gpointer u UNUSED) {
		GError *local_err = NULL;
		module_configure_srvpool(cs, &local_err, pool, key,
				(const char*)gba->data);  // FIXME: no '\0'
		if (local_err) {
			GRID_WARN("Failed to set %s for %s: %s",
					key, pool, local_err->message);
			g_clear_error(&local_err);
		}
	}
	g_hash_table_foreach(content, (GHFunc)_configure_section, NULL);
	g_hash_table_destroy(content);
	return NULL;
}

static GError *
_module_init_service_conf(struct conscience_s *cs, const gchar *filepath)
{
	GError *err = NULL;
	GKeyFile *svc_conf_file = g_key_file_new();

	if (!g_key_file_load_from_file(svc_conf_file, filepath,
			G_KEY_FILE_NONE, &err)) {
		GRID_WARN("[NS=%s] service configuration from %s failed: %s",
				cs->ns_info.name, filepath, err->message);
		g_key_file_free(svc_conf_file);
		return err;
	} else {
		GRID_INFO("Loading service configuration from %s", filepath);
	}

	gchar **groups = g_key_file_get_groups(svc_conf_file, NULL);
	for (gchar **group = groups; groups && *group; group++) {
		if (g_str_has_prefix(*group, GROUP_PREFIX_POOL)) {
			err = _load_service_pool_section(cs, svc_conf_file, *group);
		} else if (g_str_has_prefix(*group, GROUP_PREFIX_TYPE)) {
			err = _load_service_type_section(cs, svc_conf_file, *group);
		} else {
			GRID_WARN("Unknown configuration group: [%s] in file %s",
					*group, filepath);
		}
		if (err) {
			GRID_WARN("%s", err->message);
			g_clear_error(&err);
		}
	}
	g_strfreev(groups);
	g_key_file_free(svc_conf_file);
	return err;
}

static GError *
module_init_service_conf_glob(struct conscience_s *cs, const gchar *pattern)
{
	GError *err = NULL;
	cs->ns_info.service_pools = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, metautils_gba_unref);

	glob_t globbuf;
	int rc = glob(pattern, GLOB_MARK|GLOB_NOSORT|GLOB_BRACE, NULL, &globbuf);
	switch (rc) {
	case 0:
		break;
	case GLOB_NOMATCH:
		GSETERROR(&err, "No file matched [%s]", pattern);
		break;
	default:
		GSETERROR(&err, "Failed to do pattern matching with [%s] (code %d)",
				pattern, rc);
		break;
	}

	for (char **path = globbuf.gl_pathv; !err && path && *path; path++) {
		if (g_str_has_suffix(*path, "/"))
			continue;
		err = _module_init_service_conf(cs, *path);
	}

	globfree(&globbuf);
	return err;
}

struct srvtype_init_s
{
	const gchar *name;
	const gchar *expr;
};

static gboolean
module_init_known_service_types(struct conscience_s *cs, GHashTable * params, GError ** err)
{
	static struct srvtype_init_s types_to_init[] = {
		{NAME_SRVTYPE_META0,EXPR_DEFAULT_META0},
		{NAME_SRVTYPE_META1,EXPR_DEFAULT_META1},
		{NAME_SRVTYPE_META2,EXPR_DEFAULT_META2},
		{NAME_SRVTYPE_RAWX,EXPR_DEFAULT_RAWX},
		{0,0}
	};

	struct conscience_srvtype_s *config;
	struct srvtype_init_s *type;

	(void)params;
	for (type=types_to_init; type->name && type->expr ; type++) {
		config = conscience_get_srvtype(cs, err, type->name, MODE_AUTOCREATE);
		if (!config) {
			GSETERROR(err, "[NS=%s][SRVTYPE=%s] Failed to init the service type", cs->ns_info.name, type->name);
			return FALSE;
		}

		conscience_srvtype_init(config);
		if (!conscience_srvtype_set_type_expression(config, err, type->expr)) {
			GSETERROR(err, "[NS=%s][SRVTYPE=%s] Failed to set expr=[%s]", cs->ns_info.name,
				type->name, type->expr);
			conscience_srvtype_destroy(config);
			return FALSE;
		}

		config->alert_frequency_limit = time_default_alert_frequency;
		NOTICE("[NS=%s][SRVTYPE=%s] service type init done", cs->ns_info.name, type->name);
	}

	return TRUE;
}

static gboolean
_is_in (gchar **tab, const char *u)
{
	if (!tab) return FALSE;
	while (*tab) {
		if (!strcmp(*(tab++), u))
			return TRUE;
	}
	return FALSE;
}

static gboolean
_init_hub (GHashTable *params)
{
	gchar *hub_me = g_hash_table_lookup(params, "hub.me");
	gchar *hub_group = g_hash_table_lookup(params, "hub.group");
	gchar **split_me = hub_me ? g_strsplit(hub_me, ",", -1) : NULL;

	GRID_DEBUG("HUB me[%s] group[%s]", hub_me, hub_group);
	if (!hub_me && !hub_group)
		return TRUE;

	void setint (void *z, int which, int val) {
		(void) zmq_setsockopt (z, which, &val, sizeof(val));
	}

	hub_running = TRUE;
	hub_queue = g_async_queue_new ();
	g_assert (hub_queue != NULL);
	hub_zctx = zmq_ctx_new ();
	g_assert (hub_zctx != NULL);
	hub_zsub = zmq_socket (hub_zctx, ZMQ_SUB);
	g_assert (hub_zsub != NULL);
	hub_zpub = zmq_socket (hub_zctx, ZMQ_PUB);
	g_assert (hub_zpub != NULL);

	setint (hub_zpub, ZMQ_RCVBUF, 16*1024*1024);
	zmq_setsockopt (hub_zsub, ZMQ_SUBSCRIBE, "P", 1); /* push / lock / unlock */
	zmq_setsockopt (hub_zsub, ZMQ_SUBSCRIBE, "R", 1); /* removal */
	zmq_setsockopt (hub_zsub, ZMQ_SUBSCRIBE, "F", 1); /* flush */
	if (split_me && *split_me) {
		for (gchar **t=split_me; *t ;++t) {
			int rc = zmq_bind (hub_zsub, *t);
			if (rc != 0) {
				int zerr = zmq_errno ();
				GRID_WARN("HUB bind error [%s]: (%d) %s", *t, zerr, zmq_strerror(zerr));
			} else {
				GRID_NOTICE("HUB bond to [%s]", *t);
			}
		}
	}

	setint (hub_zpub, ZMQ_LINGER, 1000);
	setint (hub_zpub, ZMQ_SNDBUF, 16*1024*1024);
	if (hub_group) {
		gchar **tokens = g_strsplit (hub_group, ",", -1);
		if (tokens) {
			for (gchar **t=tokens; *t ;++t) {
				if (_is_in (split_me, *t))
					continue;
				int rc = zmq_connect (hub_zpub, *t);
				if (rc != 0) {
					int zerr = zmq_errno ();
					GRID_WARN("HUB connect error [%s]: (%d) %s", *t, zerr, zmq_strerror(zerr));
				} else {
					GRID_NOTICE("HUB connected to [%s]", *t);
				}
			}
			g_strfreev (tokens);
		}
	}

	hub_thread_pub = g_thread_new ("hub-pub", hub_worker_pub, NULL);
	g_assert (hub_thread_pub != NULL);

	hub_thread_sub = g_thread_new ("hub-sub", hub_worker_sub, NULL);
	g_assert (hub_thread_sub != NULL);

	if (split_me) g_strfreev (split_me);
	g_free0 (hub_me);
	g_free0 (hub_group);
	return TRUE;
}

static gint
plugin_init(GHashTable * params, GError ** err)
{
	gchar *str, *ns_name = NULL;

	g_rec_mutex_init(&counters_mutex);
	g_rec_mutex_init(&conscience_nsinfo_mutex);

	/*NAMEPSACE name */
	if (!(ns_name = g_hash_table_lookup(params, KEY_NAMESPACE))) {
		GSETERROR(err, "The configuration must contain a '%s' key with the namespace name", KEY_NAMESPACE);
		return -1;
	}
	if (!(conscience = conscience_create_named(ns_name, err))) {
		GSETERROR(err, "Conscience allocation failure");
		return -1;
	}
	NOTICE("[NS=%s] Configuring a new conscience", ns_name);

	/* Serialization optimizations */
	str = g_hash_table_lookup(params, KEY_SERIALIZE_SRVINFO_TAGS);
	if (NULL != str)
		flag_serialize_srvinfo_tags = oio_str_parse_bool(str, DEF_SERIALIZE_SRVINFO_TAGS);
	NOTICE("[NS=%s] Tags in serialized service_info  [%s]", ns_name,
			(flag_serialize_srvinfo_tags ? "ENABLED" : "DISABLED"));

	str = g_hash_table_lookup(params, KEY_SERIALIZE_SRVINFO_STATS);
	if (NULL != str)
		flag_serialize_srvinfo_stats = oio_str_parse_bool(str, DEF_SERIALIZE_SRVINFO_STATS);
	NOTICE("[NS=%s] Stats in serialized service_info  [%s]", ns_name,
			(flag_serialize_srvinfo_stats ? "ENABLED" : "DISABLED"));

	/*Overall alerting maximum per-service frequency*/
	if (!(str = g_hash_table_lookup(params, KEY_ALERT_LIMIT)))
		NOTICE("[NS=%s] No overall alert_frequency_limit set, default kept to [%ld] seconds",
			ns_name, time_default_alert_frequency);
	else {
		time_default_alert_frequency = g_ascii_strtoll(str,NULL,10);
		NOTICE("[NS=%s] Overall alert_frequency_limit set to [%ld] seconds", ns_name, time_default_alert_frequency);
	}

	/* storage conf initialization */
	*err = module_init_storage_conf(conscience,
			g_hash_table_lookup(params, KEY_STG_CONF));
	if( NULL != *err ) {
		g_prefix_error(err, "[NS=%s] storage conf init failed", ns_name);
		goto error;
	}

	/* SERVICES initiation */
	if (!module_init_known_service_types(conscience, params, err)) {
		GSETERROR(err, "[NS=%s] known service types init failed", ns_name);
		goto error;
	}

	/* service conf initialization (new style) */
	*err = module_init_service_conf_glob(conscience,
			g_hash_table_lookup(params, KEY_SVC_CONF));
	if (*err) {
		g_prefix_error(err, "[NS=%s] service conf init failed",
				ns_name);
		goto error;
	}

	if (!_init_hub (params)) {
		GSETERROR(err, "Failed to prepare the Conscience's HUB");
		goto error;
	}

	/* Plugin/server stuff */
	if (!srvtimer_register_regular("conscience.expire", timer_expire_services, NULL, conscience, 5LL)) {
		GSETERROR(err, "Failed to register the conscience's dump callback");
		goto error;
	}
	if (!srvtimer_register_regular("conscience.stats", save_counters, NULL, NULL, 5LL)) {
		GSETERROR(err, "Failed to register the server's statistics callback");
		goto error;
	}
	if (!message_handler_add("conscience", plugin_matcher, plugin_handler, err)) {
		GSETERROR(err, "Failed to add a new server message handler");
		goto error;
	}

	/* TODO(jfs): remove this in further releases */
	/* Print a warning in an old-style option is met */
	do {
		GHashTableIter it = {0};
		gpointer k, v;
		gboolean option_old = FALSE, service_old = FALSE;
		g_hash_table_iter_init(&it, params);
		while (g_hash_table_iter_next(&it, &k, &v)) {
			option_old |= g_str_has_prefix((gchar*)k, "option.");
			service_old |= g_str_has_prefix((gchar*)k, "service.");
			if (!strcasecmp((gchar*)k, "chunk_size"))
				GRID_WARN("OLD STYLE OPTION [chunk_size]");
			if (!strcasecmp((gchar*)k, "meta0"))
				GRID_WARN("OLD STYLE OPTION [meta0]");
		}
		if (option_old)
			GRID_WARN("OLD STYLE OPTIONS detected [param_option.*]");
		if (service_old)
			GRID_WARN("OLD STYLE OPTIONS detected [param_service.*]");
	} while (0);

	return 1;
error:
	GRID_ERROR("Conscience loading failed: %s",
			*err?(*err)->message:"unknown error");
	conscience_destroy(conscience);
	conscience = NULL;
	return -1;
}

static gint
plugin_reload(GHashTable * params, GError ** err)
{
	g_rec_mutex_lock(&conscience_nsinfo_mutex);

	g_hash_table_destroy(conscience->ns_info.storage_policy);
	g_hash_table_destroy(conscience->ns_info.data_security);
	*err = module_init_storage_conf(conscience,
			g_hash_table_lookup(params, KEY_STG_CONF));
	if (NULL != *err) {
		g_prefix_error(err, "[NS=%s] storage conf init failed: ",
				conscience->ns_info.name);
	}

	g_rec_mutex_unlock(&conscience_nsinfo_mutex);

	return (*err == NULL) ? 1 : -1;
}

static gint
plugin_close(GError ** err)
{
	(void)err;
	if (conscience) {
		g_rec_mutex_clear(&counters_mutex);
		conscience_destroy(conscience);
		conscience = NULL;
	}
	return 1;
}

struct exported_api_s exported_symbol =
{
	MODULE_NAME,
	plugin_init,
	plugin_close,
	NULL,
	NULL
};

struct exported_api_s exported_symbol_v2 =
{
	MODULE_NAME,
	plugin_init,
	plugin_close,
	NULL,
	plugin_reload
};
