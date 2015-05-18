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
#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN MODULE_NAME".plugin"
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fnmatch.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

#include <glib.h>

#include <metautils/lib/metautils.h>

#include <gridd/main/plugin.h>
#include <gridd/main/message_handler.h>
#include <gridd/main/srvalert.h>
#include <gridd/main/srvtimer.h>
#include <gridd/main/srvstats.h>

#include <cluster/lib/gridcluster.h>
#include <cluster/conscience/conscience.h>
#include <cluster/conscience/conscience_broken_holder_common.h>

#include "alerting.h"
#include "module.h"

#define SRVID_OF_ADDR(A) ((struct conscience_srvid_s*)(A))

struct conscience_request_counters
{
	guint32 ns_info;
	struct
	{
		guint32 add;
		guint32 get;
		guint32 remove;
		guint32 push_stat;
		guint32 push_score;
		guint32 push_vns;
	} services;
	struct
	{
		guint32 push;
		guint32 get;
		guint32 remove;
		guint32 fix;
	} broken;
};

/**
 * Used by handler_get_broken_containers() as tha arbitrary user
 * data passed to the callback appllied on each broken element.
 */
struct brkget_s
{
	GError *error;
	guint lines_length;
	GSList *lines;
	struct reply_context_s reply_ctx;
};

struct srvget_s
{
	gboolean full;
	struct conscience_srvtype_s *srvtype;
	GByteArray *gba_body;
	guint srv_list_size;
	guint total_size;
	gchar str_ns[LIMIT_LENGTH_NSNAME + 1];

	gboolean an_error_happened;

	/** List of all successive bodies to send */
	GSList *response_bodies;
};

typedef gint(*_cmd_handler_f) (struct request_context_s *);

struct cmd_s
{
	char *c;
	_cmd_handler_f h;
	guint32 *req_counter;
};

static void _alert_service_with_zeroed_score(struct conscience_srv_s *srv);

/* ------------------------------------------------------------------------- */

static gboolean flag_serialize_srvinfo_cache = DEF_SERIALIZE_SRVINFO_CACHED;
static gboolean flag_serialize_srvinfo_stats = DEF_SERIALIZE_SRVINFO_STATS;
static gboolean flag_serialize_srvinfo_tags = DEF_SERIALIZE_SRVINFO_TAGS;

static time_t time_default_alert_frequency = TIME_DEFAULT_ALERT_LIMIT;

static struct conscience_s *conscience = NULL;

static struct conscience_request_counters stats;

static GRecMutex counters_mutex;

static GRecMutex conscience_nsinfo_mutex;

static gboolean flag_forced_meta0 = FALSE;

static void
_reply_ctx_set_error(struct reply_context_s *ctx)
{
	reply_context_clear(ctx, FALSE);
	reply_context_set_message(ctx, gerror_get_code(ctx->warning), gerror_get_message(ctx->warning));
}

static void
_alert_service_with_zeroed_score(struct conscience_srv_s *srv)
{
	gchar c;
	gsize str_id_size, i;
	gchar str_id[sizeof("conscience.%.*s.score") + LIMIT_LENGTH_SRVTYPE + 1];
	time_t now;

	now = time(0);
	if (srv->time_last_alert < now - srv->srvtype->alert_frequency_limit) {
		str_id_size = g_snprintf(str_id, sizeof(str_id),"conscience.%.*s.score",
				LIMIT_LENGTH_SRVTYPE, srv->srvtype->type_name);

		/* ensure the service_type is in lowercase */
		for (i=sizeof("conscience.")-1; i<str_id_size ;i++) {
			c = str_id[i];
			if (c=='.')
				break;
			str_id[i] = g_ascii_tolower(c);
		}

		SRV_SEND_ERROR(str_id,"[NS=%s][%s][SCORE=0] service=%.*s",
				conscience_get_namespace(conscience), srv->srvtype->type_name,
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
	double d;

#define CONSCIENCE_COUNTER_PREFIX "conscience.req.counter."
#define SAVE_COUNTER(F) do { d=stats.F ; srvstat_set( CONSCIENCE_COUNTER_PREFIX #F, d ); } while (0)
	(void)u;
	d = time(0);
	srvstat_set(CONSCIENCE_COUNTER_PREFIX "timestamp", d);

	SAVE_COUNTER(ns_info);

	SAVE_COUNTER(services.add);
	SAVE_COUNTER(services.get);
	SAVE_COUNTER(services.remove);
	SAVE_COUNTER(services.push_stat);
	SAVE_COUNTER(services.push_score);

	SAVE_COUNTER(broken.push);
	SAVE_COUNTER(broken.fix);
	SAVE_COUNTER(broken.get);
	SAVE_COUNTER(broken.remove);
}

static gboolean
service_checker( struct conscience_srv_s * srv, gpointer u)
{
	if (!u)
		return FALSE;
	if (srv) {
		if (!srv->locked) {
			if (srv->score.value < 0)
				srv->score.value = 0;
			else if (srv->score.value > 100)
				srv->score.value = 100;
		}
		if (srv->score.timestamp > *((time_t*)u))
			srv->score.timestamp = *((time_t*)u);
	}
	return TRUE;
}

static gboolean
service_expiration_notifier(struct conscience_srv_s *srv, gpointer u)
{
	(void)u;
	if (srv)
		WARN("Service expired : [%s]", srv->description);
	return TRUE;
}

static void
timer_check_services(gpointer u)
{
	time_t now;
	GError *error_local;
	struct conscience_s *cs;
	GSList *list_type_names, *l;

	cs = u;
	error_local = NULL;

	/* XXX start of critical section */
	conscience_lock_srvtypes(cs,'r');
	list_type_names = conscience_get_srvtype_names(cs,NULL);
	conscience_unlock_srvtypes(conscience);
	/* XXX end of critical section */

	if (!list_type_names) {
		if (error_local) {
			ERROR("[NS=%s] Failed to collect the service types names : %s",
				conscience_get_namespace(cs), gerror_get_message(error_local));
			g_error_free(error_local);
		}
		return;
	}

	now = time(0);
	for (l=list_type_names; l ;l=g_slist_next(l)) {
		gboolean rc;
		gchar *str_name;
		struct conscience_srvtype_s *srvtype;

		if (!l->data)
			continue;
		str_name = l->data;
		error_local = NULL;

		/* XXX start of critical section */
		srvtype = conscience_get_locked_srvtype(cs, NULL, str_name, MODE_STRICT, 'r');
		if (!srvtype) {
			WARN("[NS=%s][SRVTYPE=%s] srvtype disappeared very quickly",
				conscience_get_namespace(cs), str_name);
			continue;
		}
		rc = conscience_srvtype_run_all( srvtype, &error_local, SRVTYPE_FLAG_ADDITIONAL_CALL, service_checker, &now);
		conscience_release_locked_srvtype(srvtype);
		/* XXX end of critical section */

		if (!rc)
			ERROR("[NS=%s][SRVTYPE=%s] Failed to run the service check loop : %s",
				conscience_get_namespace(cs), str_name, gerror_get_message(error_local));
		if (error_local)
			g_error_free(error_local);
	}

	g_slist_foreach(list_type_names,g_free1,NULL);
	g_slist_free(list_type_names);
}

static void
timer_expire_services(gpointer u)
{
	GError *error_local;
	struct conscience_s *cs;
	GSList *list_type_names, *l;

	cs = u;
	error_local = NULL;

	/* XXX start of critical section */
	conscience_lock_srvtypes(cs,'r');
	list_type_names = conscience_get_srvtype_names(cs,NULL);
	conscience_unlock_srvtypes(cs);
	/* XXX end of critical section */

	if (!list_type_names) {
		if (error_local) {
			ERROR("[NS=%s] Failed to collect the service types names : %s",
				conscience_get_namespace(cs), gerror_get_message(error_local));
			g_error_free(error_local);
		}
		return;
	}

	for (l=list_type_names; l ;l=g_slist_next(l)) {
		gint rc;
		gchar *str_name;
		struct conscience_srvtype_s *srvtype;

		if (!l->data)
			continue;
		str_name = l->data;
		error_local = NULL;

		/* XXX start of critical section */
		srvtype = conscience_get_locked_srvtype(cs, NULL, str_name, MODE_STRICT, 'r');
		if (!srvtype) {
			WARN("[NS=%s][SRVTYPE=%s] srvtype disappeared very quickly",
				conscience_get_namespace(cs), str_name);
			continue;
		}
		rc = conscience_srvtype_remove_expired( srvtype, &error_local, service_expiration_notifier, NULL);
		conscience_release_locked_srvtype(srvtype);
		/* XXX end of critical section */

		if (rc<0)
			ERROR("[NS=%s][SRVTYPE=%s] Failed to remove the expired services : %s",
				conscience_get_namespace(cs), str_name, gerror_get_message(error_local));
		else if (rc>0)
			NOTICE("[NS=%s][SRVTYPE=%s] Removed [%d] expired services",
				conscience_get_namespace(cs), str_name, rc);
		else
			DEBUG("[NS=%s][SRVTYPE=%s] no expired services",
				conscience_get_namespace(cs), str_name);

		if (error_local)
			g_error_free(error_local);
	}

	g_slist_foreach(list_type_names,g_free1,NULL);
	g_slist_free(list_type_names);
}

/* ------------------------------------------------------------------------- */

static gboolean
request_body_matches_namespace(struct request_context_s *req_ctx, GError **err)
{
	GSList *list_ns = NULL;
	int rc;

	gsize body_size = 0;
	void *body = message_get_BODY(req_ctx->request, &body_size);
	if (!body)
		return TRUE;

	if (!strings_unmarshall(&list_ns, body, &body_size, err)) {
		GSETERROR(err, "Invalid request body");
		return FALSE;
	}

	if (1 != g_slist_length(list_ns)) {
		GSETCODE(err, CODE_BAD_REQUEST, "Too many namespaces, this conscience only manage exactly 1 NS");
		rc = FALSE;
	}
	else {
		gchar local_ns[LIMIT_LENGTH_NSNAME];
		g_strlcpy(local_ns, conscience->ns_info.name, sizeof(local_ns));
		rc = (0 == g_ascii_strcasecmp(local_ns, (gchar*)list_ns->data));
	}

	g_slist_foreach(list_ns, g_free1, NULL);
	g_slist_free(list_ns);
	return rc;
}

/* ------------------------------------------------------------------------- */

static gint
handler_get_ns_info(struct request_context_s *req_ctx)
{
	struct reply_context_s ctx;
	GByteArray* gba = NULL;

	init_reply_ctx_with_request(req_ctx, &ctx);

	if (!request_body_matches_namespace(req_ctx, &(ctx.warning))) {
		if (!ctx.warning)
			GSETCODE(&(ctx.warning), CODE_NAMESPACE_NOTMANAGED, "Invalid namespace");
		reply_context_clear(&ctx, FALSE);
		reply_context_set_message(&ctx, gerror_get_code(ctx.warning),
				gerror_get_message(ctx.warning));
		(void) reply_context_reply(&ctx, &(ctx.warning));
		reply_context_log_access(&ctx, "NS=?");
		reply_context_clear(&ctx, TRUE);
		return (0);
	}

	g_rec_mutex_lock(&conscience_nsinfo_mutex);
	gba = namespace_info_marshall(&(conscience->ns_info), &(ctx.warning));
	g_rec_mutex_unlock(&conscience_nsinfo_mutex);

	if (gba == NULL) {
		GSETERROR(&(ctx.warning), "Failed to marshall namespace info");
		reply_context_log_access(&ctx, "NS=%s", conscience_get_namespace(conscience));
		reply_context_clear(&ctx, FALSE);
		return 0;
	}

	reply_context_set_body(&ctx, gba->data, gba->len, REPLYCTX_COPY);
	g_byte_array_free(gba, TRUE);
	reply_context_set_message(&ctx, CODE_FINAL_OK, "OK");
	if (!reply_context_reply(&ctx, &(ctx.warning))) {
		GSETERROR(&(ctx.warning), "Cannot reply the namespace info");
		reply_context_log_access(&ctx, "NS=%s", conscience_get_namespace(conscience));
		reply_context_clear(&ctx, FALSE);
		return (0);
	}

	reply_context_log_access(&ctx, "NS=%s", conscience_get_namespace(conscience));
	reply_context_clear(&ctx, TRUE);
	return (1);
}

static gint
handler_rm_broken_containers(struct request_context_s *req_ctx)
{
	struct reply_context_s ctx;
	GSList *elements = NULL, *list = NULL;

	init_reply_ctx_with_request(req_ctx, &ctx);

	gsize data_size;
	void *data = message_get_BODY(req_ctx->request, &data_size);
	if (data) {
		guint counter;

		if (!strings_unmarshall(&elements, data, &data_size, &(ctx.warning))) {
			GSETCODE(&(ctx.warning), CODE_BAD_REQUEST, "Bad request : failed to unmarshall broken container list");
			goto errorLabel;
		}
		counter=0;

		for (list = elements; list && list->data; list = list->next) {
			if (list->data) {

				/* XXX start of critical section*/
				conscience_lock_broken_elements(conscience,'w');
				broken_holder_remove_element(conscience->broken_elements, (gchar *) list->data);
				conscience_unlock_broken_elements(conscience);
				/* XXX end of critical section*/

				g_free(list->data);
				list->data = NULL;
				counter ++;
			}
		}

		g_slist_free(elements);
		NOTICE("[NS=%s] %u broken elements have been flushed", conscience_get_namespace(conscience), counter);
	}
	else {
		/* XXX start of critical section*/
		conscience_lock_broken_elements(conscience,'w');
		broken_holder_flush(conscience->broken_elements);
		conscience_unlock_broken_elements(conscience);
		/* XXX end of critical section*/

		NOTICE("[NS=%s] all the broken elements have been flushed", conscience_get_namespace(conscience));
	}

	reply_context_clear(&ctx, TRUE);
	reply_context_set_message(&ctx, CODE_FINAL_OK, "OK");
	if (!reply_context_reply(&ctx, &(ctx.warning))) {
		GSETERROR(&(ctx.warning), "Broken elements removed, failed to reply");
		goto errorLabel;
	}

	reply_context_log_access(&ctx, "NS=%s", conscience_get_namespace(conscience));
	reply_context_clear(&ctx, TRUE);
	return (1);

      errorLabel:
	ERROR("An error occured : %s", gerror_get_message(ctx.warning));
	reply_context_clear(&ctx,FALSE);
	reply_context_set_message(&ctx, ctx.warning->code, gerror_get_message(ctx.warning));
	reply_context_reply(&ctx, NULL);
	reply_context_log_access(&ctx, "NS=%s", conscience_get_namespace(conscience));
	reply_context_clear(&ctx, TRUE);
	return 1;
}

static gint
handler_fix_broken_containers(struct request_context_s *req_ctx)
{
	gint rc;
	struct reply_context_s ctx;
	GSList *containers = NULL, *list = NULL;

	init_reply_ctx_with_request(req_ctx, &ctx);

	/* Extract MESSAGE from request */
	gsize data_size;
	void *data = message_get_BODY(req_ctx->request, &data_size);
	if (!data) {
		GSETCODE(&(ctx.warning),CODE_BAD_REQUEST,"Invalid request - missing body");
		goto errorLabel;
	}

	containers = meta2_maintenance_names_unmarshall_buffer(data, data_size, &(ctx.warning));
	if (!containers) {
		GSETCODE(&(ctx.warning),CODE_BAD_REQUEST,"Invalid request - invalid body, deserialization eror");
		goto errorLabel;
	}

	/* Update the container hash with this new values */
	for (list = containers; list && list->data; list = list->next) {
		if (list->data) {
			typeof(errno) errsav;

			/* XXX start of critical section*/
			conscience_lock_broken_elements(conscience,'w');
			errno = 0;
			broken_holder_fix_element(conscience->broken_elements, list->data);
			errsav = errno;
			conscience_unlock_broken_elements(conscience);
			/* XXX end of critical section*/

			if (errsav)
				INFO("Failed to fix [%s] : %s", (gchar*) list->data, strerror(errno));

			g_free(list->data);
			list->data = NULL;
		}
	}

	g_slist_free(containers);

	reply_context_set_message(&ctx, CODE_FINAL_OK, "OK");
	rc = reply_context_reply(&ctx, &(ctx.warning));
	reply_context_log_access(&ctx, "NS=%s", conscience_get_namespace(conscience));
	reply_context_clear(&ctx, TRUE);
	return rc;
errorLabel:
	ERROR("An error occured : %s", gerror_get_message(ctx.warning));
	reply_context_clear(&ctx, FALSE);
	reply_context_set_message(&ctx, ctx.warning->code, ctx.warning->message);
	reply_context_reply(&ctx, NULL);
	reply_context_log_access(&ctx, "NS=%s", conscience_get_namespace(conscience));
	reply_context_clear(&ctx, TRUE);
	return 0;
}

static gint
handler_push_broken_containers(struct request_context_s *req_ctx)
{
	struct reply_context_s ctx;
	GSList *elements = NULL, *list = NULL;

	init_reply_ctx_with_request(req_ctx, &ctx);
	reply_context_set_body(&ctx, NULL, 0, 0);

	/* Extract MESSAGE from request */
	gsize data_size;
	void *data = message_get_BODY(req_ctx->request, &data_size);
	if (!data) {
		GSETCODE(&(ctx.warning),CODE_BAD_REQUEST,"Invalid request - missing body");
		goto errorLabel;
	}

	elements = meta2_maintenance_names_unmarshall_buffer(data, data_size, &(ctx.warning));
	if (!elements) {
		GSETCODE(&(ctx.warning), CODE_BAD_REQUEST,"body unmarshalling error");
		goto errorLabel;
	}

	if (DEBUG_ENABLED())
		DEBUG("%d BROKEN elements received", g_slist_length(elements));

	for (list = elements; list && list->data; list = list->next) {
		if (list->data) {
			/* XXX start of critical section*/
			conscience_lock_broken_elements(conscience,'w');
			broken_holder_add_element(conscience->broken_elements, (gchar *) (list->data));
			conscience_unlock_broken_elements(conscience);
			/* XXX end of critical section*/

			TRACE("Broken element successfuly managed : [%s]", (gchar *) (list->data));
			g_free(list->data);
			list->data = NULL;
		}
	}
	g_slist_free(elements);

	reply_context_set_message(&ctx, CODE_FINAL_OK, "OK");
	reply_context_reply(&ctx, &(ctx.warning));
	reply_context_log_access(&ctx, "NS=%s", conscience_get_namespace(conscience));
	reply_context_clear(&ctx, TRUE);
	return (1);

errorLabel:
	ERROR("An error occured : %s", gerror_get_message(ctx.warning));
	reply_context_clear(&ctx,FALSE);
	reply_context_set_message(&ctx, ctx.warning->code, ctx.warning->message);
	reply_context_reply(&ctx, NULL);
	reply_context_log_access(&ctx, "NS=%s", conscience_get_namespace(conscience));
	reply_context_clear(&ctx, TRUE);
	return 1;
}

/* ------------------------------------------------------------------------- */

static void
_clean_brkget_accumulator(struct brkget_s *data)
{
	if (data) {
		if (data->lines) {
			g_slist_foreach(data->lines, g_free1, NULL);
			g_slist_free(data->lines);
		}
		data->lines = NULL;
		data->lines_length = 0;
	}
}

static gboolean
_brkget_reply_do(struct brkget_s *data, gboolean is_last)
{
	/*Serializes the lines */
	if (data->lines) {
		GByteArray *gba = NULL;

		gba = meta2_maintenance_names_marshall(data->lines, &(data->reply_ctx.warning));
		if (!gba)
			return FALSE;
		reply_context_clear(&(data->reply_ctx), TRUE);
		reply_context_set_message(&(data->reply_ctx), (is_last?CODE_FINAL_OK:CODE_PARTIAL_CONTENT), (is_last?"OK":"Partial content"));
		reply_context_set_body(&(data->reply_ctx), gba->data, gba->len, REPLYCTX_DESTROY_ON_CLEAN|REPLYCTX_COPY);
		g_byte_array_free(gba, TRUE);
		if (!reply_context_reply(&(data->reply_ctx), &(data->reply_ctx.warning)))
			return FALSE;
	}

	_clean_brkget_accumulator(data);
	return TRUE;
}

static gboolean
brkget_manage_m1(gpointer udata, struct broken_meta1_s *bm1)
{
	struct brkget_s *data = udata;

	if (bm1) {
		gchar *str = broken_holder_write_meta1(bm1);
		if (str) {
			data->lines = g_slist_prepend(data->lines, str);
			data->lines_length++;
		}
	}
	if (!bm1 || data->lines_length >= NB_BROKEN_LINES)
		return _brkget_reply_do(data, FALSE);
	return TRUE;
}

static gboolean
brkget_manage_content(gpointer udata, struct broken_meta2_s *bm2, struct broken_content_s *bc)
{
	struct brkget_s *data = udata;

	if (bm2) {
		gchar *str;
		if (bc)
			str = broken_holder_write_content(bm2, bc);
		else
			str = broken_holder_write_meta2(bm2);
		if (str) {
			data->lines = g_slist_prepend(data->lines, str);
			data->lines_length++;
		}
	}
	if (!bm2 || data->lines_length >= NB_BROKEN_LINES)
		return _brkget_reply_do(data, FALSE);
	return TRUE;
}

static gint
handler_get_broken_containers(struct request_context_s *req_ctx)
{
	gboolean rc;
	struct brkget_s data;

	memset(&data, 0x00, sizeof(data));
	init_reply_ctx_with_request(req_ctx, &(data.reply_ctx));

	/* XXX start of critical section */
	conscience_lock_broken_elements(conscience,'r');
	rc = broken_holder_run_elements(conscience->broken_elements, 0, (gpointer) & data, brkget_manage_m1, brkget_manage_content);
	conscience_unlock_broken_elements(conscience);
	/* XXX end of critical section */

	if (!rc) {
		WARN("Failed to run all the broken elements");
		_clean_brkget_accumulator(&data);
		_reply_ctx_set_error(&(data.reply_ctx));
	}
	else {
		DEBUG("Broken elements successfuly ran");
		_brkget_reply_do(&data, TRUE);
		reply_context_clear(&(data.reply_ctx), FALSE);
		reply_context_set_message(&(data.reply_ctx), CODE_FINAL_OK, "OK");
	}

	reply_context_reply(&(data.reply_ctx), &(data.reply_ctx.warning));
	reply_context_log_access(&(data.reply_ctx), "NS=%s", conscience_get_namespace(conscience));
	reply_context_clear(&(data.reply_ctx), TRUE);
	return rc ? 1 : 0;
}

/* ------------------------------------------------------------------------- */

static void
_conscience_srv_clean_udata(struct conscience_srv_s *srv)
{
	if (!srv || srv->app_data_type != SAD_PTR)
		return;
	if (!srv->app_data.pointer.value)
		return;
	if (srv->app_data.pointer.cleaner)
		srv->app_data.pointer.cleaner(srv->app_data.pointer.value);

	srv->app_data.pointer.value = NULL;
	srv->app_data.pointer.cleaner = NULL;
}

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

static void
_conscience_srv_prepare_cache(struct conscience_srv_s *srv)
{
	GByteArray *gba;

	if (!flag_serialize_srvinfo_cache)
		return;

	gba = _conscience_srv_serialize(srv);
	_conscience_srv_clean_udata(srv);
	srv->app_data_type = SAD_PTR;
	srv->app_data.pointer.value = gba;
	srv->app_data.pointer.cleaner = metautils_gba_unref;
}

static gboolean
_srvinfo_append(struct srvget_s *sg, struct conscience_srv_s *srv)
{
	GByteArray *gba;

	if (sg->full) {
		gba = _conscience_srv_serialize_full(srv);
		if (gba) {
			g_byte_array_append(sg->gba_body, gba->data, gba->len);
			g_byte_array_free(gba, TRUE);
			return TRUE;
		}
	}
	else if (flag_serialize_srvinfo_cache
		&& srv->app_data_type == SAD_PTR
		&& NULL != (gba = srv->app_data.pointer.value))
	{
		if (gba->len > 0) {
			g_byte_array_append(sg->gba_body, gba->data, gba->len);
			return TRUE;
		}
	}
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
	sg.full = message_extract_flag(req_ctx->request, NAME_MSGKEY_FULL, FALSE);

	struct reply_context_s reply_ctx;
	init_reply_ctx_with_request(req_ctx, &reply_ctx);

	gsize data_size = 0;
	void *data = message_get_field(req_ctx->request, NAME_MSGKEY_TYPENAME, &data_size);
	if (!data) {
		GSETCODE(&(reply_ctx.warning), CODE_BAD_REQUEST, "Bad request: no/invalid TYPENAME field");
	} else {
		gchar **array_types = buffer_split(data, data_size, ",", 0);
		g_strlcpy(sg.str_ns, conscience_get_namespace(conscience), sizeof(sg.str_ns));

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
	reply_context_log_access(&(reply_ctx), "NS=%s", conscience_get_namespace(conscience));
	reply_context_clear(&(reply_ctx), TRUE);
	return rc ? 1 : 0;
}

/* ------------------------------------------------------------------------- */

/**
 * Store the given service in the given conscience instance
 *
 * Parameters are not checked
 * @param conscience
 * @param si
 */
static void
push_service(struct conscience_s *cs, struct service_info_s *si, gboolean lock_score)
{
	gchar str_addr[STRLEN_ADDRINFO + 1], str_descr[LIMIT_LENGTH_SRVDESCR];
	gint32 old_score=0;
	GError *error_local=NULL;
	struct conscience_srvtype_s *srvtype;
	struct conscience_srv_s *srv;

	if (0 == g_ascii_strcasecmp(NAME_SRVTYPE_META0, si->type)) {
		/* If we forced a meta0 in config, registering or unlocking is not
		 * allowed */
		if (flag_forced_meta0)
			return;

		/* Set the meta0 in ns_info struct if it was not forced in config */
		if ( &(cs->ns_info.addr) == NULL ) {
			g_memmove(&(cs->ns_info.addr), &(si->addr), sizeof(addr_info_t));
		}
	}

	/* XXX start of critical section */
	srvtype = conscience_get_locked_srvtype(cs, &error_local, si->type, MODE_STRICT, 'w');
	if (!srvtype) {
		ERROR("Service type [%s/%s] not found : %s", conscience_get_namespace(cs),
			si->type, gerror_get_message(error_local));
		if (error_local)
			g_error_free(error_local);
		return;
	}

	/*for alerting purposes, we need to store the previous score*/
	srv = conscience_srvtype_get_srv(srvtype, (struct conscience_srvid_s*)&(si->addr));
	if (srv) {
		old_score = srv->score.value;
		memcpy(str_descr, srv->description, LIMIT_LENGTH_SRVDESCR);
	}

	if (conscience_srvtype_refresh(srvtype, &error_local, si, lock_score)) {
		if (srv) { /* refresh */
			/* if the service was previously known, we may detect score down to zero
			 * (new services comes with a zeroed score). */
			if (lock_score) {
				if (si->score.value >= 0) /* lock */
					srv->locked = TRUE;
				else { /* unlock */
					srv->locked = FALSE;
					srv->score.value = old_score;
				}
			}
			else if (si->tags) {
				gboolean bval = FALSE;
				struct service_tag_s *tag = service_info_get_tag(si->tags, "tag.up");
				if (tag && service_tag_get_value_boolean(tag, &bval, NULL) && !bval) {
					INFO("v1.4 service down");
					_alert_service_with_zeroed_score(srv);
				}
			}

			_conscience_srv_prepare_cache(srv);
		}
		else { /* first register */
			srv = conscience_srvtype_get_srv(srvtype, (struct conscience_srvid_s*)&(si->addr));
			if (srv) {
				if (lock_score)
					srv->locked = (si->score.value >= 0);
				_conscience_srv_prepare_cache(srv);
			}
		}
		conscience_release_locked_srvtype(srvtype);
		/* XXX end of critical section */

		if (srv)
			DEBUG("Service [%s] refreshed with score=%d", str_descr, srv->score.value);
		else {
			addr_info_to_string(&(si->addr),str_addr,sizeof(str_addr));
			NOTICE("Service [%s/%s/%s] registered", conscience_get_namespace(cs), si->type, str_addr);
		}
	}
	else {
		conscience_release_locked_srvtype(srvtype);
		/* XXX end of critical section */

		if (srv)
			WARN("Service [%s] refresh failed : %s", str_descr, gerror_get_message(error_local));
		else {
			addr_info_to_string(&(si->addr),str_addr,sizeof(str_addr));
			WARN("Service [%s/%s/%s] registration failed : %s", conscience_get_namespace(cs),
				si->type, str_addr, gerror_get_message(error_local));
		}
	}

	/*clean the working structures*/
	if (error_local)
		g_error_free(error_local);
}

static gint
handler_push_service(struct request_context_s *req_ctx)
{
	GSList *list_srvinfo = NULL;

	struct reply_context_s ctx;
	init_reply_ctx_with_request(req_ctx, &(ctx));

	gsize data_size = 0;
	void *data = message_get_BODY(req_ctx->request, &data_size);
	if (!data) {
		GSETCODE(&(ctx.warning), CODE_BAD_REQUEST, "Bad requets : no body");
		goto errorLabel;
	}
	if (0 >= service_info_unmarshall(&list_srvinfo, data, &data_size, &(ctx.warning))) {
		GSETCODE(&(ctx.warning), CODE_BAD_REQUEST, "Bad request : failed to deserialize the body");
		goto errorLabel;
	}

	DEBUG("[%d] services to be pushed in namespace [%s]",
			g_slist_length(list_srvinfo), conscience_get_namespace(conscience));

	/*Now push each service and reply the success */
	gboolean lock_action = message_extract_flag(req_ctx->request, NAME_MSGKEY_LOCK, FALSE);
	gint counter = 0;
	for (GSList *l = list_srvinfo; l; l = g_slist_next(l)) {
		if (l->data) {
			push_service(conscience, (struct service_info_s *) (l->data), lock_action);
			service_info_clean(l->data);
			l->data = NULL;
			counter++;
		}
	}
	g_slist_free(list_srvinfo);

	reply_context_set_message(&ctx, CODE_FINAL_OK, "OK");
	reply_context_reply(&ctx, NULL);
	reply_context_log_access(&ctx, "NS=%s %d service pushed", conscience_get_namespace(conscience), counter);
	reply_context_clear(&ctx, TRUE);
	return 1;
errorLabel:
	ERROR("An error occured : %s", gerror_get_message(ctx.warning));
	_reply_ctx_set_error(&ctx);
	reply_context_reply(&ctx, NULL);
	reply_context_log_access(&ctx, "NS=%s", conscience_get_namespace(conscience));
	reply_context_clear(&ctx, TRUE);
	return 0;
}

/* ------------------------------------------------------------------------- */

static gint
handler_get_services_types(struct request_context_s *req_ctx)
{
	gint counter;
	struct reply_context_s ctx;
	GHashTableIter iterator;
	gpointer k, v;
	GSList *list_names;
	GByteArray *gba_names;

	init_reply_ctx_with_request(req_ctx, &(ctx));
	counter = 0;
	list_names = NULL;

	/* We avoid calling the similar feature from the conscience because
	 * it makes a deep copy of the list. We do not perform any blocking
	 * operation on the list, so we build ourselves a hollow copy and we
	 * marshal it. */

	/* XXX start of critical section */
	conscience_lock_srvtypes(conscience,'r');
	g_hash_table_iter_init(&iterator, conscience->srvtypes);
	while (g_hash_table_iter_next(&iterator, &k, &v)) {
		if (k) {
			list_names = g_slist_prepend(list_names, k);
			counter++;
		}
	}

	gba_names = meta2_maintenance_names_marshall(list_names, &(ctx.warning));
	conscience_unlock_srvtypes(conscience);
	/* XXX end of critical section */

	g_slist_free(list_names);

	/* Now we can manage the potential error and reply */
	if (!gba_names) {
		reply_context_set_message(&ctx, CODE_INTERNAL_ERROR, gerror_get_message(ctx.warning));
		ERROR("Failed to reply the service types : %s", gerror_get_message(ctx.warning));
		reply_context_reply(&ctx, NULL);
		reply_context_log_access(&ctx, "NS=%s %d names pushed", conscience_get_namespace(conscience), counter);
		reply_context_clear(&ctx, TRUE);
		return 0;
	}

	reply_context_set_body(&ctx, gba_names->data, gba_names->len, REPLYCTX_DESTROY_ON_CLEAN|REPLYCTX_COPY);
	g_byte_array_free(gba_names, TRUE);
	reply_context_set_message(&ctx, CODE_FINAL_OK, "OK");
	reply_context_reply(&ctx, NULL);
	reply_context_log_access(&ctx, "NS=%s %d names pushed", conscience_get_namespace(conscience), counter);
	reply_context_clear(&ctx, TRUE);
	return 1;
}

/* ------------------------------------------------------------------------- */

/**
 * @param conscience
 * @param si
 */
static void
rm_service(struct conscience_s *cs, struct service_info_s *si)
{
	int str_desc_len;
	gchar str_desc[LIMIT_LENGTH_NSNAME + 1 + LIMIT_LENGTH_SRVTYPE + 1 + STRLEN_ADDRINFO + 1];
	GError *error_local;
	struct conscience_srvid_s srvid;
	struct conscience_srvtype_s *srvtype;

	if (INFO_ENABLED()) {
		str_desc_len = g_snprintf(str_desc, sizeof(str_desc), "%s/%s/", conscience_get_namespace(cs), si->type);
		addr_info_to_string(&(si->addr), str_desc + str_desc_len, sizeof(str_desc) - str_desc_len);
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

static gint
handler_rm_service(struct request_context_s *req_ctx)
{
	gint counter = 0;
	struct reply_context_s ctx;

	void *data;
	gsize data_size;

	init_reply_ctx_with_request(req_ctx, &(ctx));
	data = NULL;
	data_size = 0;

	/*Get the body and unpack it as a list of services */
	data = message_get_field(req_ctx->request, NAME_MSGKEY_TYPENAME, &data_size);
	if (!data) {
		gchar str_type[LIMIT_LENGTH_SRVTYPE+1];
		struct conscience_srvtype_s *srvtype;

		g_strlcpy(str_type, data, sizeof(str_type));

		/* XXX start of critical section */
		srvtype = conscience_get_locked_srvtype(conscience, &(ctx.warning), str_type, MODE_STRICT,'w');
		if (!srvtype) {
			GSETCODE(&(ctx.warning), CODE_SRVTYPE_NOTMANAGED,"srvtype=[%s] not found", str_type);
			goto errorLabel;
		}
		counter = conscience_srvtype_count_srv(srvtype,TRUE);
		conscience_srvtype_flush(srvtype);
		conscience_release_locked_srvtype(srvtype);
		/* XXX end ofcritical section */

		NOTICE("[NS=%s][SRVTYPE=%s] flush done!", conscience_get_namespace(conscience), srvtype->type_name);
		reply_context_set_message(&ctx, CODE_FINAL_OK, "OK");
	}
	else if (message_has_BODY(req_ctx->request)) {
		GSList *list_srvinfo = NULL;

 		data = message_get_BODY(req_ctx->request, &data_size);
		if (!data) {
			GSETCODE(&(ctx.warning), CODE_BAD_REQUEST, "No body");
			goto errorLabel;
		}
		if (0 >= service_info_unmarshall(&list_srvinfo, data, &data_size, &(ctx.warning))) {
			GSETCODE(&(ctx.warning), CODE_BAD_REQUEST, "Invalid body: deserialization error");
			goto errorLabel;
		}

		NOTICE("[NS=%s] [%d] services to be removed", conscience_get_namespace(conscience), g_slist_length(list_srvinfo));

		/*Now push each service and reply the success */
		for (GSList *l = list_srvinfo; l; l = g_slist_next(l)) {
			if (l->data) {
				rm_service(conscience, (struct service_info_s *) (l->data));
				g_free(l->data);
				l->data = NULL;
				counter++;
			}
		}
		g_slist_free(list_srvinfo);
		reply_context_set_message(&ctx, CODE_FINAL_OK, "OK");
	}
	else {
		counter = 0;
		GSETCODE(&(ctx.warning), CODE_BAD_REQUEST, "Bad request : no service in the body, no service type in the fields");
		goto errorLabel;
	}

	reply_context_reply(&ctx, NULL);
	reply_context_log_access(&ctx, "NS=%s %d services removed", conscience_get_namespace(conscience), counter);
	reply_context_clear(&ctx, TRUE);
	return 1;

errorLabel:
	ERROR("Failed to remove the service : %s", gerror_get_message(ctx.warning));
	_reply_ctx_set_error(&ctx);
	reply_context_reply(&ctx, NULL);
	reply_context_log_access(&ctx, "NS=%s", conscience_get_namespace(conscience));
	reply_context_clear(&ctx, TRUE);
	return 0;
}

/* ------------------------------------------------------------------------- */

static struct cmd_s *
module_find_handler(gchar * n, gsize l)
{
	struct cmd_s *c;
	static struct cmd_s CMD[] = {
		{NAME_MSGNAME_CS_GET_NSINFO, handler_get_ns_info, &(stats.ns_info)},
		{NAME_MSGNAME_CS_GET_SRV, handler_get_service, &(stats.services.get)},
		{NAME_MSGNAME_CS_GET_SRVNAMES, handler_get_services_types, &(stats.services.get)},
		{NAME_MSGNAME_CS_PUSH_SRV, handler_push_service, &(stats.services.push_stat)},
		{NAME_MSGNAME_CS_RM_SRV, handler_rm_service, &(stats.services.remove)},
		{NAME_MSGNAME_CS_PUSH_BROKEN_CONT, handler_push_broken_containers, &(stats.broken.push)},
		{NAME_MSGNAME_CS_GET_BROKEN_CONT, handler_get_broken_containers, &(stats.broken.get)},
		{NAME_MSGNAME_CS_RM_BROKEN_CONT, handler_rm_broken_containers, &(stats.broken.remove)},
		{NAME_MSGNAME_CS_FIX_BROKEN_CONT, handler_fix_broken_containers, &(stats.broken.fix)},
		{NULL, NULL, NULL}
	};

	for (c = CMD; c && c->c; c++) {
		if (0 == g_ascii_strncasecmp(c->c, n, l))
			return c;
	}

	return NULL;
}

static gint
plugin_matcher(MESSAGE m, void *param, GError ** err)
{
	struct cmd_s *c;
	gchar *name;
	gsize nameLen;

	(void)param;
	if (!m) {
		GSETERROR(err, "Invalid parameter");
		return -1;
	}

	name = message_get_NAME(m, &nameLen);
	if (!name || nameLen <= 0)
		return 0;

	c = module_find_handler(name, nameLen);
	return (c ? 1 : 0);
}

static gint
plugin_handler(MESSAGE m, gint cnx, void *param, GError ** err)
{
	gchar *name;
	gsize nameLen;
	struct cmd_s *c;
	struct request_context_s ctx;

	(void)param;
	if (!m) {
		GSETERROR(err, "Invalid parameter");
		return -1;
	}

	name = message_get_NAME(m, &nameLen);
	if (!name || nameLen <= 6) {
		GSETERROR(err, "The message contains an invalid NAME parameter");
		return -1;
	}

	c = module_find_handler(name, nameLen);
	if (!c) {
		GSETERROR(err, "This message does not concern this plugin.");
		return -1;
	}

	memset(&ctx, 0x00, sizeof(ctx));
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
		GSETERROR(err, "Invalid Key/Value pair : %s/%s", what, value);
		return FALSE;
	}

	/*find the service type */
	if (0 == g_ascii_strcasecmp(type, "default"))
		srvtype = conscience_get_default_srvtype(cs);
	else
		srvtype = conscience_get_srvtype(cs, err, type, MODE_AUTOCREATE);
	if (!srvtype) {
		GSETERROR(err, "Failled to init a ServiceType");
		return FALSE;
	}

	/*adjust the parameter */
	if (0 == g_ascii_strcasecmp(what, KEY_SCORE_TIMEOUT)) {
		srvtype->score_expiration = g_ascii_strtoll(value, NULL, 10);
		INFO("[NS=%s][SRVTYPE=%s] score expiration interval set to [%ld] seconds", cs->ns_info.name,
		    srvtype->type_name, srvtype->score_expiration);
		return TRUE;
	}
	else if (0 == g_ascii_strcasecmp(what, KEY_SCORE_VARBOUND)) {
		srvtype->score_variation_bound = g_ascii_strtoll(value, NULL, 10);
		INFO("[NS=%s][SRVTYPE=%s] score variation bound set to [%d]", cs->ns_info.name, srvtype->type_name, srvtype->score_variation_bound);
		return TRUE;
	}
	else if (0 == g_ascii_strcasecmp(what, KEY_SCORE_EXPR)) {
		if (conscience_srvtype_set_type_expression(srvtype, err, value)) {
			INFO("[NS=%s][SRVTYPE=%s] score expression set to [%s]", cs->ns_info.name, srvtype->type_name,
			    value);
			return TRUE;
		}
		return FALSE;
	}
	else if (0 == g_ascii_strcasecmp(what, KEY_ALERT_LIMIT)) {
		srvtype->alert_frequency_limit = g_ascii_strtoll(value, NULL, 10);
		INFO("[NS=%s][SRVTYPE=%s] Alert limit set to %ld", cs->ns_info.name,
		    srvtype->type_name, srvtype->alert_frequency_limit);
	}

	WARN("[NS=%s][SRVTYPE=%s] parameter not recognized [%s] (ignored!)", cs->ns_info.name, srvtype->type_name, what);
	return TRUE;
}

static GHashTable*
module_init_valuelist(GHashTable * params, GError ** err, GRegex *value_regex)
{
	GHashTable *valuelist= NULL;
	GHashTableIter params_iterator;

	if (value_regex == NULL) {
		GSETERROR(err, "Invalid regex for parameters parsing.");
	}
	else {
		valuelist = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, metautils_gba_unref);
		if (valuelist == NULL) {
			GSETERROR(err, "Memory allocation failure");
		}
		else {
			gpointer k = NULL, v = NULL;
			GMatchInfo *match_info = NULL;

			g_hash_table_iter_init(&params_iterator, params);

			while (g_hash_table_iter_next(&params_iterator, &k, &v)) {

				if (!g_regex_match(value_regex, (gchar *) k, G_REGEX_MATCH_NOTEMPTY, &match_info))
					TRACE("Parameter skipped : [%s] (does not match %s)", (gchar *) k, g_regex_get_pattern(value_regex));
				else if (g_match_info_get_match_count(match_info) != 2)
					WARN("Ignored parameter (invalid key) : %s", (gchar *) k);
				else {
					gchar* str_opt = g_match_info_fetch(match_info, 1);
					if (str_opt != NULL)
						g_hash_table_insert(valuelist, str_opt, g_byte_array_append(g_byte_array_new(), v, strlen(v)+1));
				}

				if (match_info != NULL) {
					g_match_info_free(match_info);
					match_info = NULL;
				}
			}
		}
	}

	return valuelist;
}

#define DEFINE_MODULE_INIT(STRUCT_NAME, KEYWORD) \
static gboolean \
module_init_##STRUCT_NAME(struct conscience_s *cs, GHashTable * params, GError ** err) \
{ \
	GRegex *param_regex = g_regex_new(#KEYWORD "\\.(.+)", G_REGEX_CASELESS, G_REGEX_MATCH_NOTEMPTY, NULL); \
	GHashTable *valuelist = module_init_valuelist(params, err, param_regex); \
	g_regex_unref(param_regex); \
	cs->ns_info.STRUCT_NAME = valuelist; \
	return valuelist != NULL; \
}

/* module_init_options */
DEFINE_MODULE_INIT(options, option);

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
		}
		g_strfreev(keys);
		return e;
	}
	GSETCODE(&e, CODE_INTERNAL_ERROR, "Cannot get all keys of group '%s'", group_name);
	return e;
}

static GError *
module_init_storage_conf(struct conscience_s *cs, const gchar *stg_pol_in_option, const gchar *filepath)
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
		if (NULL != stg_pol_in_option) {
			GSETERROR(&e, "Cannot parse storage configuration from file [%s]", filepath);
		} else {
			INFO("[NS=%s] storage conf init failed -> ignored as no storage_policy was found as an option",
					cs->ns_info.name);
		}
		g_key_file_free(stg_conf_file);
		return e;
	}

	// XXX POLICIES
	cs->ns_info.storage_policy = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, metautils_gba_unref);
	e = fill_hashtable_with_group(cs->ns_info.storage_policy, stg_conf_file, NAME_GROUPNAME_STORAGE_POLICY);
	if (NULL != e) {
		g_prefix_error(&e, "Error collecting storage policy rules from file [%s]", filepath);
		g_key_file_free(stg_conf_file);
		return e;
	}
	g_hash_table_foreach(cs->ns_info.storage_policy,
			(GHFunc)_check_for_keyword, (gchar*[2]){STORAGE_POLICY_NONE, "storage policy"});

	/* If the storage policy set by param_option.storage_policy is not present in the storage conf file, set an error. */
	if (stg_pol_in_option && 0 != g_ascii_strcasecmp(stg_pol_in_option,STORAGE_POLICY_NONE)) {
		if (!g_hash_table_lookup(cs->ns_info.storage_policy, stg_pol_in_option)) {
			GSETERROR(&e, "[NS=%s] storage conf init failed: the policy [%s] wanted as an option is not defined in [%s]",
					cs->ns_info.name, stg_pol_in_option, filepath);
			g_key_file_free(stg_conf_file);
			return e;
		}
	}

	// XXX SECURITY
	cs->ns_info.data_security = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, metautils_gba_unref);
	e = fill_hashtable_with_group(cs->ns_info.data_security, stg_conf_file, NAME_GROUPNAME_DATA_SECURITY);
	if( NULL != e) {
		WARN("Data security rules not correctly loaded from file [%s] : %s", filepath, e->message);
		return e;
	}
	g_hash_table_foreach(cs->ns_info.data_security,
			(GHFunc)_check_for_keyword, (gchar*[2]){DATA_SECURITY_NONE, "data security"});

	// XXX TREATMENTS
	cs->ns_info.data_treatments = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, metautils_gba_unref);
	e = fill_hashtable_with_group(cs->ns_info.data_treatments, stg_conf_file, NAME_GROUPNAME_DATA_TREATMENTS);
	if( NULL != e) {
		WARN("Data treatments rules not correctly loaded from file [%s] : %s", filepath, e->message);
		return e;
	}
	g_hash_table_foreach(cs->ns_info.data_treatments,
			(GHFunc)_check_for_keyword, (gchar*[2]){DATA_TREATMENT_NONE, "data treatment"});

	// XXX CLASSES
	cs->ns_info.storage_class = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, metautils_gba_unref);
	e = fill_hashtable_with_group(cs->ns_info.storage_class, stg_conf_file, NAME_GROUPNAME_STORAGE_CLASS);
	if( NULL != e) {
		WARN("Storage class rules not correctly loaded from file [%s] : %s", filepath, e->message);
		return e;
	}
	g_hash_table_foreach(cs->ns_info.storage_class,
			(GHFunc)_check_for_keyword, (gchar*[2]){STORAGE_CLASS_NONE, "storage class"});

	INFO("[NS=%s] storage conf loaded successfully from file [%s]",
			cs->ns_info.name, filepath);
	return NULL;
}

static gboolean
module_init_srvtype_from_cfg(struct conscience_s *cs, GHashTable * params, GError ** err)
{
	gpointer k = NULL, v = NULL;
	GHashTableIter params_iterator;
	GRegex *service_param_regex = NULL;
	GMatchInfo *match_info = NULL;

	service_param_regex = g_regex_new("service\\.([^.]+)\\.(.+)", G_REGEX_CASELESS, G_REGEX_MATCH_NOTEMPTY, NULL);
	if (!service_param_regex) {
		GSETERROR(err,
		    "Invalid regex for parameters parsing. Contact the development team, or Jethro Gibbs (NCIS).");
		return FALSE;
	}

	g_hash_table_iter_init(&params_iterator, params);
	while (g_hash_table_iter_next(&params_iterator, &k, &v)) {

		if (match_info) {
			g_match_info_free(match_info);
			match_info = NULL;
		}
		if (!g_regex_match(service_param_regex, (gchar *) k, G_REGEX_MATCH_NOTEMPTY, &match_info))
			TRACE("Parameter skipped : [%s] (does not match %s)", (gchar *) k, g_regex_get_pattern(service_param_regex));
		else if (g_match_info_get_match_count(match_info) != 3)
			WARN("Ignored parameter (invalid key) : %s", (gchar *) k);
		else {
			gboolean rc_local;
			gchar *type_str, *what;

			type_str = g_match_info_fetch(match_info, 1);
			what = g_match_info_fetch(match_info, 2);
			rc_local = module_configure_srvtype(cs, err, type_str, what, v);
			if (type_str)
				g_free(type_str);
			if (what)
				g_free(what);
			if (!rc_local)
				break;
		}
	}

	if (match_info) {
		g_match_info_free(match_info);
		match_info = NULL;
	}

	g_regex_unref(service_param_regex);
	return TRUE;
}

static gboolean
module_init_meta0(struct conscience_s *cs, GHashTable * params, GError ** err)
{
	gchar *str;
	struct conscience_srvid_s srvid;
	struct conscience_srv_s *srv;

	/* If we find a meta0 in config, then it is forced and no other meta0 is
	 * allowed to register. Otherwise the classic register method is used for
	 * meta0 as any other service.
	 */
	if (!(str = g_hash_table_lookup(params, KEY_META0)))
		return TRUE;
	else
		flag_forced_meta0 = TRUE;

	if (!l4_address_init_with_url(&(srvid.addr),str,err)) {
		GSETERROR(err,"Invalid META0 address");
		return FALSE;
	}
	srv = conscience_srvtype_register_srv(conscience_get_srvtype(cs, err, NAME_SRVTYPE_META0, MODE_STRICT), err, &srvid);
	if (!srv) {
		GSETERROR(err, "META0 registration error");
		return FALSE;
	}

	/* Set this address in the conscience object */
	g_memmove(&(cs->ns_info.addr), &(srvid.addr), sizeof(addr_info_t));

	conscience_srv_lock_score(srv, 100);
	NOTICE("[NS=%s][SRVTYPE=%s] new locked META0 service at [%s]", cs->ns_info.name, NAME_SRVTYPE_META0, str);
	return TRUE;
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

static gint
plugin_init(GHashTable * params, GError ** err)
{
	gchar *str;

	g_rec_mutex_init(&counters_mutex);
	g_rec_mutex_init(&conscience_nsinfo_mutex);

	/*NAMEPSACE name */
	if (!(str = g_hash_table_lookup(params, KEY_NAMESPACE))) {
		GSETERROR(err, "The configuration must contain a '%s' key with the namespace name", KEY_NAMESPACE);
		return -1;
	}
	if (!(conscience = conscience_create_named(str, err))) {
		GSETERROR(err, "Conscience allocation failure");
		return -1;
	}
	NOTICE("[NS=%s] Configuring a new conscience", conscience->ns_info.name);

	/*CHUNK SIZE */
	if (!(str = g_hash_table_lookup(params, KEY_CHUNK_SIZE))) {
		GSETERROR(err, "[NS=%s] Missing key '%s' (chunk size in bytes)",
		    conscience->ns_info.name, KEY_CHUNK_SIZE);
		goto error;
	}
	conscience->ns_info.chunk_size = g_ascii_strtoll(str, NULL, 10);
	NOTICE("[NS=%s] Chunk size set to %"G_GINT64_FORMAT, conscience->ns_info.name, conscience->ns_info.chunk_size);

	/* Serialization optimizations */
	str = g_hash_table_lookup(params, KEY_SERIALIZE_SRVINFO_CACHED);
	if (NULL != str)
		flag_serialize_srvinfo_cache = metautils_cfg_get_bool(str, DEF_SERIALIZE_SRVINFO_CACHED);
	NOTICE("[NS=%s] Cache for serialized service_info  [%s]", conscience->ns_info.name,
			(flag_serialize_srvinfo_cache ? "ENABLED" : "DISABLED"));

	str = g_hash_table_lookup(params, KEY_SERIALIZE_SRVINFO_TAGS);
	if (NULL != str)
		flag_serialize_srvinfo_tags = metautils_cfg_get_bool(str, DEF_SERIALIZE_SRVINFO_TAGS);
	NOTICE("[NS=%s] Tags in serialized service_info  [%s]", conscience->ns_info.name,
			(flag_serialize_srvinfo_tags ? "ENABLED" : "DISABLED"));

	str = g_hash_table_lookup(params, KEY_SERIALIZE_SRVINFO_STATS);
	if (NULL != str)
		flag_serialize_srvinfo_stats = metautils_cfg_get_bool(str, DEF_SERIALIZE_SRVINFO_STATS);
	NOTICE("[NS=%s] Stats in serialized service_info  [%s]", conscience->ns_info.name,
			(flag_serialize_srvinfo_stats ? "ENABLED" : "DISABLED"));

	/*Overall alerting maximum per-service frequency*/
	if (!(str = g_hash_table_lookup(params, KEY_ALERT_LIMIT)))
		NOTICE("[NS=%s] No overall alert_frequency_limit set, default kept to [%ld] seconds",
			conscience->ns_info.name, time_default_alert_frequency);
	else {
		time_default_alert_frequency = g_ascii_strtoll(str,NULL,10);
		NOTICE("[NS=%s] Overall alert_frequency_limit set to [%ld] seconds", conscience->ns_info.name, time_default_alert_frequency);
	}

	/* OPTIONS initialization */
	if (!module_init_options(conscience, params, err)) {
		GSETERROR(err, "[NS=%s] options init failed", conscience->ns_info.name);
		goto error;
	}

	/* storage conf initialization */
	*err = module_init_storage_conf(conscience, namespace_storage_policy(&conscience->ns_info, conscience->ns_info.name),
			g_hash_table_lookup(params, KEY_STG_CONF));
	if( NULL != *err ) {
		g_prefix_error(err, "[NS=%s] storage conf init failed", conscience->ns_info.name);
		goto error;
	}

	/*SERVICES initiation*/
	if (!module_init_known_service_types(conscience, params, err)) {
		GSETERROR(err, "[NS=%s] known service types init failed", conscience->ns_info.name);
		goto error;
	}

	if (!module_init_meta0(conscience, params, err)) {
		GSETERROR(err, "[NS=%s] Failed to register a locked meta0 service", conscience->ns_info.name);
		goto error;
	}

	if (!module_init_srvtype_from_cfg(conscience, params, err)) {
		GSETERROR(err, "Configuration error");
		goto error;
	}

	/* Plugin/server stuff */
	if (!srvtimer_register_regular("conscience.expire", timer_expire_services, NULL, conscience, 5LL)) {
		GSETERROR(err, "Failed to register the conscience's dump callback");
		goto error;
	}
	if (!srvtimer_register_regular("conscience.check", timer_check_services, NULL, conscience, 59LL)) {
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

	return 1;
error:
	conscience_destroy(conscience);
	conscience = NULL;
	return -1;
}

static void
_debug_print_hash(gpointer k, gpointer v, gpointer udata)
{
	(void)udata;
	NOTICE("options k = [%s] | v = [%s]", (gchar*)k,(gchar*) ((GByteArray*)v)->data);
}

static gint
plugin_reload(GHashTable * params, GError ** err)
{
	(void) err;
	gchar *str = NULL;
	gchar **tmp = NULL;

	INFO("Reloading conscience configuration");
	/*CHUNK SIZE */
	if (!(str = g_hash_table_lookup(params, KEY_CHUNK_SIZE))) {
		GSETERROR(err, "[NS=%s] Missing key '%s' (chunk size in bytes)",
		    conscience->ns_info.name, KEY_CHUNK_SIZE);
		goto error;
	}
	conscience->ns_info.chunk_size = g_ascii_strtoll(str, NULL, 10);
	NOTICE("[NS=%s] Chunk size set to %"G_GINT64_FORMAT, conscience->ns_info.name, conscience->ns_info.chunk_size);

	g_rec_mutex_lock(&conscience_nsinfo_mutex);

	/* OPTIONS reload */
	/* flush old ns_info_options table */
	g_hash_table_destroy(conscience->ns_info.options);

	if (!module_init_options(conscience, params, err)) {
		GSETERROR(err, "[NS=%s] options init failed", conscience->ns_info.name);
		goto error;
	}

	/* storage conf reload */
	g_hash_table_destroy(conscience->ns_info.storage_policy);
	g_hash_table_destroy(conscience->ns_info.data_security);
	g_hash_table_destroy(conscience->ns_info.data_treatments);
	g_hash_table_destroy(conscience->ns_info.storage_class);
	*err = module_init_storage_conf(conscience, namespace_storage_policy(&conscience->ns_info, conscience->ns_info.name),
			g_hash_table_lookup(params, KEY_STG_CONF));
	if( NULL != *err ) {
		g_prefix_error(err, "[NS=%s] storage conf init failed", conscience->ns_info.name);
		goto error;
	}

	NOTICE("[NS=%s] options reloaded", conscience->ns_info.name);

	g_hash_table_foreach(conscience->ns_info.options, _debug_print_hash, NULL);

	NOTICE("[NS=%s] virtual namespaces reloaded", conscience->ns_info.name);

	g_rec_mutex_unlock(&conscience_nsinfo_mutex);

	if(tmp)
		g_strfreev(tmp);

	return 1;

error:
	if(tmp)
		g_strfreev(tmp);

	return -1;

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

struct exported_api_s exported_symbol = {
	MODULE_NAME,
	plugin_init,
	plugin_close,
	NULL,
	NULL
};

struct exported_api_s exported_symbol_v2 = {
	MODULE_NAME,
	plugin_init,
	plugin_close,
	NULL,
	plugin_reload
};
