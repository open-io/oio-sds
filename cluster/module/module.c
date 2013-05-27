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

#define MODULE_NAME "conscience"
#ifndef LOG_DOMAIN
# define LOG_DOMAIN MODULE_NAME".plugin"
#endif
#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <fnmatch.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/time.h>

#include <glib.h>

#include <metautils.h>
#include <metacomm.h>
#include <plugin.h>
#include <message_handler.h>
#include <srvalert.h>
#include <srvtimer.h>
#include <srvstats.h>

#include "../events/gridcluster_events.h"
#include "../events/gridcluster_eventsremote.h"
#include "../events/gridcluster_eventhandler.h"
#include "../conscience/conscience.h"
#include "../conscience/conscience_broken_holder_common.h"

#include "./alerting.h"
#include "./module.h"

#include "../lib/gridcluster.h"

#define BUFSIZE(B) (B),sizeof(B)
#define BUFLEN(B) (B),sizeof(B)-1
#define SRVID_OF_ADDR(A) ((struct conscience_srvid_s*)(A))
#ifdef HAVE_LEGACY
#define JUMPERR(CTX,C,M) \
do {\
        reply_context_clear((CTX), FALSE);\
        reply_context_set_message ((CTX),\
                ((CTX)->warning && (CTX)->warning->code ? (CTX)->warning->code : (C)),\
                ((CTX)->warning && (CTX)->warning->message ? (CTX)->warning->message : (M)));\
        goto errorLabel;\
} while (0)

/**/
typedef GByteArray *(*serializer_f) (GSList *, GError **);

/*apply an action on the service and the old *info_structure*/
typedef gboolean(*action_f) (struct conscience_srv_s *, gpointer, GError **);

/*convert an old *info in its serialized form*/
typedef gint(*deserializer_f) (GSList **, void *, gsize *, GError **);

/*clean for an old info structure*/
typedef void (*gcleaner_f) (gpointer, gpointer);

/*map a service into an old *info structure*/
typedef void *(*converter_f) (struct service_info_s *);

typedef GPtrArray* (*tags_builder_f) (struct service_info_s *srv, gpointer p);

/*find a service in a conscience from an old *_info structure*/
typedef struct conscience_srv_s *(*service_getter_f) (struct conscience_s *, gpointer, GError **);

/*Execution context used across the several callback for the
 *service retrieval legacy functions*/
struct legacy_srvget_s
{
	GSList *lines;
	guint lines_length;
	guint lines_total;
	gchar type_name[LIMIT_LENGTH_SRVTYPE];
	converter_f convert;
	serializer_f serialize;
	gcleaner_f clean;
	struct reply_context_s reply_ctx;
};

/*
 */
struct legacy_push_s
{
	struct request_context_s *request_ctx;
	gchar type_name[LIMIT_LENGTH_SRVTYPE];
	deserializer_f deserialize;
	gcleaner_f clean;
	tags_builder_f tags_builder;
	enum { PUSH_STAT, PUSH_SCORE, REMOVE } action;
	size_t addr_offset;
	size_t score_offset;
	size_t st_size;
	size_t header_size;
};
#endif

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
		guint32 evt_push;
		guint32 evt_status;
		guint32 push;
		guint32 get;
		guint32 remove;
		guint32 fix;
	} broken;
	struct
	{
		guint32 config;
	} event;
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
	struct reply_context_s reply_ctx;
	GByteArray *gba_body;
	guint srv_list_size;
	guint total_size;
	gchar str_ns[LIMIT_LENGTH_NSNAME + 1];

	gboolean an_error_happened;
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

static GStaticRecMutex counters_mutex;

static GStaticRecMutex conscience_nsinfo_mutex;

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

	SAVE_COUNTER(event.config);
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

#ifdef HYPER_VERBOSE
static void
dump_service(struct conscience_srv_s *srv, gpointer udata)
{
	gchar str_addr[STRLEN_ADDRINFO], str_tag[256];
	guint i;
	struct conscience_s *conscience;
	struct conscience_srvtype_s *srvtype;
	struct service_tag_s *tag;

	(void)udata;
	if (!srv)
		return;
	srvtype = srv->srvtype;
	conscience = srvtype->conscience;
	addr_info_to_string(&(srv->id.addr), str_addr, sizeof(str_addr));
	if (srv->tags && srv->tags->len) {
		DEBUG_DOMAIN(DOMAIN_PERIODIC, "   <srv score=\"%d\" addr=\"%s\" stamp=\"%ld\" locked=\"%s\">",
				srv->score.value, str_addr, srv->score.timestamp, (srv->locked ? "true" : "false"));
		for (i=srv->tags->len; i-->0 ;) {
			tag = g_ptr_array_index(srv->tags, i);
			if (tag) {
				service_tag_to_string(tag, str_tag, sizeof(str_tag));
				DEBUG_DOMAIN(DOMAIN_PERIODIC, "    <tag name=\"%s\" value=\"%s\"/>", tag->name, str_tag);
			}
		}
		DEBUG_DOMAIN(DOMAIN_PERIODIC, "   </srv>");
	}
	else {
		DEBUG_DOMAIN(DOMAIN_PERIODIC, "   <srv score=\"%d\" addr=\"%s\" stamp=\"%ld\" locked=\"%s\"/>",
				srv->score.value, str_addr, srv->score.timestamp, (srv->locked ? "true" : "false"));
	}
}

static void
dump_srvtype(struct conscience_srvtype_s *srvtype)
{

	DEBUG_DOMAIN(DOMAIN_PERIODIC, "  <type name=\"%s\">", srvtype->type_name);
	DEBUG_DOMAIN(DOMAIN_PERIODIC, "   <expr>%s</expr>", srvtype->score_expr_str);
	conscience_srvtype_run_all(srvtype, NULL, SRVTYPE_FLAG_INCLUDE_EXPIRED, dump_service, NULL);
	DEBUG_DOMAIN(DOMAIN_PERIODIC, "  </type>");
}

static void
dump_srvtypes (GHashTable *ht)
{
	gpointer k, v;
	GHashTableIter iter;

	DEBUG_DOMAIN(DOMAIN_PERIODIC, " <srv>");
	g_hash_table_iter_init(&iter, ht);
	while (g_hash_table_iter_next(&iter, &k, &v))
		dump_srvtype((struct conscience_srvtype_s *) v);
	DEBUG_DOMAIN(DOMAIN_PERIODIC, " </srv>");
}

static void
dump_broken_elements(struct broken_holder_s *bh)
{
	gchar str_addr[STRLEN_ADDRINFO];
	gpointer k, v;
	GHashTableIter iter;
	broken_meta1_t *bm1;
	broken_meta2_t *bm2;
	
	DEBUG_DOMAIN(DOMAIN_PERIODIC, " <broken>");
	if (GRID_TRACE_ENABLED()) {
		DEBUG_DOMAIN(DOMAIN_PERIODIC, "  <m1 nb=\"%u\"/>", g_hash_table_size(bh->ht_meta1));
		DEBUG_DOMAIN(DOMAIN_PERIODIC, "  <m2 nb=\"%u\"/>", g_hash_table_size(bh->ht_meta2));
	} else {
		/*META1 dump*/
		DEBUG_DOMAIN(DOMAIN_PERIODIC, "  <m1 nb=\"%u\"/>", g_hash_table_size(bh->ht_meta1));
		g_hash_table_iter_init(&iter, bh->ht_meta1);
		while (g_hash_table_iter_next(&iter,&k,&v)) {
			bm1 = v;
			addr_info_to_string(&(bm1->addr), str_addr, sizeof(str_addr));
			TRACE_DOMAIN(DOMAIN_PERIODIC, "   <srv addr=\"%s\"/>", str_addr);
		}
		DEBUG_DOMAIN(DOMAIN_PERIODIC, "  </m1>");

		/*META2 dump*/
		DEBUG_DOMAIN(DOMAIN_PERIODIC, "  <m2 nb=\"%u\">", g_hash_table_size(bh->ht_meta2));
		g_hash_table_iter_init(&iter, bh->ht_meta2);
		while (g_hash_table_iter_next(&iter,&k,&v)) {
			bm2 = v;
			addr_info_to_string(&(bm2->addr), str_addr, sizeof(str_addr));
			TRACE_DOMAIN(DOMAIN_PERIODIC, "   <srv addr=\"%s\" nb=\"%u\"/>", str_addr, g_hash_table_size(bm2->broken_containers));
		}
		DEBUG_DOMAIN(DOMAIN_PERIODIC, "  </m2>");
	}
	DEBUG_DOMAIN(DOMAIN_PERIODIC, " </broken>");
}

static void
timer_dump_conscience(gpointer u)
{
	gchar str_addr[STRLEN_ADDRINFO];
	struct conscience_s *conscience;

	if (!u)
		return;
	if (!GRID_TRACE_ENABLED())
		return;

	conscience = u;
	addr_info_to_string(&(conscience->ns_info.addr), str_addr, sizeof(str_addr));

	DEBUG_DOMAIN(DOMAIN_PERIODIC, "<conscience ns=\"%s\" chunk_size=\"%lld\" conscience_addr=\"%s\">",
	    conscience_get_namespace(conscience), conscience->ns_info.chunk_size, str_addr);
	
	/* XXX start of critical section */
	conscience_lock_srvtypes(conscience,'r');
	dump_srvtypes(conscience->srvtypes);
	conscience_unlock_srvtypes(conscience);
	/* XXX end of critical section */

	/* XXX start of critical section */	
	conscience_lock_broken_elements(conscience,'r');
	dump_broken_elements(conscience->broken_elements);
	conscience_unlock_broken_elements(conscience);
	/* XXX end of critical section */
	
	DEBUG_DOMAIN(DOMAIN_PERIODIC, "</conscience>");
}
#endif

#if 0
static inline void
manage_meta2_alerts(struct conscience_s *conscience, addr_info_t * addr)
{
	gsize str_addr_size;
	gchar str_addr[128];
	guint broken_elements_counter = 0;
	broken_meta2_t *brk_meta2;

	brk_meta2 = g_hash_table_lookup(conscience->broken_meta2, addr);
	broken_elements_counter += g_hash_table_size(brk_meta2->broken_contents);
	broken_elements_counter += g_hash_table_size(brk_meta2->broken_containers);

	if (broken_elements_counter >= ALERT_THRESHOLD_BRKM2) {
		time_t now = time(0);

		if (now < brk_meta2->last_alert_stamp || (now - brk_meta2->last_alert_stamp) > 300) {
			brk_meta2->last_alert_stamp = now;
			str_addr_size = addr_info_to_string(addr, str_addr, sizeof(str_addr));
			SRV_SEND_ERROR(ALERTID_BROKEN_META2,
			    "META2 on %.*s has %d broken containers", str_addr_size, str_addr, broken_elements_counter);
		}
	}
}
#endif


/* ------------------------------------------------------------------------- */
static GNode*
search_vns_in_tree(GNode *tree_root, const gchar *vns_name)
{
	GNode *node = tree_root;
	do {
		TRACE("Comparing [%s] || [%s]", ((struct vns_info_s*)node->data)->name, vns_name);
		if(g_ascii_strcasecmp(((struct vns_info_s*)node->data)->name, vns_name) == 0) {
			TRACE("VNS [%s] found in tree", vns_name);
			break;
		} else {
			if(g_str_has_prefix(vns_name, ((struct vns_info_s*)node->data)->name)) {
				if(node->children) {
					node = node->children;
				} else {
					DEBUG("VNS [%s] not found in tree", vns_name);
					node = NULL;
					break;
				}
			} else {
				if(!node->next) {
					DEBUG("VNS [%s] not found in tree", vns_name);
					node = NULL;
					break;
				} else
					node = node->next;
			}
		}
	} while(TRUE);

	return node;
}

static gboolean
request_body_matches_namespace(struct request_context_s *req_ctx, GError **err)
{
	void *body = NULL;
	gsize body_size = 0;
	GSList *list_ns = NULL;
	gchar local_ns[LIMIT_LENGTH_NSNAME+1];
	int rc;

	rc = message_get_BODY(req_ctx->request, &body, &body_size, NULL);
	/* No body, consider the namespace matches, for backward compatibility
	 * with old clients */
	if (rc == 0)
		return TRUE;
	if (rc < 0) {
		GSETERROR(err, "Invalid request");
		return FALSE;
	}

	if (!strings_unmarshall(&list_ns, body, &body_size, err)) {
		GSETERROR(err, "Invalid request body");
		return FALSE;
	}

	if (1 != g_slist_length(list_ns)) {
		GSETCODE(err, 400, "Too many namespaces, this conscience only manage exactly 1 NS");
		rc = FALSE;
	}
	else {
		bzero(local_ns, sizeof(local_ns));
		g_strlcpy(local_ns, conscience->ns_info.name, sizeof(conscience->ns_info.name)-1);
		rc = (0 == g_ascii_strcasecmp(local_ns, (gchar*)list_ns->data));
		if(!rc) {
			GNode *vns_node = search_vns_in_tree(conscience->virtual_namespace_tree, (gchar*)list_ns->data);
			if(vns_node)
				rc = TRUE;
		}
	}

	g_slist_foreach(list_ns, g_free1, NULL);
	g_slist_free(list_ns);
	return rc;
}

/* ------------------------------------------------------------------------- */

#ifdef HAVE_LEGACY
static void
_clean_legacy_srvget_accumulator(struct legacy_srvget_s *sg)
{
	if (sg) {
		if (sg->lines) {
			g_slist_foreach(sg->lines, sg->clean, NULL);
			g_slist_free(sg->lines);
		}
		sg->lines = NULL;
		sg->lines_length = 0;
	}
}

static gboolean
srvget_reply_do(struct conscience_srv_s *service, gpointer udata)
{
	struct service_info_s si;
	struct legacy_srvget_s *sg;

	if (!udata) {
		ALERT("Invalid parameter");
		return FALSE;
	}

	sg = udata;

	if (service) {
		void *api_data;

		si.tags = service->tags;
		memcpy(si.ns_name, conscience_get_namespace(conscience), LIMIT_LENGTH_NSNAME);
		memcpy(&(si.addr),  &(service->id.addr), sizeof(addr_info_t));
		memcpy(&(si.score), &(service->score), sizeof(score_t));
		if (!(api_data = sg->convert(&si))) { /*THROW*/
			GSETERROR(&(sg->reply_ctx.warning), "Service conversion error");
			return FALSE;
		}
		sg->lines = g_slist_prepend(sg->lines, api_data);
		sg->lines_length++;
	}

	if (!service || sg->lines_length > 256) {
		/*serialize the body if there is list */
		if (sg->lines) {
			GByteArray *gba = sg->serialize(sg->lines, &(sg->reply_ctx.warning));

			if (!gba) {
				GSETERROR(&(sg->reply_ctx.warning), "Serialization error");
				return FALSE;
			}
			reply_context_set_body(&(sg->reply_ctx), gba->data, gba->len, REPLYCTX_DESTROY_ON_CLEAN|REPLYCTX_COPY);
			g_byte_array_free(gba, TRUE);
			sg->lines_total += sg->lines_length;
	
			_clean_legacy_srvget_accumulator(sg);
		}

		/*is this callback the last one? */
		if (!service)
			reply_context_set_message(&(sg->reply_ctx), 200, "OK");
		else
			reply_context_set_message(&(sg->reply_ctx), 206, "Partial content");

		if (!reply_context_reply(&(sg->reply_ctx), &(sg->reply_ctx.warning))) {
			GSETERROR(&(sg->reply_ctx.warning), "Cannot reply");
			return FALSE;
		}
	}

	return TRUE;
}

static gint
module_legacy_handler_get(struct legacy_srvget_s *sg)
{
	gboolean rc;
	struct conscience_srvtype_s *srvtype;

	/* XXX start of critical section */
	srvtype = conscience_get_locked_srvtype(conscience, &(sg->reply_ctx.warning), sg->type_name, MODE_STRICT, 'r');
	if (!srvtype) {
		GSETERROR(&(sg->reply_ctx.warning), "srvtype=[%s] not found", sg->type_name);
		rc = FALSE;
	}
	else {
		rc = conscience_srvtype_run_all(srvtype, &(sg->reply_ctx.warning), SRVTYPE_FLAG_ADDITIONAL_CALL, srvget_reply_do, sg);
		conscience_release_locked_srvtype(srvtype);
	}
	/* XXX end of critical section */

	/*ensure all the data have been cleaned */
	_clean_legacy_srvget_accumulator(sg);

	/* If the service run failed, then reply an error */
	if (!rc) {
		_reply_ctx_set_error(&(sg->reply_ctx));
		reply_context_reply(&(sg->reply_ctx), NULL);
	}
	reply_context_log_access(&(sg->reply_ctx), "NS=%s", conscience_get_namespace(conscience));
	reply_context_clear(&(sg->reply_ctx), TRUE);
	return rc ? 1 : 0;
}

static gint
legacy_handler_get_vol(struct request_context_s *req_ctx)
{
	struct legacy_srvget_s sg;

	memset(&sg, 0x00, sizeof(sg));
	init_reply_ctx_with_request(req_ctx, &(sg.reply_ctx));
	sg.clean = volume_info_gclean;
	sg.serialize = volume_info_marshall_gba;
	sg.convert = (converter_f) service_info_convert_to_volinfo;
	g_strlcpy(sg.type_name, NAME_SRVTYPE_RAWX, sizeof(sg.type_name));
	
	return module_legacy_handler_get(&sg);
}

static gint
legacy_handler_get_meta0(struct request_context_s *req_ctx)
{
	struct legacy_srvget_s sg;

	memset(&sg, 0x00, sizeof(sg));
	init_reply_ctx_with_request(req_ctx, &(sg.reply_ctx));
	sg.clean = meta0_info_gclean;
	sg.serialize = meta0_info_marshall_gba;
	sg.convert = (converter_f) service_info_convert_to_m0info;
	g_strlcpy(sg.type_name, NAME_SRVTYPE_META0, sizeof(sg.type_name));

	return module_legacy_handler_get(&sg);
}

static gint
legacy_handler_get_meta1(struct request_context_s *req_ctx)
{
	struct legacy_srvget_s sg;

	memset(&sg, 0x00, sizeof(sg));
	init_reply_ctx_with_request(req_ctx, &(sg.reply_ctx));
	sg.clean = meta1_info_gclean;
	sg.serialize = meta1_info_marshall_gba;
	sg.convert = (converter_f) service_info_convert_to_m1info;
	g_strlcpy(sg.type_name, NAME_SRVTYPE_META1, sizeof(sg.type_name));

	return module_legacy_handler_get(&sg);
}

static gint
legacy_handler_get_meta2(struct request_context_s *req_ctx)
{
	struct legacy_srvget_s sg;

	memset(&sg, 0x00, sizeof(sg));
	init_reply_ctx_with_request(req_ctx, &(sg.reply_ctx));
	sg.clean = meta2_info_gclean;
	sg.serialize = meta2_info_marshall_gba;
	sg.convert = (converter_f) service_info_convert_to_m2info;
	g_strlcpy(sg.type_name, NAME_SRVTYPE_META2, sizeof(sg.type_name));

	return module_legacy_handler_get(&sg);
}


/* ------------------------------------------------------------------------- */

static inline gboolean
_legacy_is_zeroed(struct legacy_push_s *sp, guint8 *ptr)
{
	size_t i, len;
	guint8 *start;

	if (sp->st_size == 0 || sp->header_size == 0)
		return FALSE;
	else if (sp->st_size < sp->header_size)
		return FALSE;

	start = ptr + sp->header_size;
	len = sp->st_size - sp->header_size;
	for (i=0; i<len ;i++) {
		if (start[i])
			return FALSE;
	}
	return TRUE;
}

static gint
module_legacy_handler_push(struct legacy_push_s *sp)
{
	struct conscience_srvtype_s *srvtype;
	struct reply_context_s ctx;
	void *data;
	gsize data_size;
	GSList *list = NULL, *l = NULL;

	init_reply_ctx_with_request(sp->request_ctx, &(ctx));

	/* Extract the BODY from request and decode it */
	if (0 >= message_get_BODY(sp->request_ctx->request, &data, &data_size, &(ctx.warning))) {
		GSETCODE(&(ctx.warning), 400, "[%s] Invalid request : no/bad body", sp->type_name);
		goto errorLabel;
	}
	if (0 > sp->deserialize(&list, data, &data_size, &(ctx.warning))) {
		GSETERROR(&(ctx.warning), "[%s] Cannot deserialize the list", sp->type_name);
		goto errorLabel;
	}

	/* XXX start of critical section */
	srvtype = conscience_get_locked_srvtype(conscience, NULL, sp->type_name, MODE_STRICT, 'w');
	if (!srvtype) {
		GSETERROR(&(ctx.warning), "[%s] service type not found", sp->type_name);
		goto errorLabel;
	}

	for (l = list; l && l->data; l = l->next) {
		struct service_info_s si;
		struct conscience_srv_s *srv;

		if (!l->data)
			continue;

		memset(&si, 0x00, sizeof(struct service_info_s));
		g_strlcpy(si.ns_name, conscience_get_namespace(conscience), sizeof(si.ns_name));
		g_strlcpy(si.type, sp->type_name, sizeof(si.type));
		memcpy(&(si.addr), ((guint8 *) l->data) + sp->addr_offset, sizeof(addr_info_t));
		memcpy(&(si.score), ((guint8 *) l->data) + sp->score_offset, sizeof(score_t));
		if (sp->tags_builder)
			sp->tags_builder(&si, l->data);

		srv = conscience_srvtype_get_srv(srvtype, SRVID_OF_ADDR(&(si.addr)));
		switch (sp->action) {
		case PUSH_STAT: /* push some stats */
			if (!srv)
				conscience_srvtype_refresh(srvtype, &(ctx.warning), &si, FALSE);
			else {
				gint32 old_score;
				
				old_score = srv->score.value;
				conscience_srvtype_refresh(srvtype, &(ctx.warning), &si, FALSE);
				if (srv->score.value < old_score && srv->score.value <= 0) {
					if (_legacy_is_zeroed(sp, l->data)) {
						/* Only send alerts for stats totally zeroed, this
						 * is how the old gridagent tells a service is down */
						INFO("v1.1 service down");
						_alert_service_with_zeroed_score(srv);
					}
				}
			}
			break;
		case PUSH_SCORE: /* sets the score */
			if (srv) {
				if (si.score.value < 0) {
					INFO("service [%.*s] UNLOCKED", (int)sizeof(srv->description), srv->description);
					srv->locked = FALSE;
				}
				else
					conscience_srv_lock_score(srv, si.score.value);
			}
			break;
		case REMOVE: /* Removes the service */
			if (srv) {
				gchar str_descr[sizeof(srv->description)];

				g_strlcpy(str_descr, srv->description, sizeof(str_descr));
				conscience_srvtype_remove_srv(srvtype, SRVID_OF_ADDR(&(si.addr)));
				INFO("Service [%.*s] explicitely removed", (int)sizeof(str_descr), str_descr);
			}
			else if (DEBUG_ENABLED()) {
				gchar str_addr[STRLEN_ADDRINFO];

				addr_info_to_string(&(si.addr), str_addr, sizeof(str_addr));
				DEBUG("Service [%s/%s/%.*s] not found", si.ns_name, si.type, (int)sizeof(str_addr), str_addr);
			}
			break;
		}

		/* Clean the working structures */
		if (si.tags) {
			struct service_tag_s *tag;
			gsize i;
			for (i=0; i<si.tags->len ;i++) {
				tag = g_ptr_array_index(si.tags,i);
				if (tag)
					service_tag_destroy(tag);
			}
			g_ptr_array_free(si.tags, TRUE);
			si.tags = NULL;
		}

		/* clean the list's content */	
		sp->clean(l->data, NULL);
		l->data = NULL;
	}
	conscience_release_locked_srvtype(srvtype);
	/* XXX end of critical section */

	g_slist_free(list);

	reply_context_set_message(&ctx, 200, "OK");
	if (!reply_context_reply(&ctx, &(ctx.warning))) {
		GSETERROR(&(ctx.warning), "Cannot acknowledge the volume score");
		JUMPERR(&ctx, 500, "Internal error");
	}

	reply_context_log_access(&ctx, "NS=%s", conscience_get_namespace(conscience));
	reply_context_clear(&ctx, TRUE);
	return 1;

errorLabel:
      	ERROR("An error occured : %s", gerror_get_message(ctx.warning));
	reply_context_set_message(&ctx, gerror_get_code(ctx.warning), gerror_get_message(ctx.warning));
	reply_context_reply(&ctx, NULL);
	reply_context_log_access(&ctx, "NS=%s", conscience_get_namespace(conscience));
	reply_context_clear(&ctx, TRUE);
	return 0;
}


static void
_build_m1tags(struct service_info_s *si, gpointer p)
{
	meta1_stat_t *inf;
	if (!si->tags)
		si->tags = g_ptr_array_new();
	if (si->tags) {
		inf = p;
		service_tag_set_value_i64(service_info_ensure_tag(si->tags, NAME_MACRO_CPU_NAME), inf->cpu_idle);
		service_tag_set_value_i64(service_info_ensure_tag(si->tags, NAME_TAGNAME_REQIDLE), inf->req_idle);
	}
}

static void
_build_m2tags(struct service_info_s *si, gpointer p)
{
	meta2_stat_t *inf;
	if (!si->tags)
		si->tags = g_ptr_array_new();
	if (si->tags) {
		inf = p;
		service_tag_set_value_i64(service_info_ensure_tag(si->tags, NAME_MACRO_CPU_NAME), inf->cpu_idle);
		service_tag_set_value_i64(service_info_ensure_tag(si->tags, NAME_TAGNAME_REQIDLE), inf->req_idle);
		service_tag_set_value_i64(service_info_ensure_tag(si->tags, NAME_MACRO_SPACE_NAME), 99);
	}
}

static void
_build_voltags(struct service_info_s *si, gpointer p)
{
	volume_stat_t *inf;
	if (!si->tags)
		si->tags = g_ptr_array_new();
	if (si->tags) {
		inf = p;
		service_tag_set_value_i64(service_info_ensure_tag(si->tags, NAME_MACRO_CPU_NAME), inf->cpu_idle);
		service_tag_set_value_i64(service_info_ensure_tag(si->tags, NAME_MACRO_IOIDLE_NAME), inf->io_idle);
		service_tag_set_value_i64(service_info_ensure_tag(si->tags, NAME_MACRO_SPACE_NAME), inf->free_chunk);
		service_tag_set_value_string(service_info_ensure_tag(si->tags, NAME_TAGNAME_RAWX_VOL), inf->info.name);
	}
}

static gint
_notify_flush(const gchar *type, struct request_context_s *req_ctx)
{
	struct reply_context_s ctx;

	init_reply_ctx_with_request(req_ctx, &(ctx));

	reply_context_set_message(&ctx, 200, "OK");
	reply_context_reply(&ctx, NULL);
	reply_context_log_access(&ctx, "NS=%s SRVTYPE=%s", conscience_get_namespace(conscience), type);
	reply_context_clear(&ctx, TRUE);
	return 1;
}

static gint
handler_push_volscore(struct request_context_s *req_ctx)
{
	struct legacy_push_s sp;
	
	memset(&sp,0x00,sizeof(sp));
	sp.request_ctx = req_ctx;
	sp.clean = volume_info_gclean;
	sp.deserialize = (deserializer_f) volume_info_unmarshall;
	sp.action = PUSH_SCORE;
	sp.tags_builder = (tags_builder_f) _build_voltags;
	sp.addr_offset = offsetof(struct volume_info_s, addr);
	sp.score_offset = offsetof(struct volume_info_s, score);
	g_strlcpy(sp.type_name, NAME_SRVTYPE_RAWX, sizeof(sp.type_name));

	return module_legacy_handler_push(&sp);
}

static gint
handler_push_m2score(struct request_context_s *req_ctx)
{
	struct legacy_push_s sp;
	
	memset(&sp,0x00,sizeof(sp));
	sp.request_ctx = req_ctx;
	sp.clean = meta2_info_gclean;
	sp.deserialize = (deserializer_f) meta2_info_unmarshall;
	sp.action = PUSH_SCORE;
	sp.tags_builder = (tags_builder_f) _build_m2tags;
	sp.addr_offset = offsetof(struct meta2_info_s, addr);
	sp.score_offset = offsetof(struct meta2_info_s, score);
	g_strlcpy(sp.type_name, NAME_SRVTYPE_META2, sizeof(sp.type_name));

	return module_legacy_handler_push(&sp);
}

static gint
handler_push_volstat(struct request_context_s *req_ctx)
{
	struct legacy_push_s sp;

	memset(&sp,0x00,sizeof(sp));
	sp.request_ctx = req_ctx;
	sp.clean = volume_stat_gclean;
	sp.deserialize = (deserializer_f) volume_stat_unmarshall;
	sp.action = PUSH_STAT;
	sp.tags_builder = (tags_builder_f) _build_voltags;
	sp.addr_offset = offsetof(struct volume_stat_s, info.addr);
	sp.score_offset = offsetof(struct volume_stat_s, info.score);
	sp.st_size = sizeof(struct volume_stat_s);
	sp.header_size = sizeof(struct volume_info_s);
	g_strlcpy(sp.type_name, NAME_SRVTYPE_RAWX, sizeof(sp.type_name));
	
	return module_legacy_handler_push(&sp);
}

static gint
handler_push_m1stat(struct request_context_s *req_ctx)
{
	struct legacy_push_s sp;
	
	memset(&sp,0x00,sizeof(sp));
	sp.request_ctx = req_ctx;
	sp.clean = meta1_stat_gclean;
	sp.deserialize = (deserializer_f) meta1_stat_unmarshall;
	sp.action = PUSH_STAT;
	sp.tags_builder = (tags_builder_f) _build_m1tags;
	sp.addr_offset = offsetof(struct meta1_stat_s, info.addr);
	sp.score_offset = offsetof(struct meta1_stat_s, info.score);
	sp.st_size = sizeof(struct meta1_stat_s);
	sp.header_size = sizeof(struct meta1_info_s);
	g_strlcpy(sp.type_name, NAME_SRVTYPE_META1, sizeof(sp.type_name));

	return module_legacy_handler_push(&sp);
}

static gint
handler_push_m2stat(struct request_context_s *req_ctx)
{
	struct legacy_push_s sp;

	memset(&sp,0x00,sizeof(sp));
	sp.request_ctx = req_ctx;
	sp.clean = meta2_stat_gclean;
	sp.deserialize = (deserializer_f) meta2_stat_unmarshall;
	sp.action = PUSH_STAT;
	sp.tags_builder = (tags_builder_f) _build_m2tags;
	sp.addr_offset = offsetof(struct meta2_stat_s, info.addr);
	sp.score_offset = offsetof(struct meta2_stat_s, info.score);
	sp.st_size = sizeof(struct meta2_stat_s);
	sp.header_size = sizeof(struct meta2_info_s);
	g_strlcpy(sp.type_name, NAME_SRVTYPE_META2, sizeof(sp.type_name));

	return module_legacy_handler_push(&sp);
}

static gint
handler_rm_vol(struct request_context_s *req_ctx)
{
	if (!message_has_BODY(req_ctx->request,NULL)) {
		struct conscience_srvtype_s *srvtype;

		/* XXX start of critical section */
		srvtype = conscience_get_locked_srvtype(conscience, NULL, NAME_SRVTYPE_RAWX, MODE_STRICT, 'w');
		if (srvtype) {
			conscience_srvtype_flush(srvtype);
			conscience_release_locked_srvtype(srvtype);
		}
		/* XXX end of critical section */
		return _notify_flush(NAME_SRVTYPE_RAWX,req_ctx);
	}
	else {
		struct legacy_push_s sp;

		memset(&sp,0x00,sizeof(sp));
		sp.request_ctx = req_ctx;
		sp.clean = volume_info_gclean;
		sp.deserialize = (deserializer_f) volume_info_unmarshall;
		sp.action = REMOVE;
		sp.addr_offset = offsetof(struct volume_info_s, addr);
		sp.score_offset = offsetof(struct volume_info_s, score);
		g_strlcpy(sp.type_name, NAME_SRVTYPE_RAWX, sizeof(sp.type_name));

		return module_legacy_handler_push(&sp);
	}
}

static gint
handler_rm_meta1(struct request_context_s *req_ctx)
{
	if (!message_has_BODY(req_ctx->request,NULL)) {
		struct conscience_srvtype_s *srvtype;

		/* XXX start of critical section */
		srvtype = conscience_get_locked_srvtype(conscience, NULL, NAME_SRVTYPE_META1, MODE_STRICT, 'w');
		if (srvtype) {
			conscience_srvtype_flush(srvtype);
			conscience_release_locked_srvtype(srvtype);
		}
		/* XXX end of critical section */
		return _notify_flush(NAME_SRVTYPE_META1,req_ctx);
	}
	else {
		struct legacy_push_s sp;
		
		memset(&sp,0x00,sizeof(sp));
		sp.request_ctx = req_ctx;
		sp.clean = meta1_info_gclean;
		sp.deserialize = (deserializer_f) meta1_info_unmarshall;
		sp.action = REMOVE;
		sp.addr_offset = offsetof(struct meta1_info_s, addr);
		sp.score_offset = offsetof(struct meta1_info_s, score);
		g_strlcpy(sp.type_name, NAME_SRVTYPE_META1, sizeof(sp.type_name));

		return module_legacy_handler_push(&sp);
	}
}

static gint
handler_rm_meta2(struct request_context_s *req_ctx)
{
	if (!message_has_BODY(req_ctx->request,NULL)) {
		struct conscience_srvtype_s *srvtype;

		/* XXX start of critical section */
		srvtype = conscience_get_locked_srvtype(conscience, NULL, NAME_SRVTYPE_META2, MODE_STRICT, 'w');
		if (srvtype) {
			conscience_srvtype_flush(srvtype);
			conscience_release_locked_srvtype(srvtype);
		}
		/* XXX end of critical section */
		return _notify_flush(NAME_SRVTYPE_META2, req_ctx);
	} 
	else {
		struct legacy_push_s sp;

		memset(&sp,0x00,sizeof(sp));
		sp.request_ctx = req_ctx;
		sp.clean = meta2_info_gclean;
		sp.deserialize = (deserializer_f) meta2_info_unmarshall;
		sp.action = REMOVE;
		sp.addr_offset = offsetof(struct meta2_info_s, addr);
		sp.score_offset = offsetof(struct meta2_info_s, score);
		g_strlcpy(sp.type_name, NAME_SRVTYPE_META2, sizeof(sp.type_name));

		return module_legacy_handler_push(&sp);
	}
}
#endif


/* ------------------------------------------------------------------------- */

static gint
handler_get_ns(struct request_context_s *req_ctx)
{
	namespace_info_t ns_info;
	struct reply_context_s ctx;

	init_reply_ctx_with_request(req_ctx, &ctx);

	/*TODO lock the conscience */
	g_static_rec_mutex_lock(&conscience_nsinfo_mutex);	
	memset(&ns_info, 0x00, sizeof(ns_info));
	memcpy(&ns_info, &(conscience->ns_info), sizeof(namespace_info_t));
	g_static_rec_mutex_unlock(&conscience_nsinfo_mutex);

	/*set the body of the answer */
	reply_context_set_body(&ctx, &ns_info, sizeof(ns_info), REPLYCTX_COPY);
	reply_context_set_message(&ctx, 200, "OK");
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
handler_get_ns_info(struct request_context_s *req_ctx)
{
	struct reply_context_s ctx;
	GByteArray* gba = NULL;

	init_reply_ctx_with_request(req_ctx, &ctx);

	if (!request_body_matches_namespace(req_ctx, &(ctx.warning))) {
		if (!ctx.warning)
			GSETCODE(&(ctx.warning), 400, "Invalid namespace");
		reply_context_clear(&ctx, FALSE);
		reply_context_set_message(&ctx, gerror_get_code(ctx.warning),
				gerror_get_message(ctx.warning));
		(void) reply_context_reply(&ctx, &(ctx.warning));
		reply_context_log_access(&ctx, "NS=?");
		reply_context_clear(&ctx, TRUE);
		return (0);
	}

	/* Serialize ns_info */
	/*
	namespace_info_t ns_info;
	memset(&ns_info, 0x00, sizeof(ns_info));
	g_static_rec_mutex_lock(&conscience_nsinfo_mutex);
	memcpy(&ns_info, &(conscience->ns_info), sizeof(namespace_info_t));
	g_static_rec_mutex_unlock(&conscience_nsinfo_mutex);
	memcpy(&(ns_info.addr),&(si->addr),sizeof(addr_info_t));
	*/

	g_static_rec_mutex_lock(&conscience_nsinfo_mutex);
	gba = namespace_info_marshall(&(conscience->ns_info), &(ctx.warning));
	g_static_rec_mutex_unlock(&conscience_nsinfo_mutex);
	if (gba == NULL) {
		GSETERROR(&(ctx.warning), "Failed to marshall namespace info");
		reply_context_log_access(&ctx, "NS=%s", conscience_get_namespace(conscience));
		reply_context_clear(&ctx, FALSE);
		return 0;
	}

	/*set the body of the answer */
	reply_context_set_body(&ctx, gba->data, gba->len, REPLYCTX_COPY);
	g_byte_array_free(gba, TRUE);
	reply_context_set_message(&ctx, 200, "OK");
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
	void *data = NULL;
	gsize data_size;
	GSList *elements = NULL, *list = NULL;

	init_reply_ctx_with_request(req_ctx, &ctx);

	if (message_has_BODY(req_ctx->request,NULL)) {
		guint counter;
		
		/* Extract MESSAGE from request */
		if (0 >= message_get_BODY(req_ctx->request, &data, &data_size, &(ctx.warning))) {
			GSETCODE(&(ctx.warning), 400, "Bad request : no body");
			goto errorLabel;
		}
		if (!strings_unmarshall(&elements, data, &data_size, &(ctx.warning))) {
			GSETCODE(&(ctx.warning), 400, "Bad request : failed to unmarshall broken container list");
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
	reply_context_set_message(&ctx, 200, "OK");
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
	void *data = NULL;
	gsize data_size;
	GSList *containers = NULL, *list = NULL;

	init_reply_ctx_with_request(req_ctx, &ctx);

	/* Extract MESSAGE from request */
	if (0 >= message_get_BODY(req_ctx->request, &data, &data_size, &(ctx.warning))) {
		GSETCODE(&(ctx.warning),400,"Invalid request - missing body");
		goto errorLabel;
	}

	containers = meta2_maintenance_names_unmarshall_buffer(data, data_size, &(ctx.warning));
	if (!containers) {
		GSETCODE(&(ctx.warning),400,"Invalid request - invalid body, deserialization eror");
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

	reply_context_set_message(&ctx, 200, "OK");
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

#ifdef HAVE_LEGACY
static gint
handler_push_broken_containers(struct request_context_s *req_ctx)
{
	struct reply_context_s ctx;
	void *data = NULL;
	gsize data_size;
	GSList *elements = NULL, *list = NULL;

	init_reply_ctx_with_request(req_ctx, &ctx);
	reply_context_set_body(&ctx, NULL, 0, 0);

	/* Extract MESSAGE from request */
	if (0 >= message_get_BODY(req_ctx->request, &data, &data_size, &(ctx.warning))) {
		GSETCODE(&(ctx.warning),400,"Invalid request - missing body");
		goto errorLabel;
	}

	elements = meta2_maintenance_names_unmarshall_buffer(data, data_size, &(ctx.warning));
	if (!elements) {
		GSETCODE(&(ctx.warning),400,"body unmarshalling error");
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

	reply_context_set_message(&ctx, 200, "OK");
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
#endif

static void
print_node_info(GNode *node)
{
	DEBUG("Node info : name = %s, quota = %"G_GINT64_FORMAT", tot_space = %"G_GINT64_FORMAT, 
		((struct vns_info_s*)node->data)->name, ((struct vns_info_s*)node->data)->quota, ((struct vns_info_s*)node->data)->total_space_used);

}

static void
check_child(GNode* node, GSList **writable_list)
{
	GNode *child = node->children;
	while(child) {
		print_node_info(child);
		if((((struct vns_info_s*)child->data)->quota == -1) ||
			 (((struct vns_info_s*)child->data)->total_space_used < ((struct vns_info_s*)child->data)->quota)) {
			DEBUG("Node writable, add to list");
                        /* writable, add in list and check its children */
                        *writable_list = g_slist_prepend(*writable_list, g_strdup(((struct vns_info_s*)child->data)->name));
                        check_child(child, writable_list);
                }
		child = child->next;
	}
}

static GSList*
build_writable_vns_list(GNode * tree_root)
{
	GSList *result = NULL;
	GNode *node = tree_root;
	print_node_info(node);
	if((((struct vns_info_s*)node->data)->quota == -1) || 
		(((struct vns_info_s*)node->data)->total_space_used < ((struct vns_info_s*)node->data)->quota)) {
		DEBUG("Node writable, add to list");
		/* writable, add in list and check its children */
		result = g_slist_prepend(result, g_strdup(((struct vns_info_s*)node->data)->name));
		check_child(node, &result);
	}
	DEBUG("Writable vns list updated, %d elements", g_slist_length(result));
	return result;
}

static void
namespace_info_set_writable_vns(namespace_info_t *ns_info, GSList *writable_vns)
{
	GByteArray *vns_gba = NULL;
	GSList *l = NULL;
	gchar end[1];
	memset(end, 0x00, sizeof(end));
	vns_gba = g_byte_array_new();
	for(l = writable_vns; l; l = l->next) {
		g_byte_array_append(vns_gba, (guint8*)l->data, strlen((gchar*)l->data));
		if(l->next)
			g_byte_array_append(vns_gba, (guint8*)",", strlen(","));
		else
			g_byte_array_append(vns_gba, (guint8*)end, 1);
	}
	g_hash_table_replace(ns_info->options, g_strdup(KEY_WRITABLE_VNS), vns_gba);
}

static void
update_virtual_namespace_state(gpointer k, gpointer v, gpointer udata)
{
	(void)udata;
	gint64 diff = 0;
	gint64 new_space_used = 0;

	/* sanity check */
	if(!v ||!((GByteArray*)v)->data)
		return;
	else
		new_space_used = g_ascii_strtoll((gchar*)((GByteArray*)v)->data, NULL, 10);

	/* search and update matching node */
	GNode *vns_node = search_vns_in_tree(conscience->virtual_namespace_tree, (gchar*)k);
	if(!vns_node)
		return;

		diff = new_space_used - ((struct vns_info_s*)vns_node->data)->space_used;
		((struct vns_info_s*)vns_node->data)->space_used = new_space_used;
		((struct vns_info_s*)vns_node->data)->total_space_used += diff;

	vns_node = vns_node->parent;
	
	/* add diff to parent total space used */
	while(vns_node) {
		((struct vns_info_s*)vns_node->data)->total_space_used += diff;
		vns_node = vns_node->parent;
	}
	
}

static gint
handler_push_virtual_namespace_space_used(struct request_context_s *req_ctx)
{
	struct reply_context_s ctx;
	void *data = NULL;
	gsize data_size;
	GSList *list = NULL;
	GHashTable *vns_space_used = NULL;
	GSList* writable = NULL;

	init_reply_ctx_with_request(req_ctx, &ctx);
	reply_context_set_body(&ctx, NULL, 0, 0);

	/* Extract MESSAGE from request */
	if (0 >= message_get_BODY(req_ctx->request, &data, &data_size, &(ctx.warning))) {
		GSETCODE(&(ctx.warning),400,"Invalid request - missing body");
		goto errorLabel;
	}

	if( 0 >= key_value_pairs_unmarshall(&list, data, &data_size, &(ctx.warning))) {
		GSETCODE(&(ctx.warning),400,"body unmarshalling error");
		goto errorLabel;
	}

	vns_space_used = key_value_pairs_convert_to_map(list, TRUE, &(ctx.warning));
        if (!vns_space_used) {
		GSETERROR (&(ctx.warning), "Cannot unserialize the content of the reply");
		goto errorLabel;
	}

	if (DEBUG_ENABLED())
		DEBUG("%d VNS space used received", g_hash_table_size(vns_space_used));
	/* lock ns_info */
	g_static_rec_mutex_lock(&conscience_nsinfo_mutex);

	g_hash_table_foreach(vns_space_used, update_virtual_namespace_state, NULL);

	writable = build_writable_vns_list(conscience->virtual_namespace_tree);

	namespace_info_set_writable_vns(&(conscience->ns_info), writable);

	g_static_rec_mutex_unlock(&conscience_nsinfo_mutex);
	/* delock */
	if(writable) {
		g_slist_foreach(writable, g_free1, NULL);
		g_slist_free(writable);
	}
	if (vns_space_used)
		g_hash_table_destroy(vns_space_used);
	if (list) {
		g_slist_foreach(list, key_value_pair_gclean, NULL);
		g_slist_free(list);
	}

	reply_context_set_message(&ctx, 200, "OK");
	reply_context_reply(&ctx, &(ctx.warning));
	reply_context_log_access(&ctx, "NS=%s", conscience_get_namespace(conscience));
	reply_context_clear(&ctx, TRUE);
	return (1);
	
errorLabel:
	ERROR("An error occured : %s", gerror_get_message(ctx.warning));

	if (vns_space_used)
		g_hash_table_destroy(vns_space_used);
	if (list) {
		g_slist_foreach(list, key_value_pair_gclean, NULL);
		g_slist_free(list);
	}
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
		reply_context_set_message(&(data->reply_ctx), (is_last?200:206), (is_last?"OK":"Partial content"));
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

#ifdef HYPER_VERBOSE
	TRACE("Writing m1=%p", bm1);
#endif
	if (bm1) {
		gchar *str = broken_holder_write_meta1(bm1);
		if (str) {
#ifdef HYPER_VERBOSE
			TRACE("Broken element: %s", str);
#endif
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

#ifdef HYPER_VERBOSE
	TRACE("Writing m2=%p bc=%p", bm2, bc);
#endif
	if (bm2) {
		gchar *str;
		if (bc)
			str = broken_holder_write_content(bm2, bc);
		else
			str = broken_holder_write_meta2(bm2);
		if (str) {
#ifdef HYPER_VERBOSE
			TRACE("Broken element: %s", str);
#endif
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
		reply_context_set_message(&(data.reply_ctx), 200, "OK");
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
reply_services(struct conscience_srv_s *srv, gpointer u)
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

		reply_context_clear(&(sg->reply_ctx), TRUE);
		reply_context_set_body(&(sg->reply_ctx), sg->gba_body->data,
				sg->gba_body->len, REPLYCTX_DESTROY_ON_CLEAN|REPLYCTX_COPY);
		
		/*then forward the reply*/
		reply_context_set_message(&(sg->reply_ctx), (srv?206:200),
				(srv?"Partial content":"OK"));

		if (!reply_context_reply(&(sg->reply_ctx), &(sg->reply_ctx.warning))) {
			sg->an_error_happened = TRUE;
			return FALSE;
		}

		/*finally clean what have been replied */
		sg->total_size += sg->srv_list_size;
		sg->srv_list_size = 0;
		_srvget_reset_body(sg);
	}
	return TRUE;
}

static gint
handler_get_service(struct request_context_s *req_ctx)
{
	gboolean rc = 0;
	void *data;
	gsize data_size;
	struct srvget_s sg;

	memset(&sg, 0x00, sizeof(sg));
	init_reply_ctx_with_request(req_ctx, &(sg.reply_ctx));
	sg.full = (0 < message_get_field(req_ctx->request,"FULL",4, &data, &data_size, NULL));

	/* get the service type's name */
	if (0 >= message_get_field(req_ctx->request, BUFLEN("TYPENAME"), &data, &data_size, &(sg.reply_ctx.warning))) {
		GSETCODE(&(sg.reply_ctx.warning), 400, "Bad request : no/invalid TYPENAME field");
	} else {
		gchar **array_types = buffer_split(data, data_size, ",", 0);
		g_strlcpy(sg.str_ns, conscience_get_namespace(conscience), sizeof(sg.str_ns));

		/* XXX start of critical section */
		rc = conscience_run_srvtypes(conscience, &(sg.reply_ctx.warning),
			SRVTYPE_FLAG_ADDITIONAL_CALL|SRVTYPE_FLAG_LOCK_ENABLE, array_types, reply_services, &sg);
		/* XXX end of critical section */

		g_strfreev(array_types);
		rc = 1;
	}

	if (!rc) {
		ERROR("An error occured : %s", gerror_get_message(sg.reply_ctx.warning));
		_reply_ctx_set_error(&(sg.reply_ctx));
		reply_context_reply(&(sg.reply_ctx),NULL);
	}

	if (sg.gba_body)
		g_byte_array_free(sg.gba_body, TRUE);
	reply_context_log_access(&(sg.reply_ctx), "NS=%s", conscience_get_namespace(conscience));
	reply_context_clear(&(sg.reply_ctx), TRUE);
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
		if ( &(cs->ns_info.addr) == NULL ) {
			g_memmove(&(cs->ns_info.addr), &(si->addr), sizeof(addr_info_t));
		}
		//INFO("Not unlocking a "NAME_SRVTYPE_META0" service");
		//return ;
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
	gboolean lock_action = FALSE;
	gint counter;
	GSList *list_srvinfo, *l;
	void *data;
	struct reply_context_s ctx;
	gsize data_size;

	list_srvinfo = NULL;
	init_reply_ctx_with_request(req_ctx, &(ctx));

	/*check if we must work on the lock*/
	lock_action = (0 < message_get_field(req_ctx->request,"LOCK",sizeof("LOCK")-1, &data, &data_size, NULL));
	
	/*Get the body and unpack it as a list of services */
	if (0 >= message_get_BODY(req_ctx->request, &data, &data_size, &(ctx.warning))) {
		GSETCODE(&(ctx.warning), 400, "Bad requets : no body");
		goto errorLabel;
	}
	if (0 >= service_info_unmarshall(&list_srvinfo, data, &data_size, &(ctx.warning))) {
		GSETCODE(&(ctx.warning), 400, "Bad request : failed to deserialize the body");
		goto errorLabel;
	}

	DEBUG("[%d] services to be pushed in namespace [%s]", g_slist_length(list_srvinfo), conscience_get_namespace(conscience));

	/*Now push each service and reply the success */
	for (counter = 0, l = list_srvinfo; l; l = g_slist_next(l)) {
		if (l->data) {
			push_service(conscience, (struct service_info_s *) (l->data), lock_action);
			service_info_clean(l->data);
			l->data = NULL;
			counter++;
		}
	}
	g_slist_free(list_srvinfo);

	reply_context_set_message(&ctx, 200, "OK");
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
		reply_context_set_message(&ctx, 500, gerror_get_message(ctx.warning));
		ERROR("Failed to reply the service types : %s", gerror_get_message(ctx.warning));
		reply_context_reply(&ctx, NULL);
		reply_context_log_access(&ctx, "NS=%s %d names pushed", conscience_get_namespace(conscience), counter);
		reply_context_clear(&ctx, TRUE);
		return 0;
	}

	reply_context_set_body(&ctx, gba_names->data, gba_names->len, REPLYCTX_DESTROY_ON_CLEAN|REPLYCTX_COPY);
	g_byte_array_free(gba_names, TRUE);
	reply_context_set_message(&ctx, 200, "OK");
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
	gint counter;
	struct reply_context_s ctx;

	void *data;
	gsize data_size;

	init_reply_ctx_with_request(req_ctx, &(ctx));
	data = NULL;
	data_size = 0;
	
	/*Get the body and unpack it as a list of services */
	if (0 < message_get_field(req_ctx->request,"TYPENAME",sizeof("TYPENAME")-1,&data,&data_size, NULL)) {
		gchar str_type[LIMIT_LENGTH_SRVTYPE+1];
		struct conscience_srvtype_s *srvtype;
		
		g_strlcpy(str_type, data, sizeof(str_type));
		if (0 == g_ascii_strcasecmp(str_type,NAME_SRVTYPE_META0)) {
			GSETCODE(&(ctx.warning),451,"srvtype=[%s] is read-only!", str_type);
			goto errorLabel;
		}

		/* XXX start of critical section */
		srvtype = conscience_get_locked_srvtype(conscience, &(ctx.warning), str_type, MODE_STRICT,'w');
		if (!srvtype) {
			GSETCODE(&(ctx.warning),450,"srvtype=[%s] not found", str_type);
			goto errorLabel;
		}
		counter = conscience_srvtype_count_srv(srvtype,TRUE);
		conscience_srvtype_flush(srvtype);
		conscience_release_locked_srvtype(srvtype);
		/* XXX end ofcritical section */

		NOTICE("[NS=%s][SRVTYPE=%s] flush done!", conscience_get_namespace(conscience), srvtype->type_name);
		reply_context_set_message(&ctx, 200, "OK");
	}
	else if (0 < message_has_BODY(req_ctx->request,NULL)) {
		GSList *list_srvinfo, *l;

		list_srvinfo = NULL;
		if (0 >= message_get_BODY(req_ctx->request, &data, &data_size, &(ctx.warning))) {
			GSETCODE(&(ctx.warning), 400, "No body");
			goto errorLabel;
		}
		if (0 >= service_info_unmarshall(&list_srvinfo, data, &data_size, &(ctx.warning))) {
			GSETCODE(&(ctx.warning), 400, "Invalid body: deserialization error");
			goto errorLabel;
		}

		NOTICE("[NS=%s] [%d] services to be removed", conscience_get_namespace(conscience), g_slist_length(list_srvinfo));

		/*Now push each service and reply the success */
		for (counter = 0, l = list_srvinfo; l; l = g_slist_next(l)) {
			if (l->data) {
				rm_service(conscience, (struct service_info_s *) (l->data));
				g_free(l->data);
				l->data = NULL;
				counter++;
			}
		}
		g_slist_free(list_srvinfo);
		reply_context_set_message(&ctx, 200, "OK");
	}
	else {
		counter = 0;
		GSETCODE(&(ctx.warning), 400, "Bad request : no service in the body, no service type in the fields");
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

static inline void
repctx_add_int_header(struct reply_context_s *ctx, const gchar *name, gint value)
{
	GByteArray *gba_code;
	gchar wrk_buf[32];
	gba_code = g_byte_array_append(g_byte_array_new(), (const guint8*)wrk_buf, g_snprintf(wrk_buf,sizeof(wrk_buf),"%d", value));
	reply_context_add_header_in_reply(ctx, name, gba_code);
	g_byte_array_free(gba_code,TRUE);
}

static inline void
repctx_add_string_header(struct reply_context_s *ctx, const gchar *name, const gchar *value)
{
	GByteArray *gba_code = g_byte_array_append(g_byte_array_new(), (const guint8*)value, strlen(value));
	reply_context_add_header_in_reply(ctx, name, gba_code);
	g_byte_array_free(gba_code,TRUE);
}

static inline gsize
extract_ueid_from_headers(MESSAGE request, GError **error, gchar *dst, gsize dst_size)
{
	void *data;
	gsize data_size;

	if (0 >= message_get_field(request,MSG_HEADER_UEID,sizeof(MSG_HEADER_UEID)-1, &data, &data_size, NULL)) {
		GSETCODE(error,400,"Header '"MSG_HEADER_UEID"' extraction failure");
		return 0;
	}

	return g_strlcpy(dst, data, MIN(dst_size,data_size));
}

static inline gridcluster_event_t*
extract_event_from_body(MESSAGE request, GError **error)
{
	void *data;
	gsize data_size;
	gridcluster_event_t *event;

	if (0 >= message_get_BODY(request, &data, &data_size, error)) {
		GSETCODE(error, 400, "Bad request: no body");
		return NULL;
	}
	if (!(event = gridcluster_decode_event2(data, data_size, error))) {
		GSETCODE(error, 400, "Bad requets: invalid body");
		return NULL;
	}
	return event;
}

static inline gboolean
__manage_event(struct conscience_s *cs, gridcluster_event_t *event, GError **event_error, GError **error)
{
	gchar str_type[128], str_addr[STRLEN_ADDRINFO+2];
	struct broken_fields_s bf;
	GByteArray *gba_addr, *gba_container, *gba_path, *gba_cause;

	(void)error;

	if (!gridcluster_event_get_type(event, str_type, sizeof(str_type))) {
		GSETCODE(event_error, CODE_EVT_ERROR_DEF, "Invalid event, no TYPE field");
		return TRUE;
	}
	if (0 != fnmatch("broken.*", str_type, 0)) {
		GSETCODE(event_error, CODE_EVT_ERROR_TMP, "Invalid event, TYPE not managed (%s)", str_type);
		return TRUE;
	}

	memset(&bf, 0x00, sizeof(bf));
	bf.packed = "-";
	bf.ns = conscience_get_namespace(cs);

	/*Loads the broken element structure*/
	if ((gba_addr = g_hash_table_lookup(event, "ADDR"))) {
		gchar *ptr_port;
		memset(str_addr, 0x00, sizeof(str_addr));
		memcpy(str_addr, gba_addr->data, MIN(gba_addr->len+1,sizeof(str_addr)));
		bf.ip = str_addr;
		ptr_port = strchr(str_addr,':');
		if (!ptr_port) {
			GSETCODE(event_error, CODE_EVT_ERROR_DEF, "Invalid event : bad address");
			return TRUE;
		}
		*(ptr_port++) = '\0';
		bf.port = atoi(ptr_port);
	} else {
		GSETCODE(event_error, CODE_EVT_ERROR_DEF, "Invalid event, no address");
		return TRUE;
	}
	if ((gba_container = g_hash_table_lookup(event, "CONTAINER")))
		bf.cid = (gchar*)g_byte_array_append(gba_container,(const guint8*)"",1)->data;
	if ((gba_path = g_hash_table_lookup(event, "PATH")))
		bf.content = (gchar*)g_byte_array_append(gba_path,(const guint8*)"",1)->data;
	if ((gba_cause = g_hash_table_lookup(event, "CAUSE")))
		bf.cause = (gchar*)g_byte_array_append(gba_cause,(const guint8*)"",1)->data;

	/*now manage the kind of broken event*/
	if (0 == g_ascii_strcasecmp("broken.META1", str_type))
		broken_holder_add_meta1(conscience->broken_elements, &bf);
	else if (0 == g_ascii_strcasecmp("broken.META2", str_type))
		broken_holder_add_in_meta2(conscience->broken_elements, &bf);
	else if (0 == g_ascii_strcasecmp("broken.CONTAINER", str_type))
		broken_holder_add_in_meta2(conscience->broken_elements, &bf);
	else if (0 == g_ascii_strcasecmp("broken.CONTENT", str_type))
		broken_holder_add_in_meta2(conscience->broken_elements, &bf);

	GSETCODE(event_error, CODE_EVT_WORKDONE, "Event managed");
	return TRUE;
}

static gint
handler_event_push(struct request_context_s *req_ctx)
{
	gboolean rc;
	GError *error_event = NULL;
	struct reply_context_s ctx;
	gridcluster_event_t *event;
	gchar str_ueid[2048];
	gsize str_ueid_size;

	init_reply_ctx_with_request(req_ctx, &ctx);
	memset(str_ueid, 0x00, sizeof(str_ueid));

	str_ueid_size = extract_ueid_from_headers(req_ctx->request, &(ctx.warning), str_ueid, sizeof(str_ueid));
	if (!str_ueid_size)
		goto error_label;
	if (!(event=extract_event_from_body(req_ctx->request, &(ctx.warning)))) {
		GSETCODE(&(ctx.warning), 400, "Invalid event sequence in the payload");
		goto error_label;
	}

	rc = __manage_event(conscience, event, &error_event, &(ctx.warning));
	repctx_add_int_header(&ctx, MSG_HEADER_EVENT_STATUS, gerror_get_code(error_event));
	repctx_add_string_header(&ctx, MSG_HEADER_EVENT_MESSAGE, gerror_get_message(error_event));
	if (error_event)
		g_clear_error(&error_event);
	if (!rc) {
		GSETERROR(&(ctx.warning),"Internal error, event management failed");
		goto error_label;
	}

	reply_context_set_message(&ctx, 200, "OK");
	if (!reply_context_reply(&ctx, &(ctx.warning))) {
		GSETERROR(&(ctx.warning),"Request successful but reply failure!");
		goto reply_error_label;
	}
	
	reply_context_log_access(&ctx, "NS=%s|UEID=%s", conscience_get_namespace(conscience), str_ueid);
	reply_context_clear(&ctx, TRUE);
	return TRUE;

error_label:
	reply_context_clear(&ctx, TRUE);
	reply_context_set_message(&ctx, gerror_get_code((ctx.warning)), gerror_get_message((ctx.warning)));
	reply_context_reply(&ctx, NULL);
reply_error_label:
	reply_context_log_access(&ctx, "NS=%s", conscience_get_namespace(conscience));
	reply_context_clear(&ctx, TRUE);
	return FALSE;
}

static gint
handler_event_status(struct request_context_s *req_ctx)
{
	struct reply_context_s ctx;
	gchar str_ueid[2048];
	gsize str_ueid_size;

	init_reply_ctx_with_request(req_ctx, &ctx);
	memset(str_ueid, 0x00, sizeof(str_ueid));

	str_ueid_size = extract_ueid_from_headers(req_ctx->request, &(ctx.warning), str_ueid, sizeof(str_ueid));
	if (!str_ueid_size)
		goto error_label;

	repctx_add_int_header(&ctx, MSG_HEADER_EVENT_STATUS, CODE_EVT_WORKDONE);
	repctx_add_string_header(&ctx, MSG_HEADER_EVENT_MESSAGE, "Work done");
	if (!reply_context_reply(&ctx, &(ctx.warning))) {
		GSETERROR(&(ctx.warning),"Request successful but reply failure!");
		goto reply_error_label;
	}

	reply_context_log_access(&ctx, "NS=%s|UEID=%s", conscience_get_namespace(conscience), str_ueid);
	reply_context_clear(&ctx, TRUE);
	return TRUE;

error_label:
	reply_context_clear(&ctx, TRUE);
	reply_context_set_message(&ctx, gerror_get_code((ctx.warning)), gerror_get_message((ctx.warning)));
	reply_context_reply(&ctx, NULL);
reply_error_label:
	reply_context_log_access(&ctx, "NS=%s", conscience_get_namespace(conscience));
	reply_context_clear(&ctx, TRUE);
	return FALSE;
}

/* ------------------------------------------------------------------------- */

static gint
handler_get_eventhandler_configuration(struct request_context_s *req_ctx)
{
	struct reply_context_s ctx;
	GByteArray *gba_config;

	init_reply_ctx_with_request(req_ctx, &(ctx));

	/** @todo XXX there is no lock around around the event handler handling 
	 * because the conscience structure is not changed during the plugin lifecycle,
	 * it is configured once at the boginning. */
	gba_config = gridcluster_eventhandler_get_configuration(conscience->event_handler, &(ctx.warning));
	if (!gba_config) {
		GSETCODE(&(ctx.warning),500,"Failed to get the textual configuration of the eventhandler");
		goto reply_error_label;
	}
	reply_context_set_body(&ctx, gba_config->data, gba_config->len, REPLYCTX_DESTROY_ON_CLEAN);
	g_byte_array_free(gba_config,FALSE);
	reply_context_set_message(&ctx,200,"OK");
	if (!reply_context_reply(&ctx,&(ctx.warning))) {
		GSETCODE(&(ctx.warning), 600, "Failed to reply to the client");
		goto error_label;
	}
	reply_context_log_access(&ctx, "NS=%s", conscience_get_namespace(conscience));
	reply_context_clear(&ctx,TRUE);
	return 1;
	
reply_error_label:
	reply_context_set_message(&ctx, gerror_get_code(ctx.warning), gerror_get_message(ctx.warning));
error_label:
	ERROR("[NS=%s] Failed to serve the event handlers configuration for : %s",
		conscience_get_namespace(conscience), gerror_get_message(ctx.warning));
	reply_context_log_access(&ctx, "NS=%s", conscience_get_namespace(conscience));
	reply_context_clear(&ctx,TRUE);
	return 0;
}

#if 0
static gint
handler_get_service_configuration(struct request_context_s *req_ctx)
{
	struct reply_context_s ctx;

	void *data;
	gsize data_size;

	init_reply_ctx_with_request(req_ctx, &(ctx));
	data = NULL;
	data_size = 0;
	
	/*Get the body and unpack it as a list of services */
	if (0 < message_get_field(req_ctx->request,"TYPENAME",sizeof("TYPENAME")-1,&data,&data_size, NULL)) {
		GByteArray *gba_config;
		gchar str_type[LIMIT_LENGTH_SRVTYPE+1];
		struct conscience_srvtype_s *srvtype;

		g_strlcpy(str_type, data, sizeof(str_type));

		/* XXX start of critical section */
		srvtype = conscience_get_locked_srvtype(conscience, &(ctx.warning), str_type, MODE_STRICT,'w');
		if (!srvtype) {
			GSETCODE(&(ctx.warning),450,"srvtype=[%s] not found", str_type);
			goto errorLabel;
		}
		gba_config = conscience_get_serialized_configuration(srvtype,&(ctx.warning));
		conscience_release_locked_srvtype(srvtype);
		/* XXX end ofcritical section */

		if (gba_config)
			reply_context_set_body(&ctx, gba_config->data, gba_config->len, REPLYCTX_COPY|REPLYCTX_DESTROY_ON_CLEAN);
		DEBUG("[NS=%s][SRVTYPE=%s] Configuration found", conscience_get_namespace(conscience), srvtype->type_name);
		reply_context_set_message(&ctx, 200, "OK");
		reply_context_reply(&ctx, NULL);
		reply_context_log_access(&ctx, "NS=%s service %s configuration replied", conscience_get_namespace(conscience), str_type);
	}
	else {
		guint reply_count;
		GSList *list_names, *l;
		struct conscience_srvtype_s *srvtype;

		reply_count = 0;
		list_names = conscience_get_srvtype_names(conscience, NULL);
		for (l=list_names; l ;l=l->next) {
			GByteArray *gba_type;
			GByteArray *gba_config;

			/* XXX start of critical section */
			srvtype = conscience_get_locked_srvtype(conscience, &(ctx.warning), l->data, MODE_STRICT,'w');
			if (!srvtype) {
				GSETCODE(&(ctx.warning),450,"srvtype=[%s] not found", l->data);
				goto errorLabel;
			}
			gba_config = conscience_get_serialized_configuration(srvtype,&(ctx.warning));
			conscience_release_locked_srvtype(srvtype);
			/* XXX end ofcritical section */

			/* set the body */
			reply_context_clear(&ctx, TRUE);
			if (gba_config) {
				reply_context_set_body(&ctx, gba_config->data, gba_config->len, REPLYCTX_COPY|REPLYCTX_DESTROY_ON_CLEAN);
				g_byte_array_free(gba_config, TRUE);
			}

			/* set the message */
			if (l->next)
				reply_context_set_message(&ctx, 206, "Partial content");
			else
				reply_context_set_message(&ctx, 200, "OK");
			TRACE("[NS=%s][SRVTYPE=%s] Configuration found", conscience_get_namespace(conscience), srvtype->type_name);

			/* set additional headers */
			gba_type = g_byte_array_append(g_byte_array_new(), srvtype->type_name, strlen(srvtype->type_name));
			reply_context_add_header_in_reply(&ctx, "TYPENAME", gba_type);
			g_byte_array_free(gba_type,TRUE);
			
			reply_context_reply(&ctx, NULL);
			reply_count++;
		}
		if (!list_names) {
			reply_context_clear(&ctx, TRUE);
			reply_context_set_message(&ctx, 200, "OK");
			reply_context_reply(&ctx, NULL);
		}
		DEBUG("[NS=%s] %d service replied", conscience_get_namespace(conscience), reply_count);
		reply_context_log_access(&ctx, "NS=%s %d services replied", conscience_get_namespace(conscience), reply_count);
	}

	reply_context_clear(&ctx, TRUE);
	return 1;

errorLabel:
	ERROR("Failed to get the configuration of some services : %s", gerror_get_message(ctx.warning));
	_reply_ctx_set_error(&ctx);
	reply_context_reply(&ctx, NULL);
	reply_context_log_access(&ctx, "NS=%s", conscience_get_namespace(conscience));
	reply_context_clear(&ctx, TRUE);
	return 0;
}
#endif

/* ------------------------------------------------------------------------- */


#ifdef HAVE_LEGACY
static inline struct cmd_s *
module_find_legacy_handler(gchar * n, gsize l)
{
	struct cmd_s *c;
	static struct cmd_s CMD[] = {
		{NAME_MSGNAME_CS_GETVOL, legacy_handler_get_vol, &(stats.services.get)},
		{NAME_MSGNAME_CS_GETM0, legacy_handler_get_meta0, &(stats.services.get)},
		{NAME_MSGNAME_CS_GETM1, legacy_handler_get_meta1, &(stats.services.get)},
		{NAME_MSGNAME_CS_GETM2, legacy_handler_get_meta2, &(stats.services.get)},
		{NAME_MSGNAME_CS_PUSH_VOLSTAT, handler_push_volstat, &(stats.services.push_stat)},
		{NAME_MSGNAME_CS_PUSH_M1STAT, handler_push_m1stat, &(stats.services.push_stat)},
		{NAME_MSGNAME_CS_PUSH_M2STAT, handler_push_m2stat, &(stats.services.push_stat)},
		{NAME_MSGNAME_CS_RMVOL, handler_rm_vol, &(stats.services.remove)},
		{NAME_MSGNAME_CS_RMM1, handler_rm_meta1, &(stats.services.remove)},
		{NAME_MSGNAME_CS_RMM2, handler_rm_meta2, &(stats.services.remove)},
		{NAME_MSGNAME_CS_PUSH_VOLSCORE, handler_push_volscore, &(stats.services.push_score)},
		{NAME_MSGNAME_CS_PUSH_M2SCORE, handler_push_m2score, &(stats.services.push_score)},
		{NAME_MSGNAME_CS_PUSH_BROKEN_CONT, handler_push_broken_containers, &(stats.broken.push)},
		{NULL, NULL, NULL}
	};

	for (c = CMD; c && c->c; c++) {
		if (0 == g_ascii_strncasecmp(c->c, n, l))
			return c;
	}

	return NULL;
}
#endif

static inline struct cmd_s *
module_find_handler(gchar * n, gsize l)
{
	struct cmd_s *c;
	static struct cmd_s CMD[] = {
		{NAME_MSGNAME_CS_GETNS, handler_get_ns, &(stats.ns_info)},
		{NAME_MSGNAME_CS_GET_NSINFO, handler_get_ns_info, &(stats.ns_info)},
		{NAME_MSGNAME_CS_GET_SRV, handler_get_service, &(stats.services.get)},
		{NAME_MSGNAME_CS_GET_SRVNAMES, handler_get_services_types, &(stats.services.get)},
		{NAME_MSGNAME_CS_PUSH_SRV, handler_push_service, &(stats.services.push_stat)},
		{NAME_MSGNAME_CS_RM_SRV, handler_rm_service, &(stats.services.remove)},
		{NAME_MSGNAME_CS_GET_BROKEN_CONT, handler_get_broken_containers, &(stats.broken.get)},
		{NAME_MSGNAME_CS_RM_BROKEN_CONT, handler_rm_broken_containers, &(stats.broken.remove)},
		{NAME_MSGNAME_CS_FIX_BROKEN_CONT, handler_fix_broken_containers, &(stats.broken.fix)},
		{NAME_MSGNAME_CS_GET_EVENT_CONFIG, handler_get_eventhandler_configuration, &(stats.event.config)},
		{REQ_EVT_PUSH, handler_event_push, &(stats.broken.evt_push)},
		{REQ_EVT_STATUS, handler_event_status, &(stats.broken.evt_status)},
		{NAME_MSGNAME_CS_PUSH_VNS_SPACE_USED, handler_push_virtual_namespace_space_used, &(stats.services.push_vns)},
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

	if (!message_has_NAME(m, err))
		return 0;

	message_get_NAME(m, (void *) &name, &nameLen, err);
	if (!name || nameLen <= 0) {
		INFO("The message contains an invalid NAME parameter");
		return 0;
	}

	c = module_find_handler(name, nameLen);
#ifdef HAVE_LEGACY
	if (!c)
		c = module_find_legacy_handler(name, nameLen);
#endif
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

	message_get_NAME(m, (void *) &name, &nameLen, err);
	if (!name || nameLen <= 6) {
		GSETERROR(err, "The message contains an invalid NAME parameter");
		return -1;
	}

	c = module_find_handler(name, nameLen);
#ifdef HAVE_LEGACY
	if (!c)
		c = module_find_legacy_handler(name, nameLen);
#endif
	if (!c) {
		GSETERROR(err, "This message does not concern this plugin.");
		return -1;
	}

	memset(&ctx, 0x00, sizeof(ctx));
	ctx.request = m;
	ctx.fd = cnx;
	gettimeofday(&(ctx.tv_start), NULL);

	g_static_rec_mutex_lock(&counters_mutex);
	*(c->req_counter) = *(c->req_counter) + 1;
	g_static_rec_mutex_unlock(&counters_mutex);

	return c->h(&ctx);
}


/* ------------------------------------------------------------------------- */

static inline gboolean
module_check_event_handler(const gchar * cName, const gchar * cfg, gsize cfg_size, GError ** err)
{
	gridcluster_event_handler_t *event_handler;
	gboolean rc = FALSE;

	event_handler = gridcluster_eventhandler_create(cName, err, NULL, NULL);
	if (!event_handler) {
		GSETERROR(err, "Failed to init a new EventHandler");
		goto error_init;
	}

	if (!gridcluster_eventhandler_configure(event_handler, cfg, cfg_size, err)) {
		GSETERROR(err, "Invalid configuration");
		goto error_configure;
	}

	rc = TRUE;

      error_configure:
	gridcluster_eventhandler_destroy(event_handler, FALSE);
      error_init:
	return rc;
}

static gboolean
module_set_conscience_eventhandlers(struct conscience_s *cs, GError ** err, const gchar * raw_path)
{
	gchar *data = NULL, path[1024];
	gsize size = 0;

	/*purifies the given path */
	if (!raw_path || !cs) {
		GSETERROR(err, "Invalid parameter (%p,%p)", cs, raw_path);
		return FALSE;
	}
	else {
		const gchar *ptr;
		for (ptr=raw_path; *ptr && (g_ascii_isspace(*ptr) || (*ptr=='/' && *(ptr+1)=='/')); ptr++);
		g_strlcpy(path, ptr, sizeof(path));
	}

	if (!g_file_get_contents(path, &data, &size, err)) {
		GSETERROR(err, "[NS=%s] Cannot load the configuration file [%s]", conscience_get_namespace(cs), path);
		return FALSE;
	}

	if (!module_check_event_handler(cs->ns_info.name, data, size, err)) {
		GSETERROR(err, "[NS=%s] Failed to configure an EventHandler with the content of [%s]",
		    conscience_get_namespace(cs), path);
		goto error_label;
	}

	if (!cs->event_handler)
		cs->event_handler = gridcluster_eventhandler_create(conscience_get_namespace(cs), err, NULL, NULL);
	if (data) {
		if (!gridcluster_eventhandler_configure(cs->event_handler, data, size, err)) {
			GSETERROR(err,"[NS=%s] Failed to configure the event handling rules", conscience_get_namespace(cs));
			goto error_label;
		}
	}

	INFO("[NS=%s] successfully configured an EventHandler with the content of [%s]", cs->ns_info.name, path);
	g_free(data);
	return TRUE;

error_label:
	g_free(data);
	return FALSE;
}

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

static gboolean
g_free_node_data(GNode *node, gpointer udata)
{
	(void) udata;
	if(node->data) {
		if(((struct vns_info_s*)node->data)->name)
			g_free(((struct vns_info_s*)node->data)->name);
		g_free(node->data);
	}
	return FALSE;
}

static void
destroy_vns_tree(GNode *tree_root)
{
	g_node_traverse (tree_root, G_IN_ORDER, G_TRAVERSE_ALL, -1, g_free_node_data, NULL); 
	g_node_destroy(tree_root);
}

static GNode*
init_vns_in_tree(GNode *tree_root, gchar* vns_name)
{
	struct vns_info_s *vns_info = NULL;
	GNode *node = NULL;
	node = tree_root;
	GNode *new_node = NULL;

	void check_new_node_next_slibing(GNode *n) {
		/* if no next sibling, no check to do */
		if(!n->next)
			return;
		GNode *ptmp = n;
		GNode *tmp = n->next;
		do {
			if(g_str_has_prefix(((struct vns_info_s*)tmp->data)->name, ((struct vns_info_s*)n->data)->name)) {
				/* this node is a child */
				/* link tmp->prev & tmp->next jumping tmp node */
				tmp->prev->next = tmp->next;
				if(tmp->next)
					tmp->next->prev = tmp->prev;

				/* move tmp node under its new parent */
				tmp->prev = NULL;
				tmp->parent = n;
				tmp->next = n->children;
				n->children = tmp;
			} else {
				/* this node isn't a child, continue */
				ptmp = tmp;
			}
			tmp = ptmp->next;

		} while(tmp);
		ptmp = NULL;
	}

	while(TRUE) {
		/* check if vns is a child of current node */
		if (g_str_has_prefix(vns_name, ((struct vns_info_s*)node->data)->name)) {
			if(node->children)
				node = node->children;
			else {
				vns_info = g_malloc0(sizeof(struct vns_info_s));
				vns_info->name = vns_name;
				vns_info->space_used = 0;
				vns_info->total_space_used = 0;
				gchar key[LIMIT_LENGTH_NSNAME + 10];
				bzero(key, sizeof(key));
				g_snprintf(key, sizeof(key), "quota_%s", vns_name);
				GByteArray *quota_gba = g_hash_table_lookup(conscience->ns_info.options, key);

				if(quota_gba)
					vns_info->quota = g_ascii_strtoll((gchar*)quota_gba->data, NULL, 10);
				else
					vns_info->quota = -1;
				new_node = g_node_new(vns_info);
				g_node_insert(node, -1, new_node); 
				break;
			}
		} else {
			/* check if current node is a child of vns */
			if (g_str_has_prefix(((struct vns_info_s*)node->data)->name, vns_name)) {
				/* current node is a child of this vns, insert before, and check if we need to downgrade its next sibling */
				if(node->parent) {
					vns_info = g_malloc0(sizeof(struct vns_info_s));
					vns_info->name = vns_name;
					vns_info->space_used = 0;
					vns_info->total_space_used = 0;
					GByteArray *quota_gba = g_hash_table_lookup(conscience->ns_info.options, vns_name);
					if(quota_gba)
						vns_info->quota = g_ascii_strtoll((gchar*)quota_gba->data, NULL, 10);
					else
						vns_info->quota = -1;
					new_node = g_node_new(vns_info);
					new_node = g_node_insert_before(node->parent, node, new_node);
					check_new_node_next_slibing(new_node);
					break;
				} else {
					WARN("Virtual Namespace [%s] found in config, but not match with physical namespace [%s]",
							(gchar*)vns_name, (gchar*)((struct vns_info_s*)tree_root->data)->name);
					break;
				}
			} else {
				if(node->next)
					node = node->next;
				else {
					if(node->parent) {
						vns_info = g_malloc0(sizeof(struct vns_info_s));
						vns_info->name = vns_name;
						vns_info->space_used = 0;
						vns_info->total_space_used = 0;
						GByteArray *quota_gba = g_hash_table_lookup(conscience->ns_info.options, vns_name);
						if(quota_gba)
							vns_info->quota = g_ascii_strtoll((gchar*)quota_gba->data, NULL, 10);
						else
							vns_info->quota = -1;
						new_node = g_node_new(vns_info);
						g_node_insert(node->parent, -1, new_node);
						break;
					} else {
						WARN("Virtual Namespace [%s] found in config, but not match with physical namespace [%s]",
							(gchar*)vns_name, (gchar*)((struct vns_info_s*)tree_root->data)->name);
						break;
					}
				}
			}
		}
	}
	return new_node;
}

static gboolean
reset_total_space_used(GNode *node, gpointer udata)
{
	(void) udata;  
	DEBUG("Reset total_space_used fo vns %s",((struct vns_info_s*)node->data)->name);	
	((struct vns_info_s*)node->data)->total_space_used = 0;
	return FALSE;
}

static gboolean
notify_total_space_used(GNode *node, gpointer udata)
{
	(void) udata;	
	GNode *n = node;
	if(n->parent) {
		DEBUG("Updating vns %s space used, new total_space_used = %"G_GINT64_FORMAT,
				((struct vns_info_s*)n->parent->data)->name, ((struct vns_info_s*)n->parent->data)->total_space_used);
		((struct vns_info_s*)n->parent->data)->total_space_used += ((struct vns_info_s*)n->data)->total_space_used;
	}
	n = NULL;
	return FALSE;
}

static void
rebuild_vns_space_used(GNode *tree_root)
{
	INFO("Rebuilding vns space used");

	/* set tot space_used to 0  for each node which are not a */
	g_node_traverse(tree_root, G_IN_ORDER, G_TRAVERSE_NON_LEAVES, -1, reset_total_space_used, NULL);
	/* rebuild tot space_used */
	g_node_traverse(tree_root, G_POST_ORDER, G_TRAVERSE_ALL, -1, notify_total_space_used, NULL);
}

static gboolean
module_reload_vns(struct conscience_s *cs, GError ** err)
{
	GByteArray *vns_gba = NULL;
	GSList *writable_list = NULL;
	GNode *new_tree_root = NULL;

	/* prepare new tree_root */

	struct vns_info_s *root_info = NULL;
	root_info = g_malloc0(sizeof(struct vns_info_s));
	root_info->name = g_strndup(cs->ns_info.name, strlen(cs->ns_info.name));
	root_info->space_used = ((struct vns_info_s*)cs->virtual_namespace_tree->data)->space_used;
	root_info->total_space_used = ((struct vns_info_s*)cs->virtual_namespace_tree->data)->total_space_used;
	GByteArray *quota_gba = g_hash_table_lookup(cs->ns_info.options, cs->ns_info.name);
	if(quota_gba)
		root_info->quota = g_ascii_strtoll((gchar*)quota_gba->data, NULL, 10);
	else
		root_info->quota = -1;

	new_tree_root = g_node_new(root_info);

	/*reload vns list from conf */
	vns_gba = g_hash_table_lookup(cs->ns_info.options, KEY_VNS_LIST);
	if(vns_gba) { 
		/* vns gba split */
		gchar **buf = NULL;
		buf = g_strsplit((gchar*)vns_gba->data, ",", 0);
		if(!buf || !*buf) {
			GSETERROR(err, "[NS=%s] Failed to split virtual namespace list", cs->ns_info.name);
			return FALSE;
		}

		gchar *tmp = NULL;
		GSList *new_vns_list = NULL;

		/* get vns list we must serve */
		for(guint i = 0; i < g_strv_length (buf); i++) {
			tmp = g_strstrip(g_strdup(buf[i]));
			INFO("Serving virtual namespace : [%s]", tmp);
			new_vns_list = g_slist_prepend(new_vns_list, tmp);
		}
		g_strfreev(buf);

		/* add new vns */
		GNode *new_node = NULL;
		GNode *old_node = NULL;
		GSList *l = new_vns_list;

		while(l && l->data) {
			new_node = init_vns_in_tree(new_tree_root, (gchar*)l->data);
			if(new_node) {
				/* get info in old tree */
				old_node = search_vns_in_tree(cs->virtual_namespace_tree, (gchar*)l->data);
				if(old_node) {
					((struct vns_info_s*)new_node->data)->space_used = ((struct vns_info_s*) old_node->data)->space_used;
					((struct vns_info_s*)new_node->data)->total_space_used = ((struct vns_info_s*) old_node->data)->total_space_used;
				}
				old_node = NULL;
				new_node = NULL;
			} else
				WARN("Failed to init node in new tree for VNS [%s]", (gchar*)l->data);
			l = l->next;
		}
		g_slist_free(new_vns_list);
	}

	rebuild_vns_space_used(new_tree_root);
	destroy_vns_tree(cs->virtual_namespace_tree);
	cs->virtual_namespace_tree = new_tree_root;

	INFO("Virtual namespace n-tree rebuild");
	
	writable_list = build_writable_vns_list(cs->virtual_namespace_tree);

	INFO("Conscience writable namespace list: [%d] elements", g_slist_length(writable_list));

	/* add writable vns in options map */
	namespace_info_set_writable_vns(&(cs->ns_info), writable_list);
	g_slist_foreach(writable_list, g_free1, NULL);
	g_slist_free(writable_list);

	return TRUE;
}


static gboolean
module_init_vns(struct conscience_s *cs, GError ** err)
{
	GByteArray *vns_gba = NULL;
	GSList *writable_vns = NULL;

	/* INIT virtual namespace GNode assembly */
	struct vns_info_s *root_info = NULL;
	root_info = g_malloc0(sizeof(struct vns_info_s));
	root_info->name = g_strndup(cs->ns_info.name, strlen(cs->ns_info.name));
	root_info->space_used = 0;
	root_info->total_space_used = 0;
	GByteArray *quota_gba = g_hash_table_lookup(cs->ns_info.options, cs->ns_info.name);
	if(quota_gba)
		root_info->quota = g_ascii_strtoll((gchar*)quota_gba->data, NULL, 10);
	else
		root_info->quota = -1;

	cs->virtual_namespace_tree = g_node_new(root_info);

	INFO("Root node created");
	print_node_info(cs->virtual_namespace_tree);

	vns_gba = g_hash_table_lookup(cs->ns_info.options, KEY_VNS_LIST);

	if(!vns_gba) {
		INFO("[NS=%s] No entry %s in options table, no virtual namespaces to serve.", cs->ns_info.name, KEY_VNS_LIST);
	} else {
		gchar **buf = NULL;
		buf = g_strsplit((gchar*)vns_gba->data, ",", 0);
		if(!buf || !*buf) {
			GSETERROR(err, "[NS=%s] Failed to split virtual namespace list", cs->ns_info.name);
			return FALSE;
		}
		gchar *tmp = NULL;

		/* Place all served vns in the tree */
		for(guint i = 0; i < g_strv_length (buf); i++) {
			tmp = g_strstrip(g_strdup(buf[i]));
			INFO("Serving virtual namespace : [%s]", tmp);
			init_vns_in_tree(cs->virtual_namespace_tree, tmp);
			tmp = NULL;
		}
		g_strfreev(buf);

		INFO("Virtual namespace n-tree initialised");
	}

	INFO("building writable namespace list...");
	
	writable_vns = build_writable_vns_list(cs->virtual_namespace_tree);

	INFO("Conscience writable namespace list: [%d] elements", g_slist_length(writable_vns));

	/* Write list in ns_info options table */
	namespace_info_set_writable_vns(&(cs->ns_info), writable_vns);

	/* free the tmp list */
	g_slist_foreach(writable_vns, g_free1, NULL);
	g_slist_free(writable_vns);
	
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
		g_set_error(&e, 0, 500, "No '%s' group in configuration", group_name);
		return e;
	}

	keys = g_key_file_get_keys (conf_file, group_name, &size, &e);
	if ( NULL != keys) {
		for (uint i = 0; i < g_strv_length(keys); i++) {
			v = g_key_file_get_value (conf_file, group_name, keys[i], &e);
			if (!v) {
				GSETERROR (&e, "Cannot get the value");
				break;
			}
			if (NULL != g_hash_table_lookup(ht, keys[i])) {
				WARN("Duplicate key [%s] in hashtable for group [%s].  The value [%s] will be associated to this key.",
						keys[i], group_name, v);
			}
			g_hash_table_insert (ht, g_strdup(keys[i]), metautils_gba_from_string(v));
		}
		g_strfreev(keys);
		return e;
	}
	g_set_error(&e, 0 , 500, "Cannot get all keys of group '%s'", group_name);
	return e;
}

static GError *
module_init_storage_conf(struct conscience_s *cs, const gchar *stg_pol_in_option, const gchar *filepath)
{
	GKeyFile *stg_conf_file = g_key_file_new();
	GError *e = NULL;

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

	cs->ns_info.storage_policy = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, metautils_gba_unref);
	e = fill_hashtable_with_group(cs->ns_info.storage_policy, stg_conf_file, NAME_GROUPNAME_STORAGE_POLICY);
	if( NULL != e) {
		g_prefix_error(&e, "Error collecting storage policy rules from file [%s]", filepath);
		g_key_file_free(stg_conf_file);
		return e;
	}

	/* If the storage policy set by param_option.storage_policy is not present in the storage conf file, set an error. */
	if (stg_pol_in_option && !g_hash_table_lookup(cs->ns_info.storage_policy, stg_pol_in_option)) {
		GSETERROR(&e, "[NS=%s] storage conf init failed: the policy [%s] wanted as an option is not defined in [%s]",
				cs->ns_info.name, stg_pol_in_option, filepath);
		g_key_file_free(stg_conf_file);
		return e;
	}

	cs->ns_info.data_security = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, metautils_gba_unref);
	e = fill_hashtable_with_group(cs->ns_info.data_security, stg_conf_file, NAME_GROUPNAME_DATA_SECURITY);
	if( NULL != e) {
		WARN("Data security rules not correctly loaded from file [%s] : %s", filepath, e->message);
		g_clear_error(&e);
		e = NULL;
	}

	cs->ns_info.data_treatments = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, metautils_gba_unref);
	e = fill_hashtable_with_group(cs->ns_info.data_treatments, stg_conf_file, NAME_GROUPNAME_DATA_TREATMENTS);
	if( NULL != e) {
		WARN("Data treatments rules not correctly loaded from file [%s] : %s", filepath, e->message);
		g_clear_error(&e);
		e = NULL;
	}

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

	if (!(str = g_hash_table_lookup(params, KEY_META0))) {
		GSETERROR(err, "Key '%s' is missing (format 'ip:port')", KEY_META0);
		return FALSE;
	}
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

struct srvtype_init_s {
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
		{NAME_SRVTYPE_SOLR,EXPR_DEFAULT_INDX},
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

	g_static_rec_mutex_init(&counters_mutex);
	g_static_rec_mutex_init(&conscience_nsinfo_mutex);

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
	*err = module_init_storage_conf(conscience, namespace_storage_policy(&conscience->ns_info),
			g_hash_table_lookup(params, KEY_STG_CONF));
	if( NULL != *err ) {
		g_prefix_error(err, "[NS=%s] storage conf init failed", conscience->ns_info.name);
		goto error;
	}

	if (!module_init_vns(conscience, err)) {
		GSETERROR(err, "[NS=%s] virtual namespaces init failed", conscience->ns_info.name);
		goto error;
	}

	/*SERVICES initiation*/
	if (!module_init_known_service_types(conscience, params, err)) {
		GSETERROR(err, "[NS=%s] known service types init failed", conscience->ns_info.name);
		goto error;
	}

	/*
	if (!module_init_meta0(conscience, params, err)) {
		GSETERROR(err, "[NS=%s] Failed to register a locked meta0 service", conscience->ns_info.name);
		goto error;
	}
	*/

	if (!module_init_srvtype_from_cfg(conscience, params, err)) {
		GSETERROR(err, "Configuration error");
		goto error;
	}

	/*EVENTS initiaition*/
	if (!(str = g_hash_table_lookup(params,KEY_EVENT_HANDLERS)))
		INFO("[NS=%s] no event handler configured", conscience->ns_info.name);
	else if (!module_set_conscience_eventhandlers(conscience, err, str)) {
		GSETERROR(err,"[NS=%s] failed to loaded the event handler from [%s]", conscience_get_namespace(conscience), str);
		goto error;
	}
	else
		NOTICE("[NS=%s] event handlers successfully loaded from [%s]", conscience->ns_info.name, str);

	/* Plugin/server stuff */
	if (!srvtimer_register_regular("conscience.expire", timer_expire_services, NULL, conscience, 5LL)) {
		GSETERROR(err, "Failed to register the conscience's dump callback");
		goto error;
	}
	if (!srvtimer_register_regular("conscience.check", timer_check_services, NULL, conscience, 59LL)) {
		GSETERROR(err, "Failed to register the conscience's dump callback");
		goto error;
	}
#ifdef HYPER_VERBOSE
	if (log4c_category_is_debug_enabled(log4c_category_get(DOMAIN_PERIODIC))) {
		if (!srvtimer_register_regular("conscience.dump", timer_dump_conscience, NULL, conscience, 10LL)) {
			GSETERROR(err, "Failed to register the conscience's dump callback");
			goto error;
		}
	}
#endif

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
	
	g_static_rec_mutex_lock(&conscience_nsinfo_mutex);

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
	*err = module_init_storage_conf(conscience, namespace_storage_policy(&conscience->ns_info),
			g_hash_table_lookup(params, KEY_STG_CONF));
	if( NULL != *err ) {
		g_prefix_error(err, "[NS=%s] storage conf init failed", conscience->ns_info.name);
		goto error;
	}

	NOTICE("[NS=%s] options reloaded", conscience->ns_info.name);

	g_hash_table_foreach(conscience->ns_info.options, _debug_print_hash, NULL);

	if (!module_reload_vns(conscience, err)) {
		GSETERROR(err, "[NS=%s] virtual namespaces reload failed", conscience->ns_info.name);
		goto error;
	}

	NOTICE("[NS=%s] virtual namespaces reloaded", conscience->ns_info.name);

	/*EVENTS initiaition*/
	if (!(str = g_hash_table_lookup(params,KEY_EVENT_HANDLERS))) {
		if(conscience->event_handler)
			gridcluster_eventhandler_destroy(conscience->event_handler, FALSE);
		INFO("[NS=%s] no event handler configured", conscience->ns_info.name);
	} else if (!module_set_conscience_eventhandlers(conscience, err, str)) {
		GSETERROR(err,"[NS=%s] failed to loaded the event handler from [%s]", conscience_get_namespace(conscience), str);
		goto error;
	}
	else
		NOTICE("[NS=%s] event handlers successfully reloaded from [%s]", conscience->ns_info.name, str);



	g_static_rec_mutex_unlock(&conscience_nsinfo_mutex);

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
		g_static_rec_mutex_free(&counters_mutex);
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
