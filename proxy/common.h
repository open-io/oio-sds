/*
OpenIO SDS proxy
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2020-2025 OVH SAS

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

#ifndef OIO_SDS__proxy__common_h
# define OIO_SDS__proxy__common_h 1

#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>

#include <glib.h>
#include <json-c/json.h>

#include <core/lrutree.h>
#include <core/oioerrors.h>
#include <core/url_ext.h>
#include <core/client_variables.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/common_variables.h>
#include <proxy/proxy_variables.h>
#include <proxy/shard_resolver.h>

#include <cluster/lib/gridcluster.h>
#include <server/network_server.h>
#include <server/server_variables.h>
#include <resolver/hc_resolver.h>
#include <resolver/resolver_variables.h>
#include <meta1v2/meta1_remote.h>
#include <meta2v2/meta2_macros.h>
#include <meta2v2/meta2_utils.h>
#include <meta2v2/autogen.h>
#include <meta2v2/generic.h>
#include <sqliterepo/sqlx_remote.h>
#include <sqliterepo/sqlite_utils.h>

#include "meta2v2_remote.h"
#include "path_parser.h"
#include "transport_http.h"

#define TOK(N)    _req_get_token(args,(N))
#define NS()      TOK("NS")

#define OPT(N)                  _req_get_option(args,(N))
#define CID()                   OPT("cid")
#define CONSCIENCE()            OPT("cs")
#define ACCOUNT()               OPT("acct")
#define POOL()                  OPT("pool")
#define CONTENT()               OPT("content")
#define TYPE()                  OPT("type")
#define REF()                   OPT("ref")
#define PATH()                  OPT("path")
#define SEQ()                   OPT("seq")
#define VERSION()               OPT("version")
#define SERVICE_ID()            OPT("service_id")
#define SUFFIX()                OPT("suffix")
#define BYPASS_SERVICE_DOWN()   OPT("bypass_service_down")

#define GUARDED_READ(Lock,Action) do { \
	g_rw_lock_reader_lock(&Lock); \
	do { Action ; } while (0); \
	g_rw_lock_reader_unlock(&Lock); \
} while (0)

#define GUARDED_WRITE(Lock,Action) do { \
	g_rw_lock_writer_lock(&Lock); \
	do { Action ; } while (0); \
	g_rw_lock_writer_unlock(&Lock); \
} while (0)

#define NSINFO_READ(Action)  GUARDED_READ(nsinfo_rwlock,Action)
#define NSINFO_WRITE(Action) GUARDED_WRITE(nsinfo_rwlock,Action)

#define REG_READ(Action)  GUARDED_READ(reg_rwlock,Action)
#define REG_WRITE(Action) GUARDED_WRITE(reg_rwlock,Action)

#define PUSH_READ(Action)  GUARDED_READ(push_rwlock,Action)
#define PUSH_WRITE(Action) GUARDED_WRITE(push_rwlock,Action)

#define SRV_READ(Action)  GUARDED_READ(srv_rwlock,Action)
#define SRV_WRITE(Action) GUARDED_WRITE(srv_rwlock,Action)

#define WANTED_READ(Action)  GUARDED_READ(wanted_rwlock,Action)
#define WANTED_WRITE(Action) GUARDED_WRITE(wanted_rwlock,Action)

#define MASTER_READ(Action)  GUARDED_READ(master_rwlock,Action)
#define MASTER_WRITE(Action) GUARDED_WRITE(master_rwlock,Action)

/** Allocate on the stack a shuffled array of Conscience addresses. */
#define CSURL(C) gchar **C = NULL; do { \
	C = proxy_get_cs_urlv(); \
	STRINGV_STACKIFY(C); \
} while (0)

#define COMA(gs,first) do { \
	if (!first) \
		g_string_append_c (gs, ','); \
	else \
		first = FALSE; \
} while (0)

/* ------------------------------------------------------------------------- */

enum proxy_preference_e {
	CLIENT_PREFER_NONE = 0,
	CLIENT_RUN_ALL,
	CLIENT_PREFER_SLAVE,
	CLIENT_PREFER_MASTER,
	CLIENT_SPECIFIED
};

extern gchar *ns_name;

/* The ugliest quirk on the world, because there is a fundamental flaw in the
 * LB algorithm that fails to compares distances we duplicate the set of rawx
 * used by the meta2 logic */
extern struct oio_lb_world_s *lb_world_rawx;
extern struct oio_lb_s *lb_rawx;

extern struct oio_lb_world_s *lb_world;
extern struct oio_lb_s *lb;

extern struct hc_resolver_s *resolver;
extern struct shard_resolver_s *shard_resolver;
extern oio_location_t location_num;

/* Global NS info */
extern GRWLock nsinfo_rwlock;
extern gchar **srvtypes;
extern struct namespace_info_s nsinfo;
gboolean validate_namespace (const char * ns);
/**
 * Check that the service types are loaded
 * and check that the service type exists
 **/
GError * validate_srvtype(const char *srvtype);

/* Periodically loads the conscience's addresses from the local config
 * and keep this in cache. */
extern GRWLock csurl_rwlock;
extern gchar **csurl;
extern gsize csurl_count;
gchar ** proxy_get_cs_urlv (void);

/* Periodically loads lists of services from the conscience, and keep this
 * in cache. */
extern GRWLock wanted_rwlock;
extern gchar **wanted_srvtypes;
extern GBytes **wanted_prepared; /* formatted as <srvtype>+'\0'+<json> */
void service_remember_wanted (const char *type);
GBytes* service_is_wanted (const char *type); /* refcount++ */
GBytes** NOLOCK_service_lookup_wanted (const char *type); /* refcount iso */

/* Upstream of services registrations. */
extern GRWLock push_rwlock;
extern struct lru_tree_s *push_queue;

extern GRWLock reg_rwlock;
extern struct lru_tree_s *srv_registered; /* registered srv seen within 5s */

extern GRWLock srv_rwlock;
extern struct lru_tree_s *srv_down; /* "IP:PORT" that had a problem */
extern struct lru_tree_s *srv_known; /* services seen since 'ever' */

gboolean service_is_ok (gconstpointer p);
void service_invalidate (gconstpointer n);

void service_learn (const char *key);
gboolean service_is_known (const char *key);

/* Set of items requiring an election, associated to the latest known master */
extern GRWLock master_rwlock;
extern struct lru_tree_s *srv_master;

enum cache_control_e
{
// 	// Meta0
// 	META0_NO_CACHE           = 0x0001,
// 	META0_NO_STORE           = 0x0002,
// #define META0_CACHE_CONTROL    0x000F

// 	// Meta1
// 	META1_NO_CACHE           = 0x0010,
// 	META1_NO_STORE           = 0x0020,
// #define META1_CACHE_CONTROL    0x00F0

// 	// Meta2
// 	META2_NO_CACHE           = 0x0100,
// 	META2_NO_STORE           = 0x0200,
// #define META2_CACHE_CONTROL    0x0F00

	// Sharding
	SHARDING_NO_CACHE        = 0x1000,
	SHARDING_NO_STORE        = 0x2000,
#define SHARDING_CACHE_CONTROL 0xF000
};

struct req_args_s
{
	struct oio_requri_s *req_uri; // parsed URI
	struct path_matching_s **matchings; // matched handlers
	struct oio_url_s *url;
	enum cache_control_e cache_control;

	struct http_request_s *rq;
	struct http_reply_ctx_s *rp;

	gint64 version;
	struct network_server_s *server;

	/// Saved before any sharding redirect, for further logging purposes.

	// Parent bucket in cases of sharded containers (when URL is set to the end-container reference)
	gchar *top_bucket;

	// Parent account in cases of sharded containers (when ACCOUNT is set to the technical value for sharding purposes)
	gchar *top_account;

	// Maybe the gateway announces a top-parent operation, that helps to correlate local proxy ops with global
	// content_create ops
	gchar *top_operation;
};

typedef enum http_rc_e (*req_handler_f) (struct req_args_s *);

const char * _req_get_option (struct req_args_s *args, const char *name);
const char * _req_get_token (struct req_args_s *args, const char *name);

enum http_rc_e rest_action (struct req_args_s *args,
		enum http_rc_e (*handler) (struct req_args_s *, json_object *));

gboolean _request_get_flag(struct req_args_s *args, const char *flag);

// Collect End-User information for further logging puposes
void _request_populate_enduser(struct req_args_s *args);

// Append End-User information to the access log
void _request_log_enduser(struct req_args_s *args);

/* -------------------------------------------------------------------------- */

struct client_ctx_s {
	/* Allows overriding the default that will populate the urlv/bodyv/errorv
	 * at the end of the structure */
	client_on_reply decoder;
	gpointer decoder_data;

	/* input */
	struct sqlx_name_inline_s name;
	struct oio_url_s *url;
	const char *type;
	gint64 seq;
	enum proxy_preference_e which;
	gboolean multi_run;

	/* output */
	guint count;
	gchar **urlv;
	GError **errorv;
	GByteArray **bodyv;

	/* performance */
	gint64 resolve_duration;
	gint64 request_duration;
};

/** Sleep for the specified delay, unless:
 * - the program is stopping,
 * - the thread-local deadline is reached. */
void sleep_at_most(gint64 delay);

void sort_services(struct client_ctx_s *ctx, gchar **m1uv);

/**
 * Flushes  the resolver cache (all levels) and the cache of known MASTER
 */
void cache_flush_user(struct req_args_s *args, struct client_ctx_s *ctx);

void client_init(struct client_ctx_s *ctx, struct req_args_s *args,
		const char *srvtype, gint64 seq, const char *suffix,
		enum proxy_preference_e how, client_on_reply decoder, gpointer out);

void client_clean (struct client_ctx_s *ctx);

/**
 * Tells which kind of peer to prefer when a SLAVE is enough.
 * So that we can force the requests to the master, for consistency purposes, or
 * ignore the advice depending on the options to the oio-proxy.
 */
enum proxy_preference_e _prefer_slave(void);

/**
 * Tells which kind of peer to prefer when a MASTER is to be preferred.
 * So that we can force the requests to a SLAVE (for testing purposes), ignore
 * the advice if configured so, or tell the sdk to target the master it knows.
 */
enum proxy_preference_e _prefer_master (void);

#define CLIENT_CTX(ctx,args,type,seq)  \
	struct client_ctx_s ctx = {0}; \
	client_init(&ctx, args, type, seq, NULL, CLIENT_PREFER_NONE, NULL, NULL)

#define CLIENT_CTX2(ctx,args,type,seq,suffix,how,decoder,out)  \
	struct client_ctx_s ctx = {0}; \
	client_init(&ctx, args, type, seq, suffix, how, decoder, out)

GError * _m1_locate_and_action(struct req_args_s *args,
		GError * (*hook) (const char *m1addr));

typedef GByteArray * (request_packer_f) (const struct sqlx_name_s *,
		const gchar **headers);

#define PACKER_VOID(N) GByteArray * N (const struct sqlx_name_s *_u UNUSED, \
		const gchar **headers UNUSED)

GError * gridd_request_replicated_with_retry (struct req_args_s *args,
		struct client_ctx_s *ctx, request_packer_f pack);

GError * KV_read_properties (struct json_object *j, gchar ***out,
		const char *section, gboolean fail_if_empty);

/** Wraps KV_read_properties() to concat system's properties and user's ones
 * with the proper prefix.
 * @see KV_read_properties() */
GError * KV_read_usersys_properties (struct json_object *j, gchar ***out);

/** Trigger a whole reload of the internal LB caches, exactly as it is done
 * by the periodically scheduled internal task */
gboolean lb_cache_reload(void);

/* -------------------------------------------------------------------------- */

enum http_rc_e _reply_json (struct req_args_s *args, int code, const char * msg, GString * gstr);

enum http_rc_e _reply_format_error (struct req_args_s *args, GError *err);
enum http_rc_e _reply_bad_gateway (struct req_args_s *args, GError *err);
enum http_rc_e _reply_srv_unavailable (struct req_args_s *args, GError *err);
enum http_rc_e _reply_retry (struct req_args_s *args, GError *err);
enum http_rc_e _reply_gateway_timeout (struct req_args_s *args, GError * err);
enum http_rc_e _reply_notfound_error (struct req_args_s *args, GError * err);
enum http_rc_e _reply_forbidden_error (struct req_args_s *args, GError * err);
enum http_rc_e _reply_method_error (struct req_args_s *args, GError *err, gchar *allowed);
enum http_rc_e _reply_conflict_error (struct req_args_s *args, GError * err);
enum http_rc_e _reply_gone_error(struct req_args_s *args, GError *err);
enum http_rc_e _reply_too_large (struct req_args_s *args, GError * err);
enum http_rc_e _reply_nocontent (struct req_args_s *args);
enum http_rc_e _reply_accepted (struct req_args_s *args);
enum http_rc_e _reply_created (struct req_args_s *args);

enum http_rc_e _reply_success_bytes (struct req_args_s *args,
		const gchar *content_type, GBytes * bytes);
enum http_rc_e _reply_success_json (struct req_args_s *args, GString * gstr);

void _append_status (GString *out, gint code, const char * msg);
GString * _create_status (gint code, const char * msg);
GString * _create_status_error (GError * e);

enum http_rc_e _reply_common_error (struct req_args_s *args, GError *err);

/* -------------------------------------------------------------------------- */

GError * conscience_remote_get_namespace(struct req_args_s *args, gchar **cs,
		namespace_info_t **out,
		gint64 deadline);

GError * conscience_remote_get_services(struct req_args_s *args, gchar **cs,
		const char *type, gboolean full, GSList **out,
		gint64 deadline);

GError * conscience_remote_get_types(struct req_args_s *args, gchar **cs,
		gchar ***out,
		gint64 deadline);

GError * conscience_remote_push_services(struct req_args_s *args, gchar **cs,
		GSList *ls,
		gint64 deadline);

GError* conscience_remote_remove_services(struct req_args_s *args, gchar **cs,
		const char *type, GSList *ls,
		gint64 deadline);

/* retrieve addr of a Service Id service, use cache only */
GError * conscience_resolve_service_id(gchar **cs, const char *type, const char *service_id, gchar **out, gchar **internal_addr);

static inline gint64 DL(void) {
	return oio_clamp_deadline(proxy_timeout_common, oio_ext_get_deadline());
}

/* ------------------------------------------------------------------------- */

/* Execute the request without avoidance, and discard the output */
#define CLIENT_EXEC(Url,Timeout,Req) \
	gridd_client_exec_and_concat_string(Url,Timeout,Req,NULL)

/* wraps gridd_client_exec_and_concat() but disable the avoidance of peers
 * seen faulty or down. */
GError * gridd_client_exec_and_concat_string (const char *to, gdouble timeout,
		GByteArray *req, gchar **out);

GError* proxy_locate_meta0(const char *ns, gchar ***result, gint64 dl);

#endif /*OIO_SDS__proxy__common_h*/
