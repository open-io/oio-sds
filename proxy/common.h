/*
OpenIO SDS proxy
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

#include <core/url_ext.h>
#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>
#include <server/network_server.h>
#include <server/stats_holder.h>
#include <resolver/hc_resolver.h>
#include <meta1v2/meta1_remote.h>
#include <meta2v2/meta2_macros.h>
#include <meta2v2/meta2v2_remote.h>
#include <meta2v2/meta2_utils.h>
#include <meta2v2/autogen.h>
#include <meta2v2/generic.h>
#include <sqliterepo/sqlx_remote.h>
#include <sqliterepo/sqlite_utils.h>

#include "path_parser.h"
#include "transport_http.h"

#define TOK(N)    _req_get_token(args,(N))
#define NS()      TOK("NS")

#define OPT(N)    _req_get_option(args,(N))
#define CID()     OPT("cid")
#define ACCOUNT() OPT("acct")
#define POOL()    OPT("pool")
#define CONTENT() OPT("content")
#define TYPE()    OPT("type")
#define REF()     OPT("ref")
#define PATH()    OPT("path")
#define SEQ()     OPT("seq")
#define VERSION() OPT("version")

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

#define CSURL(C) gchar *C = NULL; do { \
	C = proxy_get_csurl(); \
	STRING_STACKIFY(C); \
} while (0)

#define COMA(gs,first) do { \
	if (!first) \
		g_string_append_c (gs, ','); \
	else \
		first = FALSE; \
} while (0)

enum preference_e {
	CLIENT_ANY = 0,
	CLIENT_RUN_ALL,
	CLIENT_PREFER_SLAVE,
	CLIENT_PREFER_MASTER
};

const char * _pref2str(enum preference_e p);

extern gchar *nsname;
extern gboolean flag_cache_enabled;
extern gboolean flag_local_scores;

/* how long the proxy remembers the srv it registered ino the conscience */
extern gint64 ttl_expire_local_services;

/* how long the proxy remembers dead services */
extern gint64 ttl_down_services;

/* how long the proxy remembers services from the conscience */
extern gint64 ttl_known_services;

/* how long the proxy remembers which service is the master for a given
   election */
extern gint64 ttl_expire_master_services;

extern struct grid_lbpool_s *lbpool;
extern struct hc_resolver_s *resolver;

/* Global NS info */
extern GRWLock nsinfo_rwlock;
extern gchar **srvtypes;
extern struct namespace_info_s nsinfo;
extern gint64 ns_chunk_size;
gboolean validate_namespace (const char * ns);
gboolean validate_srvtype (const char * n);

/* Periodically loads the consciennce's addresses from the local config
   and keep this in cache. */
extern GRWLock csurl_rwlock;
extern gchar **csurl;
extern gsize csurl_count;
gchar * proxy_get_csurl (void);

/* Periodically loads lists of services from the conscience, and keep this
   in cache. */
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
gboolean service_is_ok (gconstpointer p);
void service_invalidate (gconstpointer n);
extern struct lru_tree_s *srv_known; /* services seen since 'ever' */
void service_learn (const char *key);
gboolean service_is_known (const char *key);

/* Set of items requiring an election, associated to the latest known master */
extern GRWLock master_rwlock;
extern struct lru_tree_s *srv_master;
gboolean service_is_slave (const char *obj, const char *master);
gboolean service_is_master (const char *obj, const char *master);
void service_learn_master (const char *obj, const char *master);
guint service_expire_masters (gint64 oldest);

enum
{
	/* consider empty results sets as errors */
	FLAG_NOEMPTY = 0x0001,
};

typedef GByteArray * (request_packer_f) (const struct sqlx_name_s *);

#define PACKER_VOID(N) GByteArray * N (const struct sqlx_name_s *u UNUSED)
#define PACKER(N)      GByteArray * N (const struct sqlx_name_s *n)

struct req_args_s
{
	struct oio_requri_s *req_uri; // parsed URI
	struct path_matching_s **matchings; // matched handlers
	struct oio_url_s *url;

	struct http_request_s *rq;
	struct http_reply_ctx_s *rp;
};

struct sub_action_s
{
	const char *verb;
	enum http_rc_e (*handler) (struct req_args_s *, struct json_object *);
};

typedef enum http_rc_e (*req_handler_f) (struct req_args_s *);

const char * _req_get_option (struct req_args_s *args, const char *name);
const char * _req_get_token (struct req_args_s *args, const char *name);

enum http_rc_e abstract_action (const char *tag, struct req_args_s *args,
		struct sub_action_s *sub);

enum http_rc_e rest_action (struct req_args_s *args,
        enum http_rc_e (*handler) (struct req_args_s *, json_object *));

/* -------------------------------------------------------------------------- */

struct client_ctx_s {
	/* Allows overriding the default that will populate the urlv/bodyv/errorv
	 * at the end of the structure */
	client_on_reply decoder;
	gpointer decoder_data;

	/* input */
	struct sqlx_name_mutable_s name;
	struct oio_url_s *url;
	const char *type;
	gint64 seq;
	enum preference_e which;
	gdouble timeout;

	/* output */
	guint count;
	gchar **urlv;
	GError **errorv;
	GByteArray **bodyv;

	GByteArray *single_body;
};

void client_init (struct client_ctx_s *ctx, struct req_args_s *args,
	   const char *srvtype, gint seq);

void client_clean (struct client_ctx_s *ctx);

#define CLIENT_CTX(ctx,args,type,seq) \
	struct client_ctx_s ctx = {0}; \
	client_init (&ctx, args, type, seq) \

#define CLIENT_CTX_MASTER(ctx,args,type,seq) \
	CLIENT_CTX(ctx,args,type,seq); \
	ctx.which = CLIENT_PREFER_MASTER

#define CLIENT_CTX_SLAVE(ctx,args,type,seq) \
	CLIENT_CTX(ctx,args,type,seq); \
	ctx.which = CLIENT_PREFER_SLAVE

GError * _m1_locate_and_action (struct oio_url_s *url, GError * (*hook) ());

GError * gridd_request_replicated (struct client_ctx_s *, request_packer_f);

gboolean _request_has_flag (struct req_args_s *args, const char *header, const char *flag);

/* -------------------------------------------------------------------------- */

enum http_rc_e _reply_bytes (struct req_args_s *args, int code, const char * msg, GBytes * bytes);
enum http_rc_e _reply_json (struct req_args_s *args, int code, const char * msg, GString * gstr);

enum http_rc_e _reply_format_error (struct req_args_s *args, GError *err);
enum http_rc_e _reply_system_error (struct req_args_s *args, GError *err);
enum http_rc_e _reply_bad_gateway (struct req_args_s *args, GError *err);
enum http_rc_e _reply_srv_unavailable (struct req_args_s *args, GError *err);
enum http_rc_e _reply_gateway_timeout (struct req_args_s *args, GError * err);
enum http_rc_e _reply_not_implemented (struct req_args_s *args);
enum http_rc_e _reply_notfound_error (struct req_args_s *args, GError * err);
enum http_rc_e _reply_forbidden_error (struct req_args_s *args, GError * err);
enum http_rc_e _reply_method_error (struct req_args_s *args);
enum http_rc_e _reply_conflict_error (struct req_args_s *args, GError * err);
enum http_rc_e _reply_nocontent (struct req_args_s *args);
enum http_rc_e _reply_accepted (struct req_args_s *args);
enum http_rc_e _reply_created (struct req_args_s *args);

enum http_rc_e _reply_success_bytes (struct req_args_s *args, GBytes * bytes);
enum http_rc_e _reply_success_json (struct req_args_s *args, GString * gstr);

void _append_status (GString *out, gint code, const char * msg);
GString * _create_status (gint code, const char * msg);
GString * _create_status_error (GError * e);

enum http_rc_e _reply_common_error (struct req_args_s *args, GError *err);

/* -------------------------------------------------------------------------- */

GError * conscience_remote_get_namespace (const char *cs, namespace_info_t **out);
GError * conscience_remote_get_services(const char *cs, const char *type,
		gboolean full, GSList **out);
GError * conscience_remote_get_types(const char *cs, GSList **out);
GError * conscience_remote_push_services(const char *cs, GSList *ls);
GError* conscience_remote_remove_services(const char *cs, const char *type,
		GSList *ls);

#endif /*OIO_SDS__proxy__common_h*/
