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

#define GUARDED_DO(Lock,Action) do { \
	g_mutex_lock(&Lock); \
	do { Action ; } while (0); \
	g_mutex_unlock(&Lock); \
} while (0)

#define CSURL_DO(Action) GUARDED_DO(csurl_mutex,Action)
#define PUSH_DO(Action) GUARDED_DO(push_mutex,Action)
#define NSINFO_DO(Action) GUARDED_DO(nsinfo_mutex,Action)
#define SRV_DO(Action) GUARDED_DO(srv_mutex,Action)

#define CSURL(C) gchar *C = NULL; do { \
	C = proxy_get_csurl(); \
	STRING_STACKIFY(C); \
} while (0)

extern gchar *nsname;
extern gboolean flag_cache_enabled;
extern gdouble m2_timeout_all;
extern time_t nsinfo_refresh_delay;

/* how long the proxy remembers the srv it registered ino the conscience */
extern time_t cs_expire_local_services;

extern struct grid_lbpool_s *lbpool;
extern struct hc_resolver_s *resolver;

extern GMutex csurl_mutex;
extern gchar *csurl;

extern GMutex push_mutex;
/* staging area for services being sent up. <struct service_info_s*> */
extern struct lru_tree_s *push_queue;
/* holder for services registered within the last 5 seconds */
extern struct lru_tree_s *srv_registered;

extern GMutex nsinfo_mutex;
extern gchar **srvtypes;
extern struct namespace_info_s nsinfo;

extern GMutex srv_mutex;
extern struct lru_tree_s *srv_down;

enum
{
	/* consider empty results sets as errors */
	FLAG_NOEMPTY = 0x0001,
};

struct req_args_s
{
	struct oio_requri_s *req_uri; // parsed URI
	struct path_matching_s **matchings; // matched handlers
	struct oio_url_s *url;

	struct http_request_s *rq;
	struct http_reply_ctx_s *rp;

	guint32 flags;
};

struct sub_action_s {
	const char *verb;
	enum http_rc_e (*handler) (struct req_args_s *, struct json_object *);
};

typedef enum http_rc_e (*req_handler_f) (struct req_args_s *);

gchar * proxy_get_csurl (void);

gboolean validate_namespace (const char * ns);
gboolean validate_srvtype (const char * n);

gboolean service_is_ok (gconstpointer p);
void service_invalidate (gconstpointer n);

const char * _req_get_option (struct req_args_s *args, const char *name);
const char * _req_get_token (struct req_args_s *args, const char *name);

enum http_rc_e abstract_action (const char *tag, struct req_args_s*args, struct sub_action_s *sub);

enum http_rc_e rest_action (struct req_args_s *args,
        enum http_rc_e (*handler) (struct req_args_s *, json_object *));

GError * _resolve_service_and_do (const char *t, gint64 seq, struct oio_url_s *u,
        GError * (*hook) (struct meta1_service_url_s *m1u, gboolean *next));

GError * _m1_locate_and_action (struct oio_url_s *url, GError * (*hook) ());

GError * _gba_request (struct meta1_service_url_s *m1u, GByteArray * (reqbuilder) (void),
        GByteArray ** out);

GError * _gbav_request (const char *t, gint64 seq, struct oio_url_s *u, GByteArray * builder (void),
        gchar ***outurl, GByteArray ***out);

gboolean _request_has_flag (struct req_args_s *args, const char *header, const char *flag);

enum http_rc_e _reply_json (struct req_args_s *args, int code, const char * msg, GString * gstr);
enum http_rc_e _reply_format_error (struct req_args_s *args, GError *err);
enum http_rc_e _reply_system_error (struct req_args_s *args, GError *err);
enum http_rc_e _reply_bad_gateway (struct req_args_s *args, GError *err);
enum http_rc_e _reply_not_implemented (struct req_args_s *args);
enum http_rc_e _reply_notfound_error (struct req_args_s *args, GError * err);
enum http_rc_e _reply_forbidden_error (struct req_args_s *args, GError * err);
enum http_rc_e _reply_method_error (struct req_args_s *args);
enum http_rc_e _reply_conflict_error (struct req_args_s *args, GError * err);
enum http_rc_e _reply_nocontent (struct req_args_s *args);
enum http_rc_e _reply_accepted (struct req_args_s *args);
enum http_rc_e _reply_created (struct req_args_s *args);
enum http_rc_e _reply_success_json (struct req_args_s *args, GString * gstr);

GString * _create_status (gint code, const char * msg);
GString * _create_status_error (GError * e);

enum http_rc_e
_reply_common_error (struct req_args_s *args, GError *err);

#endif /*OIO_SDS__proxy__common_h*/
