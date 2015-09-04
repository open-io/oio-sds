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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>

#include <glib.h>
#include <json-c/json.h>

#include <core/url_ext.h>
#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>
#include <cluster/remote/gridcluster_remote.h>
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

#define BADREQ(M,...) NEWERROR(CODE_BAD_REQUEST,M,##__VA_ARGS__)

#define OPT(N)    _req_get_option(args,(N))
#define TOK(N)    _req_get_token(args,(N))
#define CID()     (TOK("CID") ?: OPT("cid"))
#define NS()      TOK("NS")
#define ACCOUNT() (TOK("ACCOUNT") ?: OPT("acct"))
#define POOL()    (TOK("POOL") ?: OPT("pool"))
#define TYPE()    (TOK("TYPE") ?: OPT("type"))
#define REF()     (TOK("REF") ?: OPT("ref"))
#define PATH()    (TOK("PATH") ?: OPT("path"))
#define SEQ()     (TOK("SEQ") ?: OPT("seq"))
#define VERSION() OPT("version")

#define PUSH_DO(Action) do { \
	g_mutex_lock(&push_mutex); \
	Action ; \
	g_mutex_unlock(&push_mutex); \
} while (0)

#define NSINFO_DO(Action) do { \
	g_mutex_lock(&nsinfo_mutex); \
	Action ; \
	g_mutex_unlock(&nsinfo_mutex); \
} while (0)


extern struct grid_lbpool_s *lbpool;
extern GMutex push_mutex;
extern struct lru_tree_s *push_queue;
extern gchar *nsname;
extern struct namespace_info_s nsinfo;
extern gchar **srvtypes;
extern GMutex nsinfo_mutex;
extern gdouble m2_timeout_all;
extern struct hc_resolver_s *resolver;

enum
{
	FLAG_NOEMPTY = 0x0001,
};

struct req_args_s
{
	struct oio_requri_s *req_uri; // parsed URI
	struct path_matching_s **matchings; // matched handlers
	struct hc_url_s *url;

	struct http_request_s *rq;
	struct http_reply_ctx_s *rp;

	guint32 flags;
};

typedef enum http_rc_e (*req_handler_f) (struct req_args_s *);

gboolean
validate_namespace (const gchar * ns);

gboolean
validate_srvtype (const gchar * n);

const gchar *
_req_get_option (struct req_args_s *args, const gchar *name);

const gchar *
_req_get_token (struct req_args_s *args, const gchar *name);

struct sub_action_s {
	const gchar *verb;
	enum http_rc_e (*handler) (struct req_args_s *, struct json_object *);
};

enum http_rc_e
abstract_action (const char *tag, struct req_args_s*args, struct sub_action_s *sub);

enum http_rc_e
rest_action (struct req_args_s *args,
        enum http_rc_e (*handler) (struct req_args_s *, json_object *));

GError *
_resolve_service_and_do (const char *t, gint64 seq, struct hc_url_s *u,
        GError * (*hook) (struct meta1_service_url_s *m1u, gboolean *next));

GError *
_m1_locate_and_action (struct req_args_s *args, GError * (*hook) ());

GError *
_gba_request (struct meta1_service_url_s *m1u, GByteArray * (reqbuilder) (void),
        GByteArray ** out);

GError *
_gbav_request (const gchar *t, gint64 seq, struct hc_url_s *u, GByteArray * builder (void),
        gchar ***outurl, GByteArray ***out);

gboolean
_request_has_flag (struct req_args_s *args, const char *header, const char *flag);

enum http_rc_e
_reply_json (struct req_args_s *args, int code, const gchar * msg, GString * gstr);

enum http_rc_e
_reply_format_error (struct req_args_s *args, GError *err);

enum http_rc_e
_reply_system_error (struct req_args_s *args, GError *err);

enum http_rc_e
_reply_bad_gateway (struct req_args_s *args, GError *err);

enum http_rc_e
_reply_not_implemented (struct req_args_s *args);

enum http_rc_e
_reply_notfound_error (struct req_args_s *args, GError * err);

enum http_rc_e
_reply_forbidden_error (struct req_args_s *args, GError * err);

enum http_rc_e
_reply_method_error (struct req_args_s *args);

enum http_rc_e
_reply_conflict_error (struct req_args_s *args, GError * err);

enum http_rc_e
_reply_nocontent (struct req_args_s *args);

enum http_rc_e
_reply_accepted (struct req_args_s *args);

enum http_rc_e
_reply_created (struct req_args_s *args);

enum http_rc_e
_reply_success_json (struct req_args_s *args, GString * gstr);

GString *
_create_status (gint code, const gchar * msg);

GString *
_create_status_error (GError * e);

enum http_rc_e
_reply_common_error (struct req_args_s *args, GError *err);

#endif /*OIO_SDS__proxy__common_h*/
