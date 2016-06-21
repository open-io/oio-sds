/*
OpenIO SDS proxy
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

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

#include "common.h"

const char *
_pref2str(enum preference_e p)
{
	switch (p) {
		ON_ENUM(CLIENT_,ANY);
		ON_ENUM(CLIENT_,RUN_ALL);
		ON_ENUM(CLIENT_,PREFER_SLAVE);
		ON_ENUM(CLIENT_,PREFER_MASTER);
	}
	g_assert_not_reached ();
	return "?";
}

gchar *
proxy_get_csurl (void)
{
	g_rw_lock_reader_lock (&csurl_rwlock);
	const guint i = oio_ext_rand_int_range(0, csurl_count);
	gchar *cs = g_strdup(csurl[i]);
	g_rw_lock_reader_unlock (&csurl_rwlock);
	return cs;
}

gboolean
validate_namespace (const char * ns)
{
	return 0 == strcmp (ns, ns_name);
}

gboolean
validate_srvtype (const char * n)
{
	gboolean rc = FALSE;
	NSINFO_READ(if (srvtypes) {
		for (gchar ** p = srvtypes; !rc && *p; ++p)
			rc = !strcmp (*p, n);
	});
	return rc;
}

gboolean
service_is_ok (gconstpointer k)
{
	gpointer v;
	SRV_READ(v = lru_tree_get (srv_down, k));
	return v == NULL;
}

void
service_invalidate (gconstpointer k)
{
	gchar *k0 = g_strdup((const char *)k);
	SRV_WRITE(lru_tree_insert (srv_down, k0, GINT_TO_POINTER(1)));
	if (GRID_DEBUG_ENABLED())
		GRID_DEBUG("invalid at %lu %s", oio_ext_monotonic_seconds(), (const char*)k);
}

gboolean
service_is_slave (const char *obj, const char *master)
{
	gboolean rc;
	MASTER_READ(
		gchar *v = lru_tree_get(srv_master, obj);
		rc = (v != NULL) && strcmp(v, master));
	return rc;
}

gboolean
service_is_master (const char *obj, const char *master)
{
	gboolean rc;
	MASTER_READ(
		gchar *v = lru_tree_get(srv_master, obj);
		rc = (v != NULL) && !strcmp(v, master));
	return rc;
}

void
service_learn_master (const char *obj, const char *master)
{
	gchar *k = g_strdup (obj), *v = g_strdup (master);
	MASTER_WRITE(lru_tree_insert(srv_master, k, v));
}

guint
service_expire_masters (gint64 oldest)
{
	guint count = 0;
	MASTER_WRITE(count = lru_tree_remove_older (srv_master, oldest));
	return count;
}

const char *
_req_get_option (struct req_args_s *args, const char *name)
{
	gsize namelen = strlen(name);
	gchar *needle = g_alloca(namelen+2);
	memcpy(needle, name, namelen);
	needle[namelen] = '=';
	needle[namelen+1] = 0;

	if (args->req_uri->query_tokens) {
		for (gchar **p=args->req_uri->query_tokens; *p ;++p) {
			if (g_str_has_prefix(*p, needle))
				return (*p) + namelen + 1;
		}
	}
	return NULL;
}

const char *
_req_get_token (struct req_args_s *args, const char *name)
{
	return path_matching_get_variable (args->matchings[0], name);
}

enum http_rc_e
abstract_action (const char *tag, struct req_args_s *args, struct sub_action_s *sub)
{
	enum http_rc_e rc;
	json_tokener *parser = json_tokener_new ();
	json_object *jbody = NULL;

	if (args->rq->body->len)
		jbody = json_tokener_parse_ex (parser,
				(char *) args->rq->body->data, args->rq->body->len);

	if (json_tokener_success != json_tokener_get_error (parser))
		rc = _reply_format_error (args, BADREQ ("Invalid JSON"));
	else if (!json_object_is_type (jbody, json_type_object))
		rc = _reply_format_error (args, BADREQ ("Invalid JSON object (%s)", tag));
	else {
		json_object *jargs = NULL, *jaction = NULL;
		if (!json_object_object_get_ex (jbody, "action", &jaction)
				|| !json_object_is_type (jaction, json_type_string))
			rc = _reply_forbidden_error (args, BADREQ ("No/Bad action (%s)", tag));
		else if (!json_object_object_get_ex (jbody, "args", &jargs))
			rc = _reply_forbidden_error (args, BADREQ ("No/Bad arguments (%s)", tag));
		else {
			const char *action = json_object_get_string (jaction);
			args->rp->access_tail ("action=%s", action);
			for (; sub->handler ;++sub) {
				if (!strcmp(action, sub->verb)) {
					rc = sub->handler(args, jargs);
					goto exit;
				}
			}
			rc = _reply_forbidden_error (args, BADREQ ("Unexpected action (%s)", tag));
		}
	}
exit:
	if (jbody)
		json_object_put (jbody);
	json_tokener_free (parser);
	return rc;
}

enum http_rc_e
rest_action (struct req_args_s *args,
		enum http_rc_e (*handler) (struct req_args_s *, json_object *))
{
	enum http_rc_e rc;
	json_tokener *parser = json_tokener_new ();
	json_object *jbody = NULL;

	if (args->rq->body->len)
		jbody = json_tokener_parse_ex (parser,
				(char *) args->rq->body->data, args->rq->body->len);

	if (json_tokener_success != json_tokener_get_error (parser))
		rc = _reply_format_error (args, BADREQ("Invalid JSON"));
	else
		rc = handler(args, jbody);

	if (jbody)
		json_object_put (jbody);
	json_tokener_free (parser);
	return rc;
}

/* -------------------------------------------------------------------------- */

#ifdef HAVE_EXTRA_DEBUG
static void
_debug_services (const char *tag, gchar **m1uv)
{
	if (!GRID_TRACE_ENABLED()) return;
	gchar *tmp = g_strjoinv(",", m1uv);
	GRID_TRACE("%s%s", tag, tmp);
	g_free (tmp);
}
#else
# define _debug_services(...)
#endif

static void
_sort_services (struct client_ctx_s *ctx, const char *k, gchar **m1uv)
{
	GRID_TRACE("Sorting for %s", _pref2str(ctx->which));
	_debug_services ("PRE sort: ", m1uv);

	gsize pivot = g_strv_length (m1uv);

	if (pivot) /* prefer services recently available */
		pivot = oio_ext_array_partition ((void**)m1uv, pivot, service_is_ok);

	if (pivot && ctx->which != CLIENT_RUN_ALL) {
		/* among available services, prefer those expected SLAVE/MASTER */
		gboolean _master (gconstpointer p) {
			return service_is_master (k, p);
		}
		gboolean _slave (gconstpointer p) {
			return service_is_slave (k, p);
		}
		switch (ctx->which) {
			case CLIENT_PREFER_SLAVE:
				pivot = oio_ext_array_partition ((void**)m1uv, pivot, _slave);
				break;
			case CLIENT_PREFER_MASTER:
				pivot = oio_ext_array_partition ((void**)m1uv, pivot, _master);
				break;
			default:
				break;
		}
		if (pivot)
			oio_ext_array_shuffle ((void**)m1uv, pivot);
	}
	_debug_services ("POST sort: ", m1uv);
}

static gboolean
_on_reply (gpointer p, MESSAGE reply)
{
	GByteArray **pbody = p, *b = NULL;
	EXTRA_ASSERT (pbody != NULL);
	GError *e = metautils_message_extract_body_gba (reply, &b);
	if (e)
		g_clear_error (&e);
	else {
		if (*pbody) g_byte_array_unref (*pbody);
		*pbody = b;
	}
	return TRUE;
}

GError *
gridd_request_replicated (struct client_ctx_s *ctx, request_packer_f pack)
{
	GError *err = NULL;
	g_assert (ctx != NULL);

	gchar *election_key = g_strconcat (ctx->name.base, "/", ctx->name.type, NULL);
	STRING_STACKIFY(election_key);

	/* Locate the services */
	gchar **m1uv = NULL;
	if (*ctx->type == '#')
		err = hc_resolve_reference_directory (resolver, ctx->url, &m1uv);
	else
		err = hc_resolve_reference_service (resolver, ctx->url, ctx->type, &m1uv);

	if (err) {
		EXTRA_ASSERT(m1uv == NULL);
		g_prefix_error (&err, "Directory error: ");
		return err;
	} else {
		EXTRA_ASSERT(m1uv != NULL);
		if (!*m1uv) {
			g_strfreev (m1uv);
			return NEWERROR (CODE_CONTAINER_NOTFOUND, "No service located");
		}
		meta1_urlv_shift_addr (m1uv);
		_sort_services (ctx, election_key, m1uv);
	}

	/* Perform the sequence of requests. */
	GPtrArray
		*urlv = g_ptr_array_new (), /* <gchar*> */
		*errorv = g_ptr_array_new (), /* <GError*> */
		*bodyv = g_ptr_array_new (); /* <GByteArray*> */

	GByteArray *packed = pack(sqlx_name_mutable_to_const(&ctx->name));

	gboolean stop = FALSE;
	for (gchar **pu=m1uv; *pu && !stop ;++pu) {

		/* TODO ensure the service match the expected TYPE and SEQ */

		/* Send a unitary request now */
		GByteArray *body = NULL;

		struct gridd_client_s *client = NULL;

		if (!ctx->decoder) {
			client = gridd_client_create (*pu, packed, &body, _on_reply);
		} else {
			client = gridd_client_create (*pu, packed, ctx->decoder_data, ctx->decoder);
		}

		g_ptr_array_add (urlv, g_strdup(*pu));

		gridd_client_start (client);
		gridd_client_set_timeout (client, ctx->timeout);
		if (!(err = gridd_client_loop (client)))
			err = gridd_client_error (client);

		g_ptr_array_add (bodyv, body);

		if (err) {
			g_ptr_array_add (errorv, g_error_copy(err));
		} else {
			g_ptr_array_add (errorv, NEWERROR(CODE_FINAL_OK, "OK"));
		}

		/* Check for a possible redirection */
		const char *actual = gridd_client_url (client);
		if (actual && 0 != strcmp(actual, *pu)) {
			gchar *k = g_strdup(election_key);
			gchar *v = g_strdup (actual);
			GRID_DEBUG("MASTER %s %s", v, k);
			MASTER_WRITE(lru_tree_insert (srv_master, k, v));
		}

		if (err && CODE_IS_NETWORK_ERROR(err->code)) {
			service_invalidate(*pu);
			g_clear_error (&err);
		}

		if (err) {
			if (ctx->which == CLIENT_RUN_ALL) {
				g_clear_error (&err);
				err = NULL;
			} else {
				stop = TRUE;
			}
		} else {
			if (ctx->which != CLIENT_RUN_ALL)
				stop = TRUE;
		}

		gridd_client_free (client);
		client = NULL;
	}

	g_byte_array_unref (packed);
	g_strfreev (m1uv);

	ctx->count = urlv->len;
	g_ptr_array_add (urlv, NULL);
	g_ptr_array_add (bodyv, NULL);
	g_ptr_array_add (errorv, NULL);
	ctx->urlv = (gchar**) g_ptr_array_free (urlv, FALSE);
	ctx->bodyv = (GByteArray**) g_ptr_array_free (bodyv, FALSE);
	ctx->errorv = (GError**) g_ptr_array_free (errorv, FALSE);

	return err;
}

/* -------------------------------------------------------------------------- */

static gboolean
_has_flag_in_headers (struct req_args_s *args, const char *header,
		const char *flag)
{
	const char *v = g_tree_lookup(args->rq->tree_headers, header);
	if (!v)	return FALSE;

	gchar **tokens = g_strsplit (v, ",", -1);
	if (!tokens) return FALSE;

	gboolean rc = FALSE;
	for (gchar **p=tokens; *p ;++p) {
		*p = g_strstrip (*p);
		if (!g_ascii_strcasecmp(flag, *p)) {
			rc = TRUE;
			break;
		}
	}
	g_strfreev (tokens);
	return rc;
}

gboolean
_request_get_flag (struct req_args_s *args, const char *flag)
{
	const gchar *v = OPT(flag);
	if (NULL != v)
		return metautils_cfg_get_bool(v, FALSE);
	return _has_flag_in_headers (args, PROXYD_HEADER_MODE, flag);
}

void
service_learn (const char *key)
{
	gchar *k = g_strdup(key);
	SRV_WRITE(lru_tree_insert(srv_known, k, GINT_TO_POINTER(1)));
}

gboolean
service_is_known (const char *key)
{
	gboolean known = FALSE;
	SRV_READ(known = (NULL != lru_tree_get (srv_known, key)));
	return known;
}

GBytes **
NOLOCK_service_lookup_wanted (const char *type)
{
	if (!wanted_prepared)
		return NULL;
	for (GBytes **pw=wanted_prepared ; *pw ; pw++) {
		if (!strcmp (type, (const char*)g_bytes_get_data(*pw,NULL)))
			return pw;
	}
	return NULL;
}

void
service_remember_wanted (const char *type)
{
	gsize i;
	WANTED_WRITE(
	if (!wanted_srvtypes) {
		wanted_srvtypes = g_malloc0 (8 * sizeof(void*));
		wanted_srvtypes[0] = g_strdup (type);
	} else {
		for (i=0; wanted_srvtypes[i] ;++i) {
			if (!strcmp(type, wanted_srvtypes[i]))
				break;
		}
		if (NULL == wanted_srvtypes[i]) {
			wanted_srvtypes = g_realloc (wanted_srvtypes, sizeof(gchar*) * (i+2));
			wanted_srvtypes[i] = g_strdup (type);
			wanted_srvtypes[i+1] = NULL;
		}
	});
}

GBytes*
service_is_wanted (const char *type)
{
	GBytes *out = NULL;
	WANTED_READ(do {
		GBytes **pold = NOLOCK_service_lookup_wanted (type);
		if (pold)
			out = g_bytes_ref (*pold);
	} while (0));
	return out;
}

void
client_init (struct client_ctx_s *ctx, struct req_args_s *args,
	   const char *srvtype, gint seq)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->url = args->url;
	ctx->type = srvtype;
	ctx->seq = seq;
	sqlx_name_fill_type_asis (&ctx->name, args->url, srvtype, ctx->seq);
	ctx->timeout = COMMON_CLIENT_TIMEOUT;
	ctx->which = CLIENT_ANY;
}

void
client_clean (struct client_ctx_s *ctx)
{
	sqlx_name_clean(&ctx->name);
	if (ctx->urlv)
		g_strfreev (ctx->urlv);
	if (ctx->errorv) {
		for (GError **pe=ctx->errorv; *pe ;pe++)
			g_clear_error(pe);
		g_free (ctx->errorv);
	}
	if (ctx->bodyv)
		metautils_gba_cleanv (ctx->bodyv);
	memset (ctx, 0, sizeof(*ctx));
}
