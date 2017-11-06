/*
OpenIO SDS proxy
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

gint32 oio_proxy_request_failure_threshold_alone = 0;
gint32 oio_proxy_request_failure_threshold_first = 100;
gint32 oio_proxy_request_failure_threshold_middle = 50;
gint32 oio_proxy_request_failure_threshold_last = 0;

gchar *
proxy_get_csurl (void)
{
	g_rw_lock_reader_lock (&csurl_rwlock);
	const gint32 i = oio_ext_rand_int_range(0, csurl_count % G_MAXINT32);
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
rest_action (struct req_args_s *args,
		enum http_rc_e (*handler) (struct req_args_s *, json_object *))
{
	json_object *jbody = NULL;
	GError *err = JSON_parse_gba(args->rq->body, &jbody);
	if (err) return _reply_format_error (args, err);
	enum http_rc_e rc = handler(args, jbody);
	json_object_put (jbody);
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

static void _sort_services (struct client_ctx_s *ctx,
		const char *k, gchar **m1uv) {
	_debug_services ("PRE sort: ", m1uv);

	gsize pivot = g_strv_length (m1uv);

	/* prefer services recently available */
	if (pivot > 1)
		pivot = oio_ext_array_partition ((void**)m1uv, pivot, service_is_ok);

	/* among the available services, prefer those expected SLAVE/MASTER */
	if (pivot > 1 && (ctx->which == CLIENT_PREFER_MASTER
			|| ctx->which == CLIENT_PREFER_SLAVE)) {
		gboolean _master (gconstpointer p) { return service_is_master (k, p); }
		gboolean _slave (gconstpointer p) { return service_is_slave (k, p); }
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
	}

	/* If multiple available & preferred services, shuffle them */
	if (pivot > 1 && oio_proxy_srv_shuffle)
		oio_ext_array_shuffle ((void**)m1uv, pivot);

	_debug_services ("POST sort: ", m1uv);
}

enum proxy_preference_e _prefer_slave(void) {
	if (flag_prefer_master_for_read)
		return CLIENT_PREFER_MASTER;
	if (flag_prefer_slave_for_read)
		return CLIENT_PREFER_SLAVE;
	return CLIENT_PREFER_NONE;
}

enum proxy_preference_e _prefer_master(void) {
	if (flag_prefer_master_for_write)
		return CLIENT_PREFER_MASTER;
	return CLIENT_PREFER_NONE;
}

static gboolean _on_reply (gpointer p, MESSAGE reply) {
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
	gboolean retry = TRUE;
	GError *err = NULL;
	gchar **m1uv = NULL;
	EXTRA_ASSERT (ctx != NULL);

	gchar *election_key = g_strconcat (ctx->name.base, "/", ctx->name.type, NULL);
	STRING_STACKIFY(election_key);

	const gint64 deadline = oio_ext_get_deadline();

	const gint64 req_start = oio_ext_monotonic_time();

	/* Locate the services */
label_retry:
	if (*ctx->type == '#')
		err = hc_resolve_reference_directory (resolver, ctx->url, &m1uv, deadline);
	else
		err = hc_resolve_reference_service (resolver, ctx->url, ctx->type, &m1uv, deadline);

	if (err) {
		EXTRA_ASSERT(m1uv == NULL);
		if (retry && err->code == CODE_RANGE_NOTFOUND) {
			retry = FALSE;
			hc_decache_reference_service(resolver, ctx->url, NAME_SRVTYPE_META1);
			hc_decache_reference(resolver, ctx->url);
			goto label_retry;
		} else {
			g_prefix_error(&err, "Directory error: ");
		}
	} else {
		EXTRA_ASSERT(m1uv != NULL);
		if (*ctx->type == '#') {
			/* when looking for a directory service, the resolver always replies
			 * all the services involved. Let's keep only the services with the
			 * targeted type */
			gchar **tmp = meta1_url_filter_typed (
					(const char * const *)m1uv, ctx->type+1);
			if (m1uv)
				g_strfreev(m1uv);
			m1uv = tmp;
			meta1_urlv_shift_addr(m1uv);
		} else if (!*m1uv) {
			g_strfreev (m1uv);
			err = NEWERROR(CODE_CONTAINER_NOTFOUND, "No service located");
		} else {
			/* We found some locations, let's keep only the URL part */
			meta1_urlv_shift_addr (m1uv);
			/* let's prefer the services requested (master, slave, etc) */
			_sort_services (ctx, election_key, m1uv);
		}
	}
	const gint64 resolve_end = oio_ext_monotonic_time();
	ctx->resolve_duration = resolve_end - req_start;
	if (err)
		return err;

	/* Perform the sequence of requests. */
	GPtrArray
		*urlv = g_ptr_array_new (), /* <gchar*> */
		*errorv = g_ptr_array_new (), /* <GError*> */
		*bodyv = g_ptr_array_new (); /* <GByteArray*> */

	NAME2CONST(n, ctx->name);
	GByteArray *packed = pack(&n);

	gboolean stop = FALSE;
	for (gchar **pu = m1uv; *pu && !stop; ++pu) {
		const char *url = pu[0];
		const char *next_url = pu[1];
		struct gridd_client_s *client = NULL;
		GByteArray *body = NULL;

		/* TODO ensure the service match the expected TYPE and SEQ */
		if (!ctx->decoder) {
			client = gridd_client_create (url, packed, &body, _on_reply);
		} else {
			client = gridd_client_create (url, packed, ctx->decoder_data, ctx->decoder);
		}

#ifdef HAVE_ENBUG
		gint32 threshold = 0;
		if (url == m1uv[0] && !next_url)
			threshold = oio_proxy_request_failure_threshold_alone;
		else if (url == m1uv[0])
			threshold = oio_proxy_request_failure_threshold_first;
		else if (next_url == NULL)
			threshold = oio_proxy_request_failure_threshold_last;
		else
			threshold = oio_proxy_request_failure_threshold_middle;
		if (threshold >= oio_ext_rand_int_range(1, 100)) {
			err = NEWERROR(CODE_AVOIDED, "FAKE ERROR");
		} else {
#endif /* HAVE_ENBUG */
			/* Send a unitary request */
			if (ctx->which == CLIENT_RUN_ALL)
				gridd_client_no_redirect (client);
			gridd_client_start (client);
			gridd_client_set_timeout (client,
					oio_clamp_timeout(proxy_timeout_common, deadline));
			if (!(err = gridd_client_loop (client)))
				err = gridd_client_error (client);
#ifdef HAVE_ENBUG
		}
#endif
		/* ensure an output for that request: each array (url, body, error)
		 * must contain the corresponding item. */
		if (err) {
			GRID_DEBUG("ERROR %s -> (%d) %s", url, err->code, err->message);
			g_ptr_array_add (errorv, g_error_copy(err));
			if (!body)
				body = g_byte_array_new();
			else
				g_byte_array_set_size(body, 0);
		} else {
			g_ptr_array_add (errorv, NEWERROR(CODE_FINAL_OK, "OK"));
			if (!body)
				body = g_byte_array_new();
		}
		g_ptr_array_add (bodyv, body);
		g_ptr_array_add (urlv, g_strdup(url));

		/* Check for a possible redirection */
		if (flag_prefer_master_for_read || flag_prefer_slave_for_read
				|| flag_prefer_master_for_write) {
			const char *actual = gridd_client_url(client);
			if (actual && 0 != strcmp(actual, url)) {
				gchar *k = g_strdup(election_key);
				gchar *v = g_strdup(actual);
				GRID_TRACE("MASTER %s %s", v, k);
				MASTER_WRITE(lru_tree_insert(srv_master, k, v));
			}
		}

		if (err) {
			if (CODE_IS_NETWORK_ERROR(err->code)) {
				/* the target service is in bad shape, let's avoid it for
				 * the subsequent requests. */
				service_invalidate(url);

				/* TODO(jfs): should we let the client retry or occupy a
				 * thread in the proxy to make all the necessary retries ? */

				/* that error is not strong enough to stop the iteration, we
				 * just try with another service */
				g_clear_error (&err);

				/* But if we expected at least one service to respond,
				 * and we still encounter that error with the last URL of the
				 * array (!pu[1]), then this is an overall error that we should return. */
				if (ctx->which != CLIENT_RUN_ALL && !next_url) {
					err = BUSY("No service replied");
					stop = TRUE;
				}
			} else if (CODE_IS_RETRY(err->code)) {
				/* the target service is in bad shape, let's avoid it for
				 * the subsequent requests. And we currently we choose to
				 * stop the iteration and let the retry be achieved in the
				 * client SDK. This error is a clue that the other replicas
				 * will also be overloaded. */
				service_invalidate(url);
				stop = TRUE;
			} else if (ctx->which == CLIENT_RUN_ALL) {
				/* All the services must be reached, let's just remind the
				 * error (already done) and continue to the next service */
				g_clear_error (&err);
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
	ctx->request_duration = oio_ext_monotonic_time() - resolve_end;

	EXTRA_ASSERT(urlv->len == bodyv->len);
	EXTRA_ASSERT(urlv->len == errorv->len);

	g_byte_array_unref (packed);
	g_strfreev (m1uv);

#define FinishArray(Out,Type,Var) do { \
	g_ptr_array_add (Var, NULL); \
	Out = (Type **) g_ptr_array_free (Var, FALSE); \
	Var = NULL; \
} while (0)

	ctx->count = urlv->len;
	FinishArray(ctx->urlv, gchar, urlv);
	FinishArray(ctx->bodyv, GByteArray, bodyv);
	FinishArray(ctx->errorv, GError, errorv);

	return err;
}

/* -------------------------------------------------------------------------- */

static gboolean _has_flag_in_headers (struct req_args_s *args,
		const char *header, const char *flag) {
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

gboolean _request_get_flag (struct req_args_s *args, const char *flag) {
	const gchar *v = OPT(flag);
	if (NULL != v)
		return oio_str_parse_bool(v, FALSE);
	return _has_flag_in_headers (args, PROXYD_HEADER_MODE, flag);
}

void service_learn (const char *key) {
	gchar *k = g_strdup(key);
	SRV_WRITE(lru_tree_insert(srv_known, k, GINT_TO_POINTER(1)));
}

gboolean service_is_known (const char *key) {
	gboolean known = FALSE;
	SRV_READ(known = (NULL != lru_tree_get (srv_known, key)));
	return known;
}

GBytes **NOLOCK_service_lookup_wanted (const char *type) {
	if (!wanted_prepared)
		return NULL;
	for (GBytes **pw=wanted_prepared ; *pw ; pw++) {
		if (!strcmp (type, (const char*)g_bytes_get_data(*pw,NULL)))
			return pw;
	}
	return NULL;
}

void service_remember_wanted (const char *type) {
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

GBytes* service_is_wanted (const char *type) {
	GBytes *out = NULL;
	WANTED_READ(do {
		GBytes **pold = NOLOCK_service_lookup_wanted (type);
		if (pold)
			out = g_bytes_ref (*pold);
	} while (0));
	return out;
}

void client_init (struct client_ctx_s *ctx, struct req_args_s *args,
		const char *srvtype, gint64 seq) {
	memset(ctx, 0, sizeof(*ctx));
	ctx->url = args->url;
	ctx->type = srvtype;
	ctx->seq = seq;
	sqlx_inline_name_fill_type_asis (&ctx->name, args->url,
			*srvtype == '#' ? srvtype+1 : srvtype, ctx->seq);
	ctx->which = CLIENT_PREFER_NONE;
}

void client_clean (struct client_ctx_s *ctx) {
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

GError * KV_read_properties (struct json_object *j, gchar ***out,
		const char *section, gboolean fail_if_empty) {

	EXTRA_ASSERT(out != NULL);
	EXTRA_ASSERT(oio_str_is_set(section));

	*out = NULL;
	if (!json_object_is_type(j, json_type_object))
		return BADREQ("Object argument expected");
	struct json_object *jprops = NULL;

	if (!json_object_object_get_ex(j, section, &jprops)) {
		if (fail_if_empty)
			return BADREQ("No \"%s\" field", section);
		*out = g_malloc0(sizeof(gchar*));
		return NULL;
	}

	GError *err = NULL;
	if (!json_object_is_type(jprops, json_type_object)) {
		err = BADREQ("Bad \"%s\" field", section);
	} else {
		err = KV_decode_object(jprops, out);
	}

	return err;
}

GError * KV_read_usersys_properties (struct json_object *j, gchar ***out) {
	gchar **user = NULL;
	GError *err = KV_read_properties(j, &user, "properties", FALSE);
	if (err)
		return err;

	gchar **sys = NULL;
	err = KV_read_properties(j, &sys, "system", FALSE);
	if (err) {
		g_strfreev(user);
		return err;
	}

	for (gchar **p = user; *p && *(p + 1); p += 2)
		oio_str_reuse(p, g_strconcat("user.", *p, NULL));
	gchar **kv = (gchar **) oio_ext_array_concat((gpointer) user, (gpointer) sys);
	g_free(user);
	g_free(sys);
	*out = kv;
	return NULL;
}
