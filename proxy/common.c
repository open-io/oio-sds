/*
OpenIO SDS proxy
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS

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

gchar **
proxy_get_cs_urlv (void)
{
	g_rw_lock_reader_lock (&csurl_rwlock);
	gchar **cs = g_strdupv(csurl);
	g_rw_lock_reader_unlock (&csurl_rwlock);

	oio_ext_array_shuffle((void**)cs, g_strv_length(cs));
	return cs;
}

gboolean
validate_namespace (const char * ns)
{
	return 0 == strcmp (ns, ns_name);
}

GError *
validate_srvtype(const char *srvtype)
{
	gboolean service_types_loaded = FALSE;
	gboolean service_type_found = FALSE;
	NSINFO_READ(
		if (srvtypes) {
			service_types_loaded = TRUE;
			for (gchar ** p = srvtypes; !service_type_found && *p; ++p)
				service_type_found = !strcmp(*p, srvtype);
		});
	if (!service_types_loaded)
		return NEWERROR(CODE_UNAVAILABLE, "Service types not yet loaded");
	if (!service_type_found)
		return BADSRVTYPE(srvtype);
	return NULL;
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

static gboolean
service_is_slave (const char *obj, const char *master)
{
	gboolean rc;
	MASTER_READ(
		gchar *v = lru_tree_get(srv_master, obj);
		rc = (v != NULL) && strcmp(v, master));
	return rc;
}

static gboolean
service_is_master (const char *obj, const char *master)
{
	gboolean rc;
	MASTER_READ(
		gchar *v = lru_tree_get(srv_master, obj);
		rc = (v != NULL) && !strcmp(v, master));
	return rc;
}

static void
service_learn_master (const char *obj, const char *master)
{
	gchar *k = g_strdup (obj), *v = g_strdup (master);
	MASTER_WRITE(lru_tree_insert(srv_master, k, v));
}

static void
service_forget_master(const char *obj)
{
	MASTER_WRITE(lru_tree_remove(srv_master, obj));
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

	gsize len = g_strv_length (m1uv);
	gsize pivot = len;

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

	if (oio_proxy_srv_shuffle) {
		switch (pivot) {
			case 1:
				break;
			case 0:
				/* If no available & preferred service, shuffle them */
				if (len > 1)
					pivot = len;
				else
					break;
				// FALLTHROUGH
			default:
				/* If multiple available & preferred services, shuffle them */
				oio_ext_array_shuffle((void**)m1uv, pivot);
		}
	}

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

static gchar *
_election_key(struct client_ctx_s *ctx)
{
	return g_strconcat (ctx->name.base, "/", ctx->name.type, NULL);
}

static gboolean
context_clue_for_decache(struct client_ctx_s *ctx)
{
	if (!ctx->errorv)
		return FALSE;
	for (guint i=0; i < ctx->count; ++i) {
		if (error_clue_for_decache(ctx->errorv[i]))
			return TRUE;
	}
	return FALSE;
}

static void
cache_flush_reference(struct req_args_s *args, struct client_ctx_s *ctx)
{
	GRID_DEBUG("Suspected stale cache entry for [%s] [%s]",
			ctx->type, oio_url_get(args->url, OIOURL_WHOLE));

	hc_decache_reference(resolver, args->url);
}

void
cache_flush_user(struct req_args_s *args, struct client_ctx_s *ctx)
{
	GRID_DEBUG("Suspected stale cache entry for [%s] [%s]",
			ctx->type, oio_url_get(args->url, OIOURL_WHOLE));

	hc_decache_reference_service(resolver, args->url, NAME_SRVTYPE_META2);
	gchar *k = g_strconcat(ctx->name.base, "/", NAME_SRVTYPE_META2, NULL);
	service_forget_master(k);
	g_free(k);
}

static GError *
gridd_request_replicated (struct req_args_s *args, struct client_ctx_s *ctx,
		request_packer_f pack)
{
	gboolean retry = TRUE;
	GError *err = NULL;
	gchar **m1uv = NULL;
	EXTRA_ASSERT (ctx != NULL);

	gchar *election_key = _election_key(ctx);
	STRING_STACKIFY(election_key);
	gchar *peers = NULL;

	const gint64 deadline = oio_ext_get_deadline();

	const gint64 req_start = oio_ext_monotonic_time();

	/* Locate the services */
label_retry:
	if (ctx->which == CLIENT_SPECIFIED) {
		const char *service_id = SERVICE_ID();
		EXTRA_ASSERT(service_id != NULL);
		m1uv = g_strsplit(service_id, OIO_CSV_SEP, -1);
	} else if (*ctx->type == '#') {
		gboolean m0_only = g_strcmp0("#meta0", ctx->type) == 0;
		err = hc_resolve_reference_directory(
				resolver, ctx->url, &m1uv, m0_only, deadline);
	} else {
		err = hc_resolve_reference_service(
				resolver, ctx->url, ctx->type, &m1uv, deadline);
	}

	if (err) {
		EXTRA_ASSERT(m1uv == NULL);
		if (retry && error_clue_for_decache(err)) {
			/* We may have asked the wrong meta1, try again.
			 * The reference has already been freed from the cache
			 * in `_resolve_service_through_many_meta1`. */
			retry = FALSE;
			g_clear_error(&err);
			goto label_retry;
		} else {
			g_prefix_error(&err, "Directory error: ");
		}
	} else {
		EXTRA_ASSERT(m1uv != NULL);
		if (*ctx->type == '#' && ctx->which != CLIENT_SPECIFIED) {
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
			return NEWERROR (CODE_CONTAINER_NOTFOUND, "No service located");
		}

		/* We found some locations, let's keep only the URL part */
		meta1_urlv_shift_addr(m1uv);
		/* let's prefer the services requested (master, slave, etc) */
		_sort_services (ctx, election_key, m1uv);
		peers = g_strjoinv(",", m1uv);
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
	const gchar *headers[4] = {SQLX_ADMIN_PEERS, peers, NULL, NULL};
	GByteArray *packed = pack(&n, headers);

	gboolean stop = FALSE;
	for (gchar **pu = m1uv; *pu && !stop; ++pu) {
		const char *url = pu[0];
		const char *next_url = pu[1];
		GByteArray *body = NULL;

		struct gridd_client_s *client = gridd_client_create_empty();
		if (!client) {
			err = SYSERR("Memory allocation error");
		} else {
			err = gridd_client_connect_url(client, url);
			if (err) {
				GRID_WARN("Invalid peer [%s]", url);
				err->code = ERRCODE_CONN_NOROUTE;
			}
		}

		if (!err) {
			/* TODO ensure the service match the expected TYPE and SEQ */
			if (!ctx->decoder) {
				err = gridd_client_request(client, packed, &body, _on_reply);
			} else {
				err = gridd_client_request(client, packed, ctx->decoder_data, ctx->decoder);
			}
		}

		if (!err) {
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
				if (ctx->which == CLIENT_RUN_ALL
						|| ctx->which == CLIENT_SPECIFIED)
					gridd_client_no_redirect (client);
				gridd_client_start (client);
				gridd_client_set_timeout (client,
					oio_clamp_timeout(proxy_timeout_common, deadline));
				if (!(err = gridd_client_loop (client)))
					err = gridd_client_error (client);
#ifdef HAVE_ENBUG
			}
#endif
		}

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

		/* If there is no error that indicate a wrong cache entry, we can
		 * check for a possible redirection to update the cache of master */
		if ((!err || !error_clue_for_decache(err))
				&& (flag_prefer_master_for_read ||
					flag_prefer_slave_for_read ||
					flag_prefer_master_for_write)) {
			const char *actual = client ? gridd_client_url(client) : NULL;
			if (actual && 0 != strcmp(actual, url)) {
				// TODO(jfs): maybe save the ID instead (or remove this mark)
				service_learn_master(election_key, actual);
			}
		}

		if (err) {
			if (CODE_IS_NETWORK_ERROR(err->code)) {
				/* the target service is in bad shape, let's avoid it for
				 * the subsequent requests. */
				service_invalidate(url);

				/* JFS: should we let the client retry or occupy a
				 * thread in the proxy to make all the necessary retries?
				 * FVE: in some cases where we are not sure the request
				 * actually failed, we will let the client retry. */

				/* that error is not strong enough to stop the iteration, we
				 * just try with another service */
				GError *last_err = err;
				err = NULL;

				/* But if we expected at least one service to respond,
				 * and we still encounter that error with the last URL of the
				 * array (!pu[1]), then this is an overall error that we should return. */
				if ((ctx->which != CLIENT_RUN_ALL
						&& ctx->which != CLIENT_SPECIFIED) && !next_url) {
					err = BUSY("No service replied (last error: (%d) %s)",
							last_err->code, last_err->message);
					stop = TRUE;
				} else if (ctx->which == CLIENT_PREFER_MASTER &&
						CODE_IS_ERR_AFTER_START(last_err->code)) {
					/* Maybe the request is running in the background.
					 * For requests on master, let the client decide to try again.
					 * Retrying may trigger an error (such as a conflict),
					 * if the request has already been executed. */
					err = BUSY("No service replied (last error: (%d) %s)",
							last_err->code, last_err->message);
					stop = TRUE;
				}
				g_clear_error(&last_err);
			} else if (CODE_IS_RETRY(err->code)) {
				/* the target service is in bad shape, let's avoid it for
				 * the subsequent requests. And we currently we choose to
				 * stop the iteration and let the retry be achieved in the
				 * client SDK. This error is a clue that the other replicas
				 * will also be overloaded. */
				service_invalidate(url);
				stop = TRUE;
			} else if (ctx->which == CLIENT_RUN_ALL
					|| ctx->which == CLIENT_SPECIFIED) {
				/* All the services must be reached, let's just remind the
				 * error (already done) and continue to the next service */
				g_clear_error (&err);
			} else {
				stop = TRUE;
			}
		} else {
			if (ctx->which != CLIENT_RUN_ALL && ctx->which != CLIENT_SPECIFIED)
				stop = TRUE;
		}

		if (client) {
			gridd_client_free (client);
			client = NULL;
		}
	}
	ctx->request_duration = oio_ext_monotonic_time() - resolve_end;

	EXTRA_ASSERT(urlv->len == bodyv->len);
	EXTRA_ASSERT(urlv->len == errorv->len);

	g_byte_array_unref (packed);
	g_strfreev(m1uv);
	g_free(peers);

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

GError *
gridd_request_replicated_with_retry (struct req_args_s *args,
		struct client_ctx_s *ctx, request_packer_f pack)
{
	GError *err = NULL;
	gint attempts = 3;
retry:
	err = gridd_request_replicated(args, ctx, pack);
	if (error_clue_for_decache(err) || context_clue_for_decache(ctx)) {
		if (*ctx->type == '#')
			cache_flush_reference(args, ctx);
		else
			cache_flush_user(args, ctx);
		if (attempts-- > 0) {
			g_clear_error(&err);
			client_clean(ctx);
			goto retry;
		}
	}
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
	if (SERVICE_ID())
		ctx->which = CLIENT_SPECIFIED;
	else
		ctx->which = CLIENT_PREFER_NONE;
}

void client_clean (struct client_ctx_s *ctx) {
	if (ctx->urlv) {
		g_strfreev (ctx->urlv);
		ctx->urlv = NULL;
	}
	if (ctx->errorv) {
		for (GError **pe=ctx->errorv; *pe ;pe++)
			g_clear_error(pe);
		g_free (ctx->errorv);
		ctx->errorv = NULL;
	}
	if (ctx->bodyv) {
		metautils_gba_cleanv (ctx->bodyv);
		ctx->bodyv = NULL;
	}
}

GError * KV_read_properties (struct json_object *j, gchar ***out,
		const char *section, gboolean fail_if_empty) {

	EXTRA_ASSERT(out != NULL);
	EXTRA_ASSERT(oio_str_is_set(section));

	*out = NULL;
	if (json_object_get_type(j) == json_type_null && !fail_if_empty) {
		*out = g_malloc0(sizeof(gchar*));
		return NULL;
	}
	if (!json_object_is_type(j, json_type_object)) {
		return BADREQ("Object argument expected, got %s",
				json_type_to_name(json_object_get_type(j)));
	}
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

static gboolean
_cb_exec_and_concat (GByteArray *tmp, MESSAGE reply)
{
	gsize bsize = 0;
	void *b = metautils_message_get_BODY(reply, &bsize);
	if (b && bsize)
		g_byte_array_append(tmp, b, bsize);
	return TRUE;
}

GError *
gridd_client_exec_and_concat_string (const gchar *to, gdouble seconds,
		GByteArray *req, gchar **out)
{
	EXTRA_ASSERT(to != NULL);
	EXTRA_ASSERT(out == NULL || *out == NULL);

	GError *err = NULL;
	GByteArray *tmp = g_byte_array_sized_new(512);

	struct gridd_client_s *client = gridd_client_create(
			to, req, tmp, (client_on_reply)_cb_exec_and_concat);
	g_byte_array_unref (req);
	req = NULL;

	if (!client) {
		return SYSERR("client creation");
	} else {
		if (seconds > 0.0)
			gridd_client_set_timeout (client, seconds);
		gridd_client_set_avoidance(client, FALSE);
		err = gridd_client_run (client);
		gridd_client_free (client);
	}

	if (!err && out) {
		g_byte_array_append (tmp, (guint8*)"", 1);
		*out = (gchar*) g_byte_array_free (tmp, FALSE);
		tmp = NULL;
	}
	if (tmp)
		g_byte_array_free (tmp, TRUE);

	return err;
}
