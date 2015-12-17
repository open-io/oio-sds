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

gchar *
proxy_get_csurl (void)
{
	gchar *cs = NULL;
	CSURL_DO(if (csurl) { cs = g_strdup(csurl); });
	return cs;
}

gboolean
validate_namespace (const char * ns)
{
	return 0 == strcmp (ns, nsname);
}

gboolean
validate_srvtype (const char * n)
{
	gboolean rc = FALSE;
	NSINFO_DO(if (srvtypes) {
		for (gchar ** p = srvtypes; !rc && *p; ++p)
			rc = !strcmp (*p, n);
	});
	return rc;
}

gboolean
service_is_ok (gconstpointer k)
{
	gpointer v;
	SRV_DO(v = lru_tree_get (srv_down, k));
	return v == NULL;
}

void
service_invalidate (gconstpointer k)
{
	gulong now = oio_ext_monotonic_time () / G_TIME_SPAN_SECOND;
	SRV_DO(lru_tree_insert (srv_down, g_strdup((const char *)k), (void*)now));
	GRID_INFO("invalid at %lu %s", now, (const char*)k);
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

static gboolean
_qualify_service_url (gconstpointer p)
{
	gboolean rc = FALSE;
	gchar *u = meta1_strurl_get_address ((const char*)p);
	if (u)
		rc = service_is_ok (u);
	g_free (u);
	return rc;
}

GError *
_resolve_service_and_do (const char *t, gint64 seq, struct oio_url_s *u,
		GError * (*hook) (struct meta1_service_url_s *m1u, gboolean *next))
{
	gchar **uv = NULL;
	GError *err = NULL;
	guint failures = 0;

	if (*t == '#')
		err = hc_resolve_reference_directory (resolver, u, &uv);
	else
		err = hc_resolve_reference_service (resolver, u, t, &uv);

	EXTRA_ASSERT(BOOL(uv!=NULL) ^ BOOL(err!=NULL));

	if (NULL != err) {
		g_prefix_error (&err, "Resolution error: ");
		return err;
	}

	if (!*uv)
		err = NEWERROR (CODE_CONTAINER_NOTFOUND, "No service located");
	else {
		/* just consider the URL part. The resolver already pre-shuffled it. */

		gsize pivot = oio_ext_array_partition ((void**)uv, g_strv_length(uv),
				_qualify_service_url);
		if (pivot > 0 && !oio_dir_no_shuffle)
			oio_ext_array_shuffle ((void**)uv, pivot);

		for (gchar **pm2 = uv; *pm2; ++pm2) {
			struct meta1_service_url_s *m1u = meta1_unpack_url (*pm2);

			if (seq > 0 && seq != m1u->seq) {
				meta1_service_url_clean (m1u);
				continue;
			}
			if (*t == '#' && strcmp(t+1, m1u->srvtype)) {
				meta1_service_url_clean (m1u);
				continue;
			}

			gboolean next = FALSE;
			err = hook (m1u, &next);
			if (err && CODE_IS_NETWORK_ERROR(err->code))
				service_invalidate (m1u->host);
			meta1_service_url_clean (m1u);

			if (!err) {
				if (!next)
					goto exit;
			} else {
				++ failures;
				GRID_DEBUG ("HOOK error : (%d) %s", err->code, err->message);
				if (!next && !CODE_IS_NETWORK_ERROR(err->code)) {
					g_prefix_error (&err, "HOOK error: ");
					goto exit;
				}
				g_clear_error (&err);
			}
		}
		if (!err && failures == g_strv_length(uv))
			err = NEWERROR (CODE_PLATFORM_ERROR, "No reply");
	}
exit:
	g_strfreev (uv);
	return err;
}

GError *
_gba_request (struct meta1_service_url_s *m1u,
		GByteArray * (reqbuilder) (void),
		GByteArray ** out)
{
	gboolean _on_reply (gpointer ctx, MESSAGE reply) {
		GByteArray **pgba = ctx;
		GError *e = metautils_message_extract_body_gba (reply, pgba);
		if (e) g_clear_error (&e);
		return TRUE;
	}

	GByteArray *body = NULL;
	GByteArray *req = reqbuilder();
	struct gridd_client_s *c = gridd_client_create(m1u->host, req,
			&body, _on_reply);
	g_byte_array_unref (req);
	gridd_client_start (c);
	gridd_client_set_timeout (c, 1.0);
	GError *e = gridd_client_loop (c);
	if (!e)
		e = gridd_client_error (c);
	gridd_client_free (c);

	if (!e && out)
		*out = g_byte_array_ref (body);
	metautils_gba_unref (body);
	return e;
}

GError *
_gbav_request (const char *t, gint64 seq, struct oio_url_s *u,
		GByteArray * builder (void),
		gchar ***outurl, GByteArray ***out)
{
	GPtrArray *url = g_ptr_array_new (), *tmp = g_ptr_array_new ();
	GError* hook (struct meta1_service_url_s *m1u, gboolean *next) {
		GByteArray *body = NULL;
		*next = FALSE;
		GError *e = _gba_request (m1u, builder, &body);
		if (!e && body) {
			g_ptr_array_add (tmp, g_byte_array_ref (body));
			g_ptr_array_add (url, g_strdup(m1u->host));
		}
		if (body)
			g_byte_array_unref (body);
		return e;
	}
	GError *e = _resolve_service_and_do (t, seq, u, hook);
	if (!e) {
		if (out) {
			*out = (GByteArray**) metautils_gpa_to_array (tmp, TRUE);
			tmp = NULL;
		}
		if (outurl) {
			*outurl = (gchar**) metautils_gpa_to_array (url, TRUE);
			url = NULL;
		}
	}
	if (url) {
		g_ptr_array_set_free_func (url, g_free);
		g_ptr_array_free (url, TRUE);
	}
	if (tmp) {
		g_ptr_array_set_free_func (tmp, metautils_gba_unref);
		g_ptr_array_free (tmp, TRUE);
	}
	return e;
}

gboolean
_request_has_flag (struct req_args_s *args, const char *header,
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

