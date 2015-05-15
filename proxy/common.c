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

struct sub_action_s {
	const gchar *verb;
	enum http_rc_e (*handler) (struct req_args_s *, struct json_object *);
};

static enum http_rc_e
abstract_action (struct req_args_s *args, struct sub_action_s *sub)
{
	struct json_tokener *parser;
	struct json_object *jbody, *jargs, *jaction;
	enum http_rc_e rc;

	jaction = jargs = NULL;
	parser = json_tokener_new ();

	jbody = json_tokener_parse_ex (parser, (char *) args->rq->body->data,
			args->rq->body->len);
	if (!json_object_is_type (jbody, json_type_object))
		rc = _reply_format_error (args, BADREQ ("Invalid JSON object"));
	else {
		if (!json_object_object_get_ex (jbody, "action", &jaction)
				|| !json_object_is_type (jaction, json_type_string))
			rc = _reply_forbidden_error (args, BADREQ ("No/Bad action"));
		else if (!json_object_object_get_ex (jbody, "args", &jargs))
			rc = _reply_forbidden_error (args, BADREQ ("No/Bad arguments"));
		else {
			const char *action = json_object_get_string (jaction);
			args->rp->access_tail ("action=%s", action);
			for (; sub->handler ;++sub) {
				if (!strcmp(action, sub->verb)) {
					rc = sub->handler(args, jargs);
					goto exit;
				}
			}
			rc = _reply_forbidden_error (args, BADREQ ("Unexpected action"));
		}
	}
exit:
	json_object_put (jbody);
	json_tokener_free (parser);
	return rc;
}

static GError *
_resolve_service_and_do (const gchar *t, gint64 seq, struct hc_url_s *u,
		GError * (*hook) (struct meta1_service_url_s *m1u, gboolean *next))
{
	gchar **uv = NULL;
	GError *err = NULL;
	guint failures = 0;

	if (*t == '#')
		err = hc_resolve_reference_directory (resolver, u, &uv);
	else
		err = hc_resolve_reference_service (resolver, u, t, &uv);

	g_assert(BOOL(uv!=NULL) ^ BOOL(err!=NULL));

	if (NULL != err) {
		g_prefix_error (&err, "Resolution error: ");
		return err;
	}

	if (!*uv)
		err = NEWERROR (CODE_CONTAINER_NOTFOUND, "No service located");
	else {
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

static GError *
_gba_request (struct meta1_service_url_s *m1u,
		GByteArray * (reqbuilder) (void),
		GByteArray ** out)
{
	gboolean _on_reply (gpointer ctx, struct message_s *reply) {
		GByteArray **pgba = ctx;
		GError *e = message_extract_body_gba (reply, pgba);
		if (e) g_clear_error (&e);
		return TRUE;
	}

	GByteArray *body = NULL;
	GByteArray *req = reqbuilder();
	struct gridd_client_s *c = gridd_client_create(m1u->host, req,
			&body, _on_reply);
	g_byte_array_unref (req);
	gridd_client_start (c);
	gridd_client_set_timeout (c, 1.0, 1.0);
	GError *e = gridd_client_loop (c);
	if (!e)
		e = gridd_client_error (c);
	gridd_client_free (c);

	if (!e && out)
		*out = g_byte_array_ref (body);
	metautils_gba_unref (body);
	return e;
}

static GError *
_gbav_request (const gchar *t, gint64 seq, struct hc_url_s *u,
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

