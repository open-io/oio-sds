/*
OpenIO SDS core library
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#include <glib.h>
#include <json.h>
#include <curl/curl.h>

#include <metautils/lib/metautils_macros.h>

#include "oiostr.h"
#include "oiocs.h"

#include "internals.h"
#include "cs_internals.h"
#include "http_internals.h"

#define CS_CALL(self,F) VTABLE_CALL(self,struct oio_cs_client_abstract_s*,F)

void
oio_cs_client__destroy (struct oio_cs_client_s *self)
{
	CS_CALL(self,destroy)(self);
}

GError *
oio_cs_client__register_service (struct oio_cs_client_s *self,
		const char *in_type, const struct oio_cs_registration_s *reg)
{
	if (!in_type)
		return BADREQ("Missing srvtype");
	CS_CALL(self,register_service)(self,in_type,reg);
}

GError *
oio_cs_client__list_services (struct oio_cs_client_s *self,
		const char *in_type,
		void (*on_reg) (const struct oio_cs_registration_s *reg))
{
	if (!in_type)
		return BADREQ("Missing srvtype");
	CS_CALL(self,list_services)(self,in_type,on_reg);
}

GError *
oio_cs_client__list_types (struct oio_cs_client_s *self,
		void (*on_type) (const char *srvtype))
{
	CS_CALL(self,list_types)(self,on_type);
}

/* -------------------------------------------------------------------------- */

struct oio_cs_client_PROXY_s
{
	struct oio_cs_client_vtable_s *vtable;
	gchar *ns;
};

static void _cs_PROXY__destroy (struct oio_cs_client_s *self);

static GError * _cs_PROXY__register_service (struct oio_cs_client_s *self,
		const char *in_type, const struct oio_cs_registration_s *reg);

static GError * _cs_PROXY__list_services (struct oio_cs_client_s *self,
		const char *in_type,
		void (*on_reg) (const struct oio_cs_registration_s *reg));

static GError * _cs_PROXY__list_types (struct oio_cs_client_s *self,
		void (*on_type) (const char *srvtype));

static struct oio_cs_client_vtable_s vtable_PROXY =
{
	_cs_PROXY__destroy,
	_cs_PROXY__register_service,
	_cs_PROXY__list_services,
	_cs_PROXY__list_types
};

void
_cs_PROXY__destroy (struct oio_cs_client_s *self)
{
	g_assert (self != NULL);
	struct oio_cs_client_PROXY_s *cs = (struct oio_cs_client_PROXY_s*) self;
	g_assert (cs->vtable == &vtable_PROXY);
	oio_str_clean (&cs->ns);
	SLICE_FREE (struct oio_cs_client_PROXY_s, cs);
}

GError *
_cs_PROXY__register_service (struct oio_cs_client_s *self,
		const char *in_type, const struct oio_cs_registration_s *reg)
{
	g_assert (self != NULL);
	struct oio_cs_client_PROXY_s *cs = (struct oio_cs_client_PROXY_s*) self;
	g_assert (cs->vtable == &vtable_PROXY);

	if (!in_type || !*in_type)
		return BADREQ("Missing srvtype");
	if (!reg || !reg->url || !reg->id)
		return BADREQ("Invalid service");

	/* TODO(jfs): manage utf-8 and quotes */
	GString *body = g_string_new ("");
	g_string_append_printf (body, "{\"ns\":\"%s\"", cs->ns);
	g_string_append_printf (body, ",\"type\":\"%s\"", in_type);
	g_string_append_printf (body, ",\"addr\":\"%s\"", reg->url);
	g_string_append_printf (body, ",\"score\":%d", SCORE_UNSET);
	if (reg->kv_tags) {
		g_string_append (body, ",\"tags\":{");
		gboolean first = TRUE;
		for (const char * const *pp = reg->kv_tags; *pp && *(pp+1) ;pp+=2) {
			if (!first) g_string_append_c (body, ',');
			g_string_append_printf (body, "\"%s\":\"%s\"", *pp, *(pp+1));
		}
		g_string_append_c (body, '}');
	}
	g_string_append (body, "}");

	CURL *h = _curl_get_handle ();
	GError *err = oio_proxy_call_conscience_register (h, cs->ns, body);
	curl_easy_cleanup (h);

	g_string_free (body, TRUE);
	return err;
}

GError *
_cs_PROXY__list_services (struct oio_cs_client_s *self,
		const char *in_type,
		void (*on_reg) (const struct oio_cs_registration_s *reg))
{
	g_assert (self != NULL);
	struct oio_cs_client_PROXY_s *cs = (struct oio_cs_client_PROXY_s*) self;
	g_assert (cs->vtable == &vtable_PROXY);

	if (!in_type || !*in_type)
		return BADREQ("Missing srvtype");

	GString *body = g_string_new ("");

	CURL *h = _curl_get_handle ();
	GError *err = oio_proxy_call_conscience_list (h, cs->ns, in_type, body);
	curl_easy_cleanup (h);

	if (!err && !body->len)
		err = NEWERROR(CODE_PLATFORM_ERROR, "proxy: empty reply");

	if (!err) {
		json_tokener *parser = json_tokener_new ();
		json_object *jbody = json_tokener_parse_ex (parser, body->str, body->len);
		if (json_tokener_success != json_tokener_get_error (parser))
			err = NEWERROR(CODE_PLATFORM_ERROR, "proxy: invalid JSON");
		else if (!jbody || !json_object_is_type (jbody, json_type_array))
			err = NEWERROR(CODE_PLATFORM_ERROR, "proxy:  unexpected JSON");
		else for (int i=json_object_array_length(jbody); i>0 && !err ;i--) {
			json_object *item = json_object_array_get_idx (jbody, i-1);
			if (!json_object_is_type(item, json_type_object))
				err = NEWERROR(CODE_PLATFORM_ERROR, "proxy:  unexpected item");
			else {
				struct oio_cs_registration_s reg = {0};
				/* TODO(jfs) fill reg with the item */
				if (on_reg)
					(on_reg)(&reg);
			}
		}
		if (jbody) json_object_put (jbody);
		json_tokener_free (parser);
	}

	g_string_free (body, TRUE);
	return err;
}

GError *
_cs_PROXY__list_types (struct oio_cs_client_s *self,
		void (*on_type) (const char *srvtype))
{
	g_assert (self != NULL);
	struct oio_cs_client_PROXY_s *cs = (struct oio_cs_client_PROXY_s*) self;
	g_assert (cs->vtable == &vtable_PROXY);

	GString *body = g_string_new ("");

	CURL *h = _curl_get_handle ();
	GError *err = oio_proxy_call_conscience_list_types (h, cs->ns, body);
	curl_easy_cleanup (h);

	if (!err && !body->len)
		err = NEWERROR(CODE_PLATFORM_ERROR, "proxy: empty reply");

	if (!err) {
		json_tokener *parser = json_tokener_new ();
		json_object *jbody = json_tokener_parse_ex (parser, body->str, body->len);
		if (json_tokener_success != json_tokener_get_error (parser))
			err = NEWERROR(CODE_PLATFORM_ERROR, "proxy: invalid JSON");
		else if (!jbody || !json_object_is_type (jbody, json_type_array))
			err = NEWERROR(CODE_PLATFORM_ERROR, "proxy:  unexpected reply");
		else for (int i=json_object_array_length(jbody); i>0 && !err ;i--) {
			json_object *item = json_object_array_get_idx (jbody, i-1);
			if (!json_object_is_type(item, json_type_string))
				err = NEWERROR(CODE_PLATFORM_ERROR, "proxy:  unexpected reply");
			else if (on_type)
				(on_type)(json_object_get_string(item));
		}
		if (jbody) json_object_put (jbody);
		json_tokener_free (parser);
	}

	g_string_free (body, TRUE);
	return err;
}

struct oio_cs_client_s *
oio_cs_client__create_proxied (const char *ns)
{
	struct oio_cs_client_PROXY_s *cs = SLICE_NEW0(struct oio_cs_client_PROXY_s);
	cs->vtable = &vtable_PROXY;
	oio_str_replace (&cs->ns, ns);
	return (struct oio_cs_client_s*) cs;
}

