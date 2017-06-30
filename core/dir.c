/*
OpenIO SDS core library
Copyright (C) 2015-2017 OpenIO, as part of OpenIO Software Defined Storage

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

#include <core/oiodir.h>

#include <curl/curl.h>
#include <json-c/json.h>

#include <core/oiostr.h>
#include <core/oioext.h>

#include "internals.h"
#include "http_internals.h"

#define DIR_CALL(self,F) VTABLE_CALL(self,struct oio_directory_abstract_s*,F)

void
oio_directory__destroy (struct oio_directory_s *self)
{
	DIR_CALL(self,destroy)(self);
}

GError *
oio_directory__create (struct oio_directory_s *self,
		const struct oio_url_s *url)
{
	DIR_CALL(self,create)(self, url);
}

GError *
oio_directory__list (struct oio_directory_s *self,
		const struct oio_url_s *url, const char *srvtype,
		gchar ***out_dir, gchar ***out_srv)
{
	DIR_CALL(self,list)(self, url, srvtype, out_dir, out_srv);
}

GError *
oio_directory__link (struct oio_directory_s *self,
		const struct oio_url_s *url, const char *srvtype, gboolean autocreate,
		gchar ***out_srv)
{
	DIR_CALL(self,link)(self, url, srvtype, autocreate, out_srv);
}

GError *
oio_directory__get_properties(struct oio_directory_s *self,
		const struct oio_url_s *url, on_element_f fct, void *ctx)
{
	DIR_CALL(self, get_prop)(self, url, fct, ctx);
}

GError *
oio_directory__set_properties(struct oio_directory_s *self,
		const struct oio_url_s *url, const char * const *values)
{
	DIR_CALL(self, set_prop)(self, url, values);
}

/* -------------------------------------------------------------------------- */

struct oio_directory_PROXY_s {
	struct oio_directory_vtable_s *vtable;
	gchar *ns;
};

static void _dir_proxy_destroy (struct oio_directory_s *self);

static GError * _dir_proxy_create (struct oio_directory_s *self,
			const struct oio_url_s *url);

static GError * _dir_proxy_list (struct oio_directory_s *self,
			const struct oio_url_s *url, const char *srvtype,
			gchar ***out_dir, gchar ***out_srv);

static GError * _dir_proxy_link (struct oio_directory_s *self,
			const struct oio_url_s *url, const char *srvtype,
			gboolean autocreate, gchar ***out_srv);

static GError * _dir_proxy_get_prop(struct oio_directory_s *self,
		const struct oio_url_s *url, on_element_f fct, void *ctx);

static GError * _dir_proxy_set_prop(struct oio_directory_s *self,
		const struct oio_url_s *url, const char * const *values);

static struct oio_directory_vtable_s vtable_PROXY =
{
	_dir_proxy_destroy,
	_dir_proxy_create,
	_dir_proxy_list,
	_dir_proxy_link,
	_dir_proxy_get_prop,
	_dir_proxy_set_prop,
};

struct oio_directory_s *
oio_directory__create_proxy (const char *ns)
{
	EXTRA_ASSERT (oio_str_is_set(ns));
	struct oio_directory_PROXY_s *self = g_malloc0 (sizeof(*self));
	self->vtable = &vtable_PROXY;
	self->ns = g_strdup (ns);
	return (struct oio_directory_s*) self;
}

static void
_dir_proxy_destroy (struct oio_directory_s *self)
{
	EXTRA_ASSERT (self != NULL);
	struct oio_directory_PROXY_s *d = (struct oio_directory_PROXY_s *) self;
	EXTRA_ASSERT (d->vtable == &vtable_PROXY);
	d->vtable = NULL;
	oio_str_clean (&d->ns);
	g_free (d);
}

static GError *
_load_srvtab (struct json_object *jtab, gchar ***out)
{
	GPtrArray *tmp = g_ptr_array_new ();
	GError *err = NULL;
	for (int i=0,max=json_object_array_length(jtab); i<max ;++i) {
		struct json_object *jitem = json_object_array_get_idx (jtab, i);
		struct json_object *jseq, *jtype, *jhost;
		struct oio_ext_json_mapping_s m[] = {
			{"seq",  &jseq,  json_type_int, 1},
			{"type", &jtype, json_type_string, 1},
			{"host", &jhost, json_type_string, 1},
			{NULL, NULL, 0, 0}
		};
		if (NULL != (err = oio_ext_extract_json (jitem, m)))
			break;
		g_ptr_array_add (tmp, g_strdup_printf ("%"G_GINT64_FORMAT",%s,%s",
					json_object_get_int64 (jseq),
					json_object_get_string (jtype),
					json_object_get_string (jhost)));
	}
	g_ptr_array_add (tmp, NULL);
	if (!err) {
		*out = (gchar**) g_ptr_array_free (tmp, FALSE);
		return NULL;
	} else {
		g_strfreev((gchar**)g_ptr_array_free (tmp, FALSE));
		return err;
	}
}

#define _DIR_FUNC_INIT \
	EXTRA_ASSERT(self != NULL);\
	struct oio_directory_PROXY_s *d = (struct oio_directory_PROXY_s *) self;\
	EXTRA_ASSERT(d->vtable == &vtable_PROXY);\
	(void)d;

static GError *
_dir_proxy_create (struct oio_directory_s *self, const struct oio_url_s *url)
{
	_DIR_FUNC_INIT

	struct oio_url_s *u = oio_url_dup (url);
	CURL *h = _curl_get_handle_proxy ();
	GError *err = oio_proxy_call_reference_create (h, u);
	curl_easy_cleanup (h);
	oio_url_pclean (&u);

	return err;
}

static GError *
_dir_proxy_list (struct oio_directory_s *self,
		const struct oio_url_s *url, const char *srvtype,
		gchar ***out_dir, gchar ***out_srv)
{
	_DIR_FUNC_INIT

	GError *err = NULL;
	GString *out = g_string_new ("");
	struct oio_url_s *u = oio_url_dup (url);
	CURL *h = _curl_get_handle_proxy ();
	err = oio_proxy_call_reference_show (h, u, srvtype, out);
	curl_easy_cleanup (h);
	oio_url_pclean (&u);

	if (!err) {
		struct json_tokener *tok = json_tokener_new ();
		struct json_object *jbody = json_tokener_parse_ex (tok, out->str, out->len);
		if (json_tokener_success != json_tokener_get_error (tok))
			err = SYSERR("Proxy protocol error");
		else {
			struct json_object *jdir, *jsrv;
			struct oio_ext_json_mapping_s m[] = {
				{"dir",  &jdir,  json_type_array, 1},
				{"srv",  &jsrv,  json_type_array, 1},
				{NULL, NULL, 0, 0}
			};
			err = oio_ext_extract_json (jbody, m);
			if (!err && out_dir)
				err = _load_srvtab (jdir, out_dir);
			if (!err && out_srv)
				err = _load_srvtab (jsrv, out_srv);
		}
		if (jbody)
			json_object_put (jbody);
		json_tokener_free (tok);
	}
	if (out) {
		g_string_free (out, TRUE);
	}

	return err;
}

static GError *
_dir_proxy_link (struct oio_directory_s *self,
			const struct oio_url_s *url, const char *srvtype,
			gboolean autocreate, gchar ***out_srv)
{
	_DIR_FUNC_INIT

	GError *err = NULL;
	GString *out = g_string_new ("");
	struct oio_url_s *u = oio_url_dup (url);
	CURL *h = _curl_get_handle_proxy ();
	err = oio_proxy_call_reference_link (h, u, srvtype, autocreate, out);
	curl_easy_cleanup (h);
	oio_url_pclean (&u);

	if (!err) {
		struct json_tokener *tok = json_tokener_new ();
		struct json_object *jbody = json_tokener_parse_ex (tok,
				out->str, out->len);
		if (json_tokener_success != json_tokener_get_error (tok))
			err = SYSERR("Proxy protocol error");
		else
			err = _load_srvtab (jbody, out_srv);
		if (jbody)
			json_object_put (jbody);
		json_tokener_free (tok);
	}
	g_string_free (out, TRUE);

	return err;
}

static GError *
_dir_proxy_get_prop(struct oio_directory_s *self, const struct oio_url_s *url,
		on_element_f fct, void *ctx)
{
	_DIR_FUNC_INIT

	GError *err = NULL;
	GString *out = NULL;
	struct oio_url_s *u = oio_url_dup(url);
	CURL *h = _curl_get_handle_proxy();

	err = oio_proxy_call_reference_get_properties(h, u, &out);
	if (!err) {
		json_object *json = json_tokener_parse(out->str);
		json_object *props = NULL;
		if (!json_object_object_get_ex(json, "properties", &props)) {
			err = SYSERR("Malformed answer received from proxy: "
					"no 'properties' key");
		} else {
			json_object_object_foreach(props, key, val) {
				fct(ctx, key, json_object_get_string(val));
			}
		}
	}

	if (out) {
		g_string_free(out, TRUE);
	}
	curl_easy_cleanup(h);
	oio_url_pclean(&u);
	return err;
}

static GError *
_dir_proxy_set_prop(struct oio_directory_s *self, const struct oio_url_s *url,
		const char * const *values)
{
	_DIR_FUNC_INIT

	GError *err = NULL;
	struct oio_url_s *u = oio_url_dup(url);
	CURL *h = _curl_get_handle_proxy();

	err = oio_proxy_call_reference_set_properties(h, u, values);

	curl_easy_cleanup(h);
	oio_url_pclean(&u);
	return err;
}
