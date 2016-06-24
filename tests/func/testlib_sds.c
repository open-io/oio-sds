/*
OpenIO SDS core library
Copyright (C) 2015-2016 OpenIO, as part of OpenIO Software Defined Storage

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

#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <json.h>

#include <core/oiolog.h>
#include <core/oiourl.h>
#include <core/oio_sds.h>
#include <core/internals.h>

void setup (void);
void test_init (const char *strcfg, const char *ns);
void test_has (const char *strcfg, const char *ns, const char *url);
void test_has_not (const char *strcfg, const char *ns, const char *url);
void test_has_fail (const char *strcfg, const char *ns, const char *url);
void test_get_fail (const char *strcfg, const char *ns, const char *url);
void test_get_success (const char *strcfg, const char *ns, const char *url,
		size_t count);

void test_list_badarg (const char *strcfg, const char *ns);
void test_list_fail (const char *strcfg, const char *ns, const char *url);
void test_list_success_count (const char *strcfg, const char *ns,
		const char *strurl, unsigned int count,
		const char *prefix, const char *marker, const char *end,
		unsigned int max);

/* -------------------------------------------------------------------------- */

struct oio_FAKE_s
{
	struct oio_cfg_handle_vtable_s *vtable;
	GTree *values;
};

static void _fake_cfg_clean (struct oio_cfg_handle_s *cfg);
static gchar ** _fake_cfg_namespaces (struct oio_cfg_handle_s *cfg0);
static gchar * _fake_cfg_get (struct oio_cfg_handle_s *cfg, const char *ns, const char *k);

struct oio_cfg_handle_vtable_s VTABLE =
{
	_fake_cfg_clean,
	_fake_cfg_namespaces,
	_fake_cfg_get
};

static gint
_strcmp3 (gconstpointer p0, gconstpointer p1, gpointer i)
{
	(void) i;
	return g_strcmp0 ((gchar*)p0, (gchar*)p1);
}

#define ASSERT_FAKE(C) do {\
	g_assert ((C) != NULL); \
	g_assert (((struct oio_cfg_handle_abstract_s*)(C))->vtable == &VTABLE); \
} while (0)

static void
_fake_cfg_clean (struct oio_cfg_handle_s *cfg0)
{
	ASSERT_FAKE (cfg0);
	struct oio_FAKE_s *cfg = (struct oio_FAKE_s*) cfg0;
	g_tree_destroy (cfg->values);
	g_free (cfg);
}

static gchar **
_fake_cfg_namespaces (struct oio_cfg_handle_s *cfg0)
{
	ASSERT_FAKE (cfg0);
	struct oio_FAKE_s *cfg = (struct oio_FAKE_s*) cfg0;

	GTree *tmp = g_tree_new_full (_strcmp3, NULL, g_free, NULL);
	gboolean _run (gchar *k, gchar *v, gpointer i) {
		(void) v, (void) i;
		gchar *slash = strchr(k, '/');
		g_tree_replace (tmp, g_strndup (k, slash-k), GUINT_TO_POINTER(1));
		return FALSE;
	}
	g_tree_foreach (cfg->values, (GTraverseFunc)_run, NULL);

	gchar **items = g_malloc0 ((1 + g_tree_nnodes(cfg->values)) * sizeof(gchar*));
	g_tree_foreach (cfg->values, (GTraverseFunc)_run, NULL);

	g_tree_destroy (tmp);
	return items;
}

static gchar *
_fake_cfg_get (struct oio_cfg_handle_s *cfg0, const char *ns, const char *k)
{
	ASSERT_FAKE (cfg0);
	struct oio_FAKE_s *cfg = (struct oio_FAKE_s*) cfg0;

	gchar *p = g_strconcat (ns, "/", k, NULL);
	gchar *v = g_tree_lookup (cfg->values, p);
	g_free (p);
	return (!v) ? NULL : g_strdup(v);
}

static struct oio_cfg_handle_s *
_build_fake_config (const char *strcfg)
{
	g_assert_nonnull (strcfg);

	struct oio_FAKE_s *cfg = g_malloc0 (sizeof(*cfg));
	cfg->vtable = &VTABLE;
	cfg->values = g_tree_new_full (_strcmp3, NULL, g_free, g_free);

	struct json_tokener *tok = json_tokener_new ();
	g_assert_nonnull (tok);
	struct json_object *jall = json_tokener_parse_ex (tok, strcfg, strlen(strcfg));
	g_assert_nonnull (jall);
	json_object_object_foreach (jall, ns, jcfg) {
		g_assert_nonnull (ns);
		g_assert_nonnull (jcfg);
		g_assert (json_object_is_type (jcfg, json_type_object));
		json_object_object_foreach (jcfg, k, jv) {
			g_assert (json_object_is_type (jv, json_type_string));
			g_tree_replace (cfg->values, g_strconcat(ns, "/", k, NULL),
					g_strdup(json_object_get_string(jv)));
		}
	}
	json_object_put (jall);
	json_tokener_free (tok);

	return (struct oio_cfg_handle_s*) cfg;
}

/* -------------------------------------------------------------------------- */

static void
_test_wrap (const char *strcfg, const char *ns,
		void (*hook) (struct oio_sds_s *))
{
	g_printerr("\r\n");
	struct oio_cfg_handle_s *cfg = _build_fake_config (strcfg);
	oio_cfg_set_handle (cfg);

	struct oio_sds_s *sds = NULL;
	struct oio_error_s *err = oio_sds_init (&sds, ns);
	g_assert_no_error ((GError*)err);
	g_assert_nonnull (sds);

	hook(sds);

	oio_sds_pfree (&sds);
	g_assert_null (sds);
	oio_cfg_set_handle (NULL);
	oio_cfg_handle_clean (cfg);
}

static void
_test_wrap_url (const char *strcfg, const char *ns, const char *strurl,
		void (*hook) (struct oio_sds_s *, struct oio_url_s *))
{
	void _h0 (struct oio_sds_s *sds) {
		struct oio_url_s *url = oio_url_init (strurl);
		g_assert_nonnull (url);
		hook (sds, url);
		oio_url_pclean (&url);
	}
	_test_wrap (strcfg, ns, _h0);
}

/* -------------------------------------------------------------------------- */

void
setup (void)
{
	oio_log_to_stderr();
	oio_sds_default_autocreate = 1;
	oio_sds_no_shuffle = 1;
	for (int i=0; i<6 ;i++)
		oio_log_more ();
}

void
test_init (const char *strcfg, const char *ns)
{
	void _hook (struct oio_sds_s *sds) { (void) sds; /* NO-OP */ }
	_test_wrap (strcfg, ns, _hook);
}

void
test_has (const char *strcfg, const char *ns, const char *strurl)
{
	void _hook (struct oio_sds_s *sds, struct oio_url_s *url) {
		int has = 0;
		struct oio_error_s *err = oio_sds_has (sds, url, &has);
		g_assert_no_error ((GError*)err);
		g_assert (has != 0);
	}
	_test_wrap_url (strcfg, ns, strurl, _hook);
}

void
test_has_not (const char *strcfg, const char *ns, const char *strurl)
{
	void _hook (struct oio_sds_s *sds, struct oio_url_s *url) {
		int has = 0;
		struct oio_error_s *err = oio_sds_has (sds, url, &has);
		g_assert_no_error ((GError*)err);
		g_assert (has == 0);
	}
	_test_wrap_url (strcfg, ns, strurl, _hook);
}

void
test_has_fail (const char *strcfg, const char *ns, const char *strurl)
{
	void _hook (struct oio_sds_s *sds, struct oio_url_s *url) {
		int has = 0;
		struct oio_error_s *err = oio_sds_has (sds, url, &has);
		g_assert (has == 0);
		g_assert (NULL != err);
	}
	_test_wrap_url (strcfg, ns, strurl, _hook);
}

static gint
_count (void *i, const unsigned char *b, size_t l)
{
	(void) b;
	*((size_t*)i) += l;
	return l;
}

void
test_get_fail (const char *strcfg, const char *ns, const char *strurl)
{
	size_t total = 0;
	void _hook (struct oio_sds_s *sds, struct oio_url_s *url) {
		struct oio_sds_dl_src_s src = { .url = url, .ranges = NULL };
		struct oio_sds_dl_dst_s dst = {
			.type = OIO_DL_DST_HOOK_SEQUENTIAL,
			.data = { .hook = {
				.cb = _count,
				.ctx = &total,
				.length = (size_t)-1,
			} }
		};
		struct oio_error_s *err = oio_sds_download (sds, &src, &dst);
		g_assert (NULL != err);
	}
	_test_wrap_url (strcfg, ns, strurl, _hook);
}

void
test_get_success (const char *strcfg, const char *ns, const char *strurl,
		size_t count)
{
	size_t total = 0;
	void _hook (struct oio_sds_s *sds, struct oio_url_s *url) {
		struct oio_sds_dl_src_s src = { .url = url, .ranges = NULL };
		struct oio_sds_dl_dst_s dst = {
			.type = OIO_DL_DST_HOOK_SEQUENTIAL,
			.data = { .hook = {
				.cb = _count,
				.ctx = &total,
				.length = (size_t)-1,
			} }
		};
		struct oio_error_s *err = oio_sds_download (sds, &src, &dst);
		g_assert_no_error ((GError*)err);
		g_assert (total == count);
	}
	_test_wrap_url (strcfg, ns, strurl, _hook);
}

void
test_list_badarg (const char *strcfg, const char *ns)
{
	void _hook (struct oio_sds_s *sds) {
		struct oio_sds_list_param_s param = {0};
		struct oio_sds_list_listener_s listener = {0};
		struct oio_error_s *err = NULL;

		err = oio_sds_list (sds, NULL, NULL);
		g_assert_nonnull (err);
		err = oio_sds_list (sds, &param, NULL);
		g_assert_nonnull (err);
		err = oio_sds_list (sds, NULL, &listener);
		g_assert_nonnull (err);
		err = oio_sds_list (sds, &param, &listener);
		g_assert_nonnull (err);
	}
	_test_wrap (strcfg, ns, _hook);
}

void
test_list_fail (const char *strcfg, const char *ns, const char *strurl)
{
	void _hook (struct oio_sds_s *sds, struct oio_url_s *url) {
		struct oio_sds_list_param_s param = {0};
		struct oio_sds_list_listener_s listener = {0};
		struct oio_error_s *err = NULL;

		param.url = url;

		err = oio_sds_list (sds, &param, &listener);
		g_assert_nonnull (err);
	}
	_test_wrap_url (strcfg, ns, strurl, _hook);
}

void
test_list_success_count (const char *strcfg, const char *ns,
		const char *strurl, unsigned int count,
		const char *prefix, const char *marker, const char *end,
		unsigned int max)
{
	size_t count_items = 0;
	int _hook_item (void *ctx, const struct oio_sds_list_item_s *item) {
		(void) ctx, (void) item;
		GRID_DEBUG("item %s", item->name);
		count_items ++;
		return 0;
	}
	void _hook (struct oio_sds_s *sds, struct oio_url_s *url) {
		GRID_DEBUG("TEST LIST ns=%s count=%u prefix=%s marker=%s end=%s max=%u",
				ns, count, prefix, marker, end, max);
		struct oio_sds_list_param_s param = {0};
		struct oio_sds_list_listener_s listener = {0};
		struct oio_error_s *err = NULL;

		param.url = url;
		param.prefix = prefix;
		param.marker = marker;
		param.end = end;
		param.max_items = max;
		listener.on_item = _hook_item;

		err = oio_sds_list (sds, &param, &listener);
		g_assert_no_error ((GError*)err);
	}
	_test_wrap_url (strcfg, ns, strurl, _hook);
	g_assert_cmpuint (count_items, ==, count);
}

