/*
OpenIO SDS metautils
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#include "metautils.h"

#include "storage_policy_internals.h"

static GHashTable * _params (void) {
	return g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
}

static gboolean _is_none(const gchar *s) {
	return !oio_str_is_set(s) || !g_ascii_strcasecmp(s,"none");
}

static gboolean _is_plain(const gchar *s) {
	return _is_none(s) || !g_ascii_strcasecmp(s, STGPOL_DSPREFIX_PLAIN);
}

/* Destructors ------------------------------------------------------------- */

static void
_data_security_clean(struct data_security_s *ds)
{
	if (!ds)
		return;

	oio_str_clean(&ds->name);
	if (NULL != ds->params)
		g_hash_table_destroy(ds->params);
	g_free(ds);
}

void
storage_policy_clean(struct storage_policy_s *sp)
{
	if (!sp)
		return;

	oio_str_clean(&sp->name);
	if (NULL != sp->datasec)
		_data_security_clean(sp->datasec);
	if (sp->service_pool) {
		g_free(sp->service_pool);
		sp->service_pool = NULL;
	}
	g_free(sp);
}

/* Dummy implementations --------------------------------------------------- */

static struct data_security_s *
_dummy_datasec(void)
{
	struct data_security_s *result = g_malloc0(sizeof(struct data_security_s));
	result->name = g_strdup(STGPOL_DSPREFIX_PLAIN);
	result->type = STGPOL_DS_PLAIN;
	result->params = _params();
	return result;
}

static struct storage_policy_s*
_dummy_stgpol(void)
{
	struct storage_policy_s *result = g_malloc0(sizeof(struct storage_policy_s));
	result->name = g_strdup(STORAGE_POLICY_NONE);
	result->datasec = _dummy_datasec();
	result->service_pool = g_strdup(NAME_SRVTYPE_RAWX);
	return result;
}

/* Constructors & parsers -------------------------------------------------- */

static void
__fill_info(GHashTable *params, const char *info)
{
	gchar **tok = g_strsplit_set(info, "|,", 0);
	if (!tok)
		return;

	const guint max = g_strv_length(tok);
	for (guint i = 0; i < max; i++) {
		gchar **kv = g_strsplit(tok[i], "=", 2);
		if (kv) {
			if (kv[0] && kv[1])
				g_hash_table_insert(params, g_strdup(kv[0]), g_strdup(kv[1]));
			g_strfreev(kv);
		}
	}

	g_strfreev(tok);
}

static int
_parse_data_security(struct data_security_s *ds, const char *config)
{
	if (oio_str_prefixed (config, STGPOL_DSPREFIX_PLAIN, "/")) {
		ds->type = STGPOL_DS_PLAIN;
	} else if (oio_str_prefixed (config, "ec", "/")) {
		ds->type = STGPOL_DS_EC;
	} else {
		return 0;
	}

	gchar **tok = g_strsplit(config, "/", 2);
	if (tok[1])
		__fill_info(ds->params, tok[1]);
	g_strfreev(tok);
	return 1;
}

static gchar *
_load_service_pool(const gchar *sp_name, const gchar *key)
{
	if (!key || !key[0] ||
			!g_ascii_strcasecmp(key, STORAGE_POLICY_NONE)) {
		return g_strdup(sp_name);
	}
	return g_strdup(key);
}

static struct data_security_s *
_load_data_security(namespace_info_t *ni, const gchar *key)
{
	if (_is_plain(key))
		return _dummy_datasec();
	if (!ni)
		return NULL;

	gchar *config = namespace_info_get_data_security(ni, key);
	if (!config)
		return NULL;

	struct data_security_s *ds = g_malloc0(sizeof(struct data_security_s));
	ds->name = g_strdup(key);
	ds->type = STGPOL_DS_PLAIN;
	ds->params = _params();

	int rc = _parse_data_security(ds, config);
	g_free(config);
	if (rc)
		return ds;
	_data_security_clean(ds);
	return NULL;
}

static int
_load_storage_policy(struct storage_policy_s *sp, GByteArray *gba,
		namespace_info_t *ni)
{
	gchar *str = g_strndup((gchar *)gba->data, gba->len);
	gchar **tok = g_strsplit(str, ":", 3);
	g_free(str);

	if (!tok)
		return 0;
	int rc = (2 == g_strv_length(tok))
		&& NULL != (sp->service_pool = _load_service_pool(sp->name, tok[0]))
		&& NULL != (sp->datasec = _load_data_security(ni, tok[1]));
	g_strfreev(tok);
	return rc;
}

struct storage_policy_s *
storage_policy_init(namespace_info_t *ni, const char *name)
{
	if (_is_plain(name))
		return _dummy_stgpol();
	if (!ni)
		return NULL;

	GByteArray *gba = NULL;
	struct storage_policy_s *sp = g_malloc0(sizeof(struct storage_policy_s));
	sp->name = g_strdup(name);

	gba = g_hash_table_lookup(ni->storage_policy, name);
	if (gba == NULL) {
		/* set dirty flag, don't allow any getter */
		storage_policy_clean(sp);
		return NULL;
	}
	if (!_load_storage_policy(sp, gba, ni)) {
		/* set dirty flag, don't allow any getter */
		storage_policy_clean(sp);
		return NULL;
	}

	return sp;
}

/* Various getters --------------------------------------------------------- */

const char *
storage_policy_get_name(const struct storage_policy_s *sp)
{
	return (NULL != sp) ? sp->name : NULL;
}

const struct data_security_s *
storage_policy_get_data_security(const struct storage_policy_s *sp)
{
	return (NULL != sp) ? sp->datasec : NULL;
}

const gchar *
storage_policy_get_service_pool(const struct storage_policy_s *sp)
{
	return (NULL != sp) ? sp->service_pool : NULL;
}

enum data_security_e
data_security_get_type(const struct data_security_s *ds)
{
	return (NULL != ds) ? ds->type : STGPOL_DS_PLAIN;
}

const char *
data_security_get_param(const struct data_security_s *ds, const char *key)
{
	if (ds && ds->params)
		return g_hash_table_lookup(ds->params, key);

	return NULL;
}

gint64
data_security_get_int64_param(const struct data_security_s *ds, const char *key,
		gint64 def)
{
	const gchar *str_val = data_security_get_param(ds, key);
	gchar *end = NULL;
	gint64 res = 0;
	if (str_val == NULL)
		return def;
	res = g_ascii_strtoll(str_val, &end, 10);
	if (end == str_val)
		return def;
	return res;
}

static GString *
_ec_policy_to_chunk_method(const struct data_security_s *datasec)
{
	GString *result = g_string_sized_new(64);

	const gint64 k = data_security_get_int64_param(datasec, DS_KEY_K, 6);
	const gint64 m = data_security_get_int64_param(datasec, DS_KEY_M, 4);
	const char *algo = data_security_get_param(datasec, DS_KEY_ALGO);

	g_string_append_printf(result,
			"ec/algo=%s,k=%" G_GINT64_FORMAT",m=%" G_GINT64_FORMAT,
			algo, k, m);

	return result;
}

static GString *
_plain_policy_to_chunk_method(const struct data_security_s *datasec)
{
	GString *result = g_string_sized_new(32);

	const gint64 nb_copy = data_security_get_int64_param(datasec, DS_KEY_COPY_COUNT, 1);

	g_string_append_printf(result,
			"plain/nb_copy=%" G_GINT64_FORMAT"",
			nb_copy);

	return result;
}

GString *
storage_policy_to_chunk_method(const struct storage_policy_s *sp)
{
	const struct data_security_s *datasec = storage_policy_get_data_security(sp);
	switch (data_security_get_type(datasec)) {
		case STGPOL_DS_EC:
			return _ec_policy_to_chunk_method(datasec);
		case STGPOL_DS_PLAIN:
			return _plain_policy_to_chunk_method(datasec);
		default:
			g_assert_not_reached();
	}
}

gint64
storage_policy_get_nb_chunks(const struct storage_policy_s *sp)
{
	const struct data_security_s *dsec = storage_policy_get_data_security(sp);
	switch (data_security_get_type(dsec)) {
		case STGPOL_DS_EC:
			return (data_security_get_int64_param(dsec, DS_KEY_K, 6)
					+ data_security_get_int64_param(dsec, DS_KEY_M, 4));
		case STGPOL_DS_PLAIN:
		default:
			return data_security_get_int64_param(dsec, DS_KEY_COPY_COUNT, 1);
	}
}

gint64
storage_policy_get_distance(const struct storage_policy_s *sp)
{
	const struct data_security_s *dsec = storage_policy_get_data_security(sp);
	/* DS_KEY_DISTANCE was the original keyword,
	 * DS_KEY_MIN_DIST was introduced with service pools. */
	gint64 min_dist = data_security_get_int64_param(dsec, DS_KEY_DISTANCE, 1);
	return data_security_get_int64_param(dsec, DS_KEY_MIN_DIST, min_dist);
}

gint64
storage_policy_get_warn_dist(const struct storage_policy_s *sp)
{
	const struct data_security_s *dsec = storage_policy_get_data_security(sp);
	return data_security_get_int64_param(dsec, DS_KEY_WARN_DIST, 0);
}
