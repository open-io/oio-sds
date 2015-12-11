/*
OpenIO SDS metautils
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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
	return !s || !*s || !g_ascii_strcasecmp(s,"none");
}

static gboolean _is_any(const gchar *s) {
	return _is_none(s) || !g_ascii_strcasecmp(s, STORAGE_CLASS_ANY);
}

static gboolean _is_off(const gchar *s) {
	return _is_any(s) || !g_ascii_strcasecmp(s,"off");
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

static void
_data_treatments_clean(struct data_treatments_s *dt)
{
	if (!dt)
		return;

	oio_str_clean(&dt->name);
	if (NULL != dt->params)
		g_hash_table_destroy(dt->params);
	g_free(dt);
}

void
storage_class_clean(struct storage_class_s *sc)
{
	if (!sc)
		return;
	oio_str_clean(&sc->name);
	g_slist_free_full(sc->fallbacks, g_free);
	g_free(sc);
}

void
storage_class_gclean(gpointer u, gpointer ignored)
{
	(void) ignored;
	storage_class_clean((struct storage_class_s*)u);
}

void
storage_policy_clean(struct storage_policy_s *sp)
{
	if (!sp)
		return;

	oio_str_clean(&sp->name);
	if (NULL != sp->datasec)
		_data_security_clean(sp->datasec);
	if (NULL != sp->datatreat)
		_data_treatments_clean(sp->datatreat);
	if (NULL != sp->stgclass)
		storage_class_clean(sp->stgclass);
	g_free(sp);
}

void
storage_policy_gclean(gpointer u, gpointer ignored)
{
	(void) ignored;
	storage_policy_clean((struct storage_policy_s*) u);
}

/* Dummy implementations --------------------------------------------------- */

static struct storage_class_s *
_dummy_stgclass(void)
{
	struct storage_class_s *result = g_malloc0(sizeof(struct storage_class_s));
	result->name  = g_strdup(STORAGE_CLASS_ANY);
	return result;
}

static struct data_treatments_s*
_dummy_datatreat(void)
{
	struct data_treatments_s *result = g_malloc0(sizeof(struct data_treatments_s));
	result->name = g_strdup(DATA_TREATMENT_NONE);
	result->type = DT_NONE;
	result->params = _params();
	return result;
}

static struct data_security_s *
_dummy_datasec(void)
{
	struct data_security_s *result = g_malloc0(sizeof(struct data_security_s));
	result->name = g_strdup(DATA_SECURITY_NONE);
	result->type = DS_NONE;
	result->params = _params();
	return result;
}

static struct storage_policy_s*
_dummy_stgpol(void)
{
	struct storage_policy_s *result = g_malloc0(sizeof(struct storage_policy_s));
	result->name = g_strdup(STORAGE_POLICY_NONE);
	result->datasec = _dummy_datasec();
	result->datatreat = _dummy_datatreat();
	result->stgclass = _dummy_stgclass();
	return result;
}

/* Constructors & parsers -------------------------------------------------- */

static void
__fill_info(GHashTable *params, const char *info)
{
	gchar **tok = NULL;
	tok = g_strsplit(info, "|", 0);
	for (guint i = 0; i < g_strv_length(tok); i++) {
		gchar **kv = g_strsplit(tok[i], "=", 2);
		if(g_strv_length(kv) == 2) {
			g_hash_table_insert(params, g_strdup(kv[0]), g_strdup(kv[1]));
		}
		g_strfreev(kv);
	}

	g_strfreev(tok);
}

static int
_parse_data_treatments(struct data_treatments_s *dt, const char *config)
{
	gchar **tok = g_strsplit(config, ":", 2);

	if (g_strv_length(tok) != 2) {
		g_strfreev(tok);
		return 0;
	}

	if (g_str_has_prefix(tok[0], "COMP")) {
		dt->type = COMPRESSION;
	} else if (g_str_has_prefix(tok[0],"CYPHER")) {
		dt->type = CYPHER;
	} else {
		g_strfreev(tok);
		return 0;
	}

	__fill_info(dt->params, tok[1]);
	g_strfreev(tok);
	return 1;
}

static struct data_treatments_s *
_load_data_treatments(namespace_info_t *ni, const char *key)
{
	if (_is_off(key))
		return _dummy_datatreat();
	if (!ni)
		return NULL;

	gchar *config = namespace_info_get_data_treatments(ni, key);
	if (!config)
		return NULL;

	struct data_treatments_s *dt = g_malloc0(sizeof(struct data_treatments_s));
	dt->name = g_strdup(key);
	dt->params = _params();
	dt->type = DT_NONE;

	int rc = _parse_data_treatments(dt, config);
	g_free(config);
	if (rc)
		return dt;
	_data_treatments_clean(dt);
	return NULL;
}

static int
_parse_data_security(struct data_security_s *ds, const char *config)
{
	gchar **tok = g_strsplit(config, ":", 2);

	if (g_strv_length(tok) != 2) {
		g_strfreev(tok);
		return 0;
	}

	if (g_str_has_prefix(tok[0], "DUP")) {
		ds->type = DUPLI;
	} else if (g_str_has_prefix(tok[0],"RAIN")) {
		ds->type = RAIN;
	} else {
		g_strfreev(tok);
		return 0;
	}

	__fill_info(ds->params, tok[1]);
	g_strfreev(tok);
	return 1;
}

static struct data_security_s *
_load_data_security(namespace_info_t *ni, const gchar *key)
{
	if (_is_off(key))
		return _dummy_datasec();
	if (!ni)
		return NULL;

	gchar *config = namespace_info_get_data_security(ni, key);
	if (!config)
		return NULL;

	struct data_security_s *ds = g_malloc0(sizeof(struct data_security_s));
	ds->name = g_strdup(key);
	ds->type = DS_NONE;
	ds->params = _params();

	int rc = _parse_data_security(ds, config);
	g_free(config);
	if (rc)
		return ds;
	_data_security_clean(ds);
	return NULL;
}

static int
_load_storage_policy(struct storage_policy_s *sp, GByteArray *gba, namespace_info_t *ni)
{
	gchar *str = g_strndup((gchar *)gba->data, gba->len);
	gchar **tok = g_strsplit(str, ":", 3);
	g_free(str);

	int rc = (3 == g_strv_length(tok))
		&& NULL != (sp->stgclass = storage_class_init(ni, tok[0]))
		&& NULL != (sp->datasec = _load_data_security(ni, tok[1]))
		&& NULL != (sp->datatreat = _load_data_treatments(ni, tok[2]));
	g_strfreev(tok);
	return rc;
}

struct storage_class_s *
storage_class_init (struct namespace_info_s *ni, const char *name)
{
	if (_is_any (name))
		return _dummy_stgclass();
	if (!ni)
		return NULL;

	gchar *config = namespace_info_get_storage_class(ni, name);
	if (!config)
		return NULL;

	struct storage_class_s *result = g_malloc(sizeof(struct storage_class_s));
	result->name = g_strdup(name);
	gchar **fallbacks = g_strsplit(config, ":", 0);
	result->fallbacks = metautils_array_to_list((void**)fallbacks);

	g_free(fallbacks); // XXX Pointers reused !
	g_free(config);
	return result;
}

struct storage_policy_s *
storage_policy_init(namespace_info_t *ni, const char *name)
{
	if (_is_any(name))
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

/* Copy constructors ------------------------------------------------------- */

static void
__kv_dup(gpointer k, gpointer v, gpointer out)
{
	GHashTable **r = (GHashTable **) out;
	g_hash_table_insert(*r, g_strdup((gchar*)k), g_strdup((gchar*)v));
}

static GHashTable *
__copy_params(GHashTable *params)
{
	GHashTable *r = _params();
	g_hash_table_foreach(params, __kv_dup, &r);
	return r;
}

static struct data_security_s *
_data_security_dup(struct data_security_s *ds)
{
	struct data_security_s *r = NULL;

	r = g_malloc0(sizeof(struct data_security_s));
	r->type = ds->type;
	if(NULL != ds->name)
		r->name = g_strdup(ds->name);
	if(NULL != ds->params)
		r->params = __copy_params(ds->params);

	return r;
}

static struct data_treatments_s *
_data_treatments_dup(struct data_treatments_s *dt)
{
	struct data_treatments_s *r = NULL;

	r = g_malloc0(sizeof(struct data_treatments_s));
	r->type = dt->type;
	if(NULL != dt->name)
		r->name = g_strdup(dt->name);
	if(NULL != dt->params)
		r->params = __copy_params(dt->params);

	return r;
}

static struct storage_class_s *
_storage_class_dup(struct storage_class_s *sc)
{
	struct storage_class_s *copy = NULL;
	copy = g_malloc0(sizeof(struct storage_class_s));
	if (sc->name != NULL)
		copy->name = g_strdup(sc->name);

	void _dup_elm(gchar *fallback, GSList **list) {
		*list = g_slist_prepend(*list, g_strdup(fallback));
	}
	g_slist_foreach(sc->fallbacks, (GFunc)_dup_elm, &(copy->fallbacks));
	copy->fallbacks = g_slist_reverse(copy->fallbacks);
	return copy;
}

struct storage_policy_s *
storage_policy_dup(const struct storage_policy_s *sp)
{
	struct storage_policy_s *r = NULL;

	if(!sp)
		return NULL;

	r = g_malloc0(sizeof(struct storage_policy_s));

	if (NULL != sp->name)
		r->name = g_strdup(sp->name);
	if (NULL != sp->stgclass)
		r->stgclass = _storage_class_dup(sp->stgclass);
	if (NULL != sp->datasec)
		r->datasec = _data_security_dup(sp->datasec);
	if (NULL != sp->datatreat)
		r->datatreat = _data_treatments_dup(sp->datatreat);

	return r;
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

const struct data_treatments_s *
storage_policy_get_data_treatments(const struct storage_policy_s *sp)
{
	return (NULL != sp) ? sp->datatreat : NULL;
}

const struct storage_class_s *
storage_policy_get_storage_class(const struct storage_policy_s *sp)
{
	return (NULL != sp) ? sp->stgclass : NULL;
}

const gchar *
data_security_get_name(const struct data_security_s *ds)
{
	return (NULL != ds) ? ds->name : NULL;
}

enum data_security_e
data_security_get_type(const struct data_security_s *ds)
{
	return (NULL != ds) ? ds->type : DS_NONE;
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

const gchar *
data_security_type_name(enum data_security_e type)
{
	switch (type) {
		case DUPLI:
			return "DUPLI";
		case RAIN:
			return "RAIN";
		case DS_NONE:
		default:
			return "NONE";
	}
}

enum data_treatments_e
data_treatments_get_type(const struct data_treatments_s *ds)
{
	if (NULL != ds)
		return ds->type;
	return DT_NONE;
}

const char *
data_treatments_get_param(const struct data_treatments_s *dt, const char *key)
{
	if(NULL != dt && NULL != dt->params)
		return g_hash_table_lookup(dt->params, key);

	return NULL;
}

const gchar *
storage_class_get_name(const struct storage_class_s *sc)
{
	return (sc != NULL)? sc->name : NULL;
}

const GSList *
storage_class_get_fallbacks(const struct storage_class_s *sc)
{
	return (sc != NULL)? sc->fallbacks : NULL;
}

gboolean
storage_class_is_satisfied(const gchar *wsc, const gchar *asc)
{
	return _is_any(wsc) || (asc && !g_ascii_strcasecmp(wsc, asc));
}

gboolean
storage_class_is_satisfied2(const struct storage_class_s *wsc,
		const gchar *asc, gboolean strict)
{
	if (wsc == NULL || storage_class_is_satisfied(wsc->name, asc))
		return TRUE;
	if (strict)
		return FALSE;

	for (GSList *l = wsc->fallbacks; l != NULL ; l = l->next) {
		if (!l->data)
			continue;
		if (storage_class_is_satisfied((gchar*)l->data, asc))
			return TRUE;
	}
	return FALSE;
}

GError *
storage_policy_check_compat_by_name(namespace_info_t *ni,
		const gchar *old_stgpol, const gchar *new_stgpol)
{
	GError *err = NULL;
	struct storage_policy_s *old = storage_policy_init(ni, old_stgpol);
	struct storage_policy_s *new = storage_policy_init(ni, new_stgpol);

	err = storage_policy_check_compat(old, new);

	storage_policy_clean(old);
	storage_policy_clean(new);
	return err;
}

GError *
storage_policy_check_compat(struct storage_policy_s *old,
		struct storage_policy_s *new)
{
	GError *err = NULL;
	const struct data_security_s *old_dsec = storage_policy_get_data_security(old);
	const struct data_security_s *new_dsec = storage_policy_get_data_security(new);

	if ((!old_dsec || old_dsec->type == DS_NONE || old_dsec->type == DUPLI) &&
			(!new_dsec || new_dsec->type == DS_NONE || new_dsec->type == DUPLI)) {
		/* OK, we have to adjust copy count, stgclass or distance,
		 * and we can do that with policycheck. */
		return err;
	} else if (old_dsec->type == RAIN && new_dsec->type == RAIN) {
		gint64 old_k, new_k, old_m, new_m;
		const gchar *old_algo, *new_algo;
		old_k = data_security_get_int64_param(old_dsec, DS_KEY_K, 1);
		new_k = data_security_get_int64_param(new_dsec, DS_KEY_K, 1);
		old_m = data_security_get_int64_param(old_dsec, DS_KEY_M, 1);
		new_m = data_security_get_int64_param(new_dsec, DS_KEY_M, 1);
		old_algo = data_security_get_param(old_dsec, DS_KEY_ALGO);
		new_algo = data_security_get_param(new_dsec, DS_KEY_ALGO);
		if (old_algo == NULL || new_algo == NULL ||
				g_ascii_strcasecmp(old_algo, new_algo) != 0) {
			/* Even if they share same k and m, parity chunks are incompatible,
			 * and policycheck won't detect the problem. */
			err = NEWERROR(CODE_NOT_IMPLEMENTED,
					"different RAIN algorithm (%s vs %s)", old_algo, new_algo);
		} else if (old_k != new_k) {
			err = NEWERROR(CODE_NOT_IMPLEMENTED,
					"different number of RAIN data chunks (%ld vs %ld)",
					old_k, new_k);
		} else if (old_m != new_m) {
			err = NEWERROR(CODE_NOT_IMPLEMENTED,
					"different number of RAIN parity chunks (%ld vs %ld)",
					old_m, new_m);
		} else {
			/* Only case supported at the moment: a change in distance */
		}
	} else {
		/* RAIN chunks are not the same as DUPLI chunks,
		 * content must be reuploaded. */
		err = NEWERROR(CODE_NOT_IMPLEMENTED,
				"different type of data security (incompatible chunks): %s vs %s",
				data_security_type_name(data_security_get_type(old_dsec)),
				data_security_type_name(data_security_get_type(new_dsec)));
	}

	if (err != NULL) {
		g_prefix_error(&err,
				"Impossible to change data security from %s to %s, "
				"you must re-upload content: ",
				data_security_get_name(old_dsec),
				data_security_get_name(new_dsec));
		GRID_DEBUG("%s", err->message);
	}
	return err;
}

static GString *
_rain_policy_to_chunk_method(const struct data_security_s *datasec) {
	GString *result = g_string_new("plain/rain?");

	gint64 k = data_security_get_int64_param(datasec, DS_KEY_K, 0);
	gint64 m = data_security_get_int64_param(datasec, DS_KEY_M, 0);
	const char *algo = data_security_get_param(datasec, DS_KEY_ALGO);

	g_string_append_printf(result, "algo=%s&k=%" G_GINT64_FORMAT
			"&m=%" G_GINT64_FORMAT, algo, k, m);

	return result;
}

GString *
storage_policy_to_chunk_method(const struct storage_policy_s *sp)
{
	const struct data_security_s *datasec = storage_policy_get_data_security(sp);

	switch (data_security_get_type(datasec)) {
		case RAIN:
			return _rain_policy_to_chunk_method(datasec);
		case DS_NONE:
		case DUPLI:
			return g_string_new("plain/bytes");
		default:
			g_assert_not_reached();
	}
}
