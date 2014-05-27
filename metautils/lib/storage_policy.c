#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.stgpol"
#endif

#include "metautils_macros.h"
#include "metautils_errors.h"
#include "metautils_loggers.h"
#include "metatypes.h"
#include "metatype_nsinfo.h"
#include "storage_policy.h"


struct data_security_s
{
	gchar *name;
	enum data_security_e type;
	GHashTable *params;
};

struct data_treatments_s
{
	gchar *name;
	enum data_treatments_e type;
	GHashTable *params;
};

struct storage_class_s
{
	gchar *name;
	GSList *fallbacks;
};

struct storage_policy_s
{
	gchar *name;
	struct data_security_s *datasec;
	struct data_treatments_s *datatreat;
	struct storage_class_s *stgclass;
};

/***********************************************************/

static void
_data_security_clean(struct data_security_s *ds)
{
	if (!ds)
		return;

	if (NULL != ds->name)
		g_free(ds->name);

	if (NULL != ds->params)
		g_hash_table_destroy(ds->params);

	g_free(ds);
}

static void
_data_treatments_clean(struct data_treatments_s *dt)
{
	if (!dt)
		return;

	if (NULL != dt->name)
		g_free(dt->name);

	if (NULL != dt->params)
		g_hash_table_destroy(dt->params);

	g_free(dt);
}

static void
_storage_class_clean(struct storage_class_s *sc)
{
	if (!sc)
		return;
	if (sc->name != NULL)
		g_free(sc->name);
	sc->name = NULL;
	g_slist_free_full(sc->fallbacks, g_free);
	g_free(sc);
}

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
_parse_data_treatments(struct storage_policy_s *sp, const char *str)
{
	gchar **tok = NULL;
	tok = g_strsplit(str, ":", 2);
	if(g_strv_length(tok) != 2) {
		g_strfreev(tok);
		return 0;
	}

	if (g_str_has_prefix(tok[0], "COMP")) {
		sp->datatreat->type = COMPRESSION;
	} else if (g_str_has_prefix(tok[0],"CYPHER")) {
		sp->datasec->type = CYPHER;
	} else {
		g_strfreev(tok);
		return 0;
	}
	sp->datatreat->params = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	__fill_info(sp->datatreat->params, tok[1]);
	g_strfreev(tok);
	return 1;
}

static int
_parse_data_security(struct storage_policy_s *sp, const char *str)
{
	gchar **tok = NULL;
	tok = g_strsplit(str, ":", 2);
	if(g_strv_length(tok) != 2) {
		g_strfreev(tok);
		return 0;
	}

	if (g_str_has_prefix(tok[0], "DUP")) {
		sp->datasec->type = DUPLI;
	} else if (g_str_has_prefix(tok[0],"RAIN")) {
		sp->datasec->type = RAIN;
	} else {
		g_strfreev(tok);
		return 0;
	}
	sp->datasec->params = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	__fill_info(sp->datasec->params, tok[1]);
	g_strfreev(tok);
	return 1;
}

/**
 * Parse the storage class fallback list.
 *
 * @param sp The storage policy object to put parsed data into
 * @param str The raw storage class string to parse (storage classes
 *   separated by ':')
 * @return 1 in case of success
 */
static int
_parse_storage_class(struct storage_policy_s *sp, const char *str)
{
	if (str == NULL) {
		return 1; // No fallback
	}
	gchar **tok = NULL;
	tok = g_strsplit(str, ":", 0);
	for (gchar **tok2 = tok; tok2 && *tok2; tok2++) {
		sp->stgclass->fallbacks = g_slist_prepend(sp->stgclass->fallbacks,
				g_strdup(*tok));
	}
	sp->stgclass->fallbacks = g_slist_reverse(sp->stgclass->fallbacks);
	g_strfreev(tok);
	return 1;
}

static int
_load_data_security(struct storage_policy_s *sp, const char *key, namespace_info_t *ni)
{
	int status = 0;
	gchar *datasec = NULL;

	sp->datasec = g_malloc0(sizeof(struct data_security_s));
	sp->datasec->name = g_strdup(key);

	if ((0 == g_ascii_strcasecmp(key, "NONE")) || (0 == g_ascii_strcasecmp(key, "OFF"))) {
		sp->datasec->type = DS_NONE;
		return 1;
	}

	datasec = namespace_info_get_data_security(ni, key);
	if (datasec == NULL) {
		return 0;
	}

	status = _parse_data_security(sp, datasec);

	g_free(datasec);

	return status;
}

static int
_load_data_treatments(struct storage_policy_s *sp, const char *key, namespace_info_t *ni)
{
	int status = 0;
	gchar *datatreat = NULL;

	sp->datatreat = g_malloc0(sizeof(struct data_treatments_s));
	sp->datatreat->name = g_strdup(key);

	if ((0 == g_ascii_strcasecmp(key, "NONE")) || (0 == g_ascii_strcasecmp(key, "OFF"))) {
		sp->datatreat->type = DT_NONE;
		return 1;
	}

	datatreat = namespace_info_get_data_treatments(ni, key);
	if (datatreat == NULL) {
		return 0;
	}

	status = _parse_data_treatments(sp, datatreat);

	g_free(datatreat);
	return status;
}

static int
_load_storage_class(struct storage_policy_s *sp, const char *key, namespace_info_t *ni)
{
	int status = 0;
	gchar *stgclass_str = NULL;
	sp->stgclass = g_malloc0(sizeof(struct storage_class_s));
	sp->stgclass->name = g_strdup(key);

	stgclass_str = namespace_info_get_storage_class(ni, key);
	status = _parse_storage_class(sp, stgclass_str);

	g_free(stgclass_str);
	return status;
}

static int
_load_storage_policy(struct storage_policy_s *sp, GByteArray *gba, namespace_info_t *ni)
{
	gchar *str = NULL;
	gchar **tok = NULL;
	str = g_strndup((gchar *)gba->data, gba->len);
	tok = g_strsplit(str, ":", 3);
	g_free(str);

	if(g_strv_length(tok) != 3) {
		goto error_label;
	}

	if (!_load_storage_class(sp, tok[0], ni)) {
		goto error_label;
	}

	if (!_load_data_security(sp, tok[1], ni)) {
		goto error_label;
	}

	if (!_load_data_treatments(sp, tok[2], ni)) {
		goto error_label;
	}

	g_strfreev(tok);
	return 1;

error_label:
	g_strfreev(tok);
	return 0;
}

static void
__kv_dup(gpointer k, gpointer v, gpointer out)
{
	GHashTable **r = (GHashTable **) out;
	g_hash_table_insert(*r, g_strdup((gchar*)k), g_strdup((gchar*)v));
}

static GHashTable *
__copy_params(GHashTable *params)
{
	GHashTable *r = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	g_hash_table_foreach(params, __kv_dup, &r);

	return r;
}

static struct data_security_s *
_data_security_dup(struct data_security_s *ds)
{
	struct data_security_s *r = NULL;

	r = g_malloc0(sizeof(struct data_security_s));

	if(NULL != ds->name)
		r->name = g_strdup(ds->name);
	r->type = ds->type;
	if(NULL != ds->params)
		r->params = __copy_params(ds->params);

	return r;
}

static struct data_treatments_s *
_data_treatments_dup(struct data_treatments_s *dt)
{
	struct data_treatments_s *r = NULL;

	r = g_malloc0(sizeof(struct data_treatments_s));

	if(NULL != dt->name)
		r->name = g_strdup(dt->name);
	r->type = dt->type;
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
	else
		copy->name = NULL;

	void _dup_elm(gchar *fallback, GSList **list) {
		*list = g_slist_prepend(*list, g_strdup(fallback));
	}
	g_slist_foreach(sc->fallbacks, (GFunc)_dup_elm, &(copy->fallbacks));
	copy->fallbacks = g_slist_reverse(copy->fallbacks);
	return copy;
}

/* ------------------------------------------------------------------------- */

static struct storage_class_s *
_dummy_stgclass(void)
{
	struct storage_class_s *result = g_malloc0(sizeof(struct storage_class_s));
	result->name  = g_strdup(DUMMY_STORAGE_CLASS);
	return result;
}

static struct data_treatments_s*
_dummy_datatreat(void)
{
	struct data_treatments_s *result = g_malloc0(sizeof(struct data_treatments_s));
	result->name = g_strdup("none");
	result->type = DT_NONE;
	result->params = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	return result;
}

static struct data_security_s *
_dummy_datasec(void)
{
	struct data_security_s *result = g_malloc0(sizeof(struct data_security_s));
	result->name = g_strdup("none");
	result->type = DS_NONE;
	result->params = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	return result;
}

static struct storage_policy_s*
_dummy_stgpol(void)
{
	struct storage_policy_s *result = g_malloc0(sizeof(struct storage_policy_s));
	result->name = g_strdup("none");
	result->datasec = _dummy_datasec();
	result->datatreat = _dummy_datatreat();
	result->stgclass = _dummy_stgclass();
	return result;
}

struct storage_policy_s *
storage_policy_init(namespace_info_t *ni, const char *name)
{
	if (!name || !g_ascii_strcasecmp(name, "none"))
		return _dummy_stgpol();

	/* sanity check */
	if (!ni)
		return NULL;

	GByteArray *gba = NULL;
	struct storage_policy_s *sp = NULL;
	sp = g_malloc0(sizeof(struct storage_policy_s));
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

void storage_policy_clean(struct storage_policy_s *sp)
{
	if (!sp)
		return;

	if (NULL != sp->name)
		g_free(sp->name);

	if (NULL != sp->datasec) {
		_data_security_clean(sp->datasec);
		sp->datasec = NULL;
	}

	if (NULL != sp->datatreat) {
		_data_treatments_clean(sp->datatreat);
		sp->datatreat = NULL;
	}

	if (NULL != sp->stgclass) {
		_storage_class_clean(sp->stgclass);
		sp->stgclass = NULL;
	}

	g_free(sp);
}

void storage_policy_gclean(gpointer u, gpointer ignored)
{
	(void) ignored;
	storage_policy_clean((struct storage_policy_s*) u);
}

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
	GRID_TRACE("Wanted storage class: %s, got %s", wsc, asc);

	/* NULL or DUMMY wanted -> always OK */
	if (wsc == NULL || !g_ascii_strcasecmp(wsc, DUMMY_STORAGE_CLASS)) {
		return TRUE;
	}
	/* Specific class wanted and no class defined -> KO */
	if (asc == NULL) {
		return FALSE;
	}
	/* Do an exact match of storage class (case insensitive) */
	return (g_ascii_strcasecmp(wsc, asc) == 0);
}

gboolean
storage_class_is_satisfied2(const struct storage_class_s *wsc,
		const gchar *asc, gboolean strict)
{
	GRID_TRACE("Wanted storage class (%s): %s, got %s",
		strict ? "strictly" : "lazily", wsc? wsc->name : NULL, asc);

	if (wsc == NULL || storage_class_is_satisfied(wsc->name, asc)) {
		return TRUE;
	} else if (strict) {
		return FALSE;
	} else {
		GRID_DEBUG("Trying fallbacks");
		/* Search in the fallback list */
		for (GSList *cursor = wsc->fallbacks;
				cursor != NULL && cursor->data != NULL;
				cursor = cursor->next) {
			if (storage_class_is_satisfied((gchar*)cursor->data, asc)) {
				return TRUE;
			}
		}
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
		GRID_DEBUG(err->message);
	}
	return err;
}

