/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif
#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.sqlx.version"
#endif

#include <stddef.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <glib.h>
#include <sqlite3.h>

#include <Table.h>
#include <TableSequence.h>

#include "../metautils/lib/metautils.h"
#include "../metautils/lib/metacomm.h"
#include "../metautils/lib/loggers.h"
#include "../metautils/lib/hashstr.h"

#include "./internals.h"
#include "./version.h"
#include "./sqliterepo.h"
#include "./hash.h"
#include "./cache.h"
#include "./election.h"

static GQuark gquark_log = 0;

static struct object_version_s*
version_get(gboolean init, GTree *t, const hashstr_t *k)
{
	struct object_version_s *o;
	o = g_tree_lookup(t, k);
	if (!o && init) {
		o = g_malloc0(sizeof(struct object_version_s));
		o->version = 1;
		g_tree_replace(t, hashstr_dup(k), o);
	}
	return o;
}

static struct object_version_s *
version_gets(gboolean init, GTree *t, const gchar *ks)
{
	hashstr_t *k = NULL;
	HASHSTR_ALLOCA(k, ks);
	return version_get(init, t, k);
}

static struct object_version_s *
version_getslen(gboolean init, GTree *t, const guint8 *ks, gsize ks_len)
{
	struct object_version_s *o;
	hashstr_t *k;

	k = hashstr_printf("%.*s", ks_len, ks);
	o = version_get(init, t, k);
	g_free(k);
	return o;
}

/**
 * Load the version from the tables met in the SCHEMA
 */
static void
version_init(sqlite3 *db, GTree **t)
{
	int rc;
	sqlite3_stmt *stmt = NULL;

	if (!gquark_log)
		gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	if (!*t)
		*t = g_tree_new_full(hashstr_quick_cmpdata, NULL, g_free, g_free);

	GRID_TRACE2("%s(%p)", __FUNCTION__, db);
	SQLX_ASSERT(db != NULL);

	sqlite3_prepare_debug(rc, db,
			"SELECT name FROM sqlite_master WHERE type = 'table'",
			-1, &stmt, NULL);

	if (rc != SQLITE_OK)
		GRID_WARN("Version init error (prepare) : (%d) %s", rc, sqlite_strerror(rc));
	else {
		while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
			const gchar *sk = (gchar*) sqlite3_column_text(stmt, 0);
			hashstr_t *k = hashstr_printf("main.%s", sk);
			struct object_version_s *o = version_get(1, *t, k);
			o->when = time(0);
			g_free(k);
		}
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			GRID_WARN("VERSION loading error : %s (%d)", sqlite_strerror(rc), rc);
		(void) sqlite3_finalize(stmt);
	}
}


gboolean
version_load(struct sqlx_sqlite3_s *sq3, gboolean schema_only)
{
	int rc, any = 0, missing = 0;
	sqlite3_stmt *stmt = NULL;
	gchar tmp[256];

	if (!gquark_log)
		gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	GRID_TRACE2("%s(%p)", __FUNCTION__, sq3);
	SQLX_ASSERT(sq3 != NULL);
	SQLX_ASSERT(sq3->db != NULL);

	if (sq3->versions) {
		g_tree_destroy(sq3->versions);
		sq3->versions = NULL;
	}
	version_init(sq3->db, &(sq3->versions));

	/* Fill the versions */
	sqlite3_prepare_debug(rc, sq3->db, "SELECT k,v FROM admin", -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		GRID_WARN("Version loading error (prepare) : (%d) %s",
				rc, sqlite_strerror(rc));
	}
	else {
		while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
			const gchar *k, *v;
			gchar *p;
			struct object_version_s *o;

			k = (gchar*) sqlite3_column_text(stmt, 0);
			v = (gchar*) sqlite3_column_text(stmt, 1);
			if (!k || !v || !*k ||!*v)
				continue;
			if (*k!='v' || !g_str_has_prefix(k, "version:"))
				continue;
			k += sizeof("version:") - 1;
			if (!*k)
				continue;

			any = 1;
			memset(tmp, 0, sizeof(tmp));
			g_strlcpy(tmp, v, sizeof(tmp)-1);

			if (!(o = version_gets(schema_only?0:1, sq3->versions, k))) {
				/* A table appeared! */
				missing = 1;
			}
			else {
				if (!(p = strchr(tmp, ':')))
					continue;
				*(p++) = '\0';
				o->version = g_ascii_strtoll(tmp, NULL, 10);
				o->when = g_ascii_strtoll(p, NULL, 10);
			}
		}
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			GRID_WARN("VERSION loading error : %s (%d)", sqlite_strerror(rc), rc);
		(void) sqlite3_finalize(stmt);
	}

	(void) any;
	(void) missing;
	return TRUE;
}

/* @see version_init() */
void
version_reinit(struct sqlx_sqlite3_s *sq3)
{
	SQLX_ASSERT(sq3 != NULL);
	SQLX_ASSERT(sq3->db != NULL);
	version_init(sq3->db, &(sq3->versions));
}

gboolean
version_save(struct sqlx_sqlite3_s *sq3)
{
	int rc;
	sqlite3_stmt *stmt = NULL;

	if (!gquark_log)
		gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	GRID_TRACE2("%s(%p)", __FUNCTION__, sq3);
	SQLX_ASSERT(sq3 != NULL);
	SQLX_ASSERT(sq3->db != NULL);
	SQLX_ASSERT(sq3->versions != NULL);

	sqlite3_prepare_debug(rc, sq3->db,
			"REPLACE INTO admin (k,v) VALUES (?,?)", -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		GRID_WARN("Version saving error (prepare) : (%d) %s",
				rc, sqlite_strerror(rc));
	}
	else {
		gboolean runner(gpointer _k, gpointer _v, gpointer _u) {
			hashstr_t *k = _k;
			struct object_version_s *v = _v;
			gchar sk[256], sv[256];
			(void) _u;

			g_snprintf(sk, sizeof(sk), "version:%s", hashstr_str(k));
			g_snprintf(sv, sizeof(sv), "%"G_GINT64_FORMAT":%"G_GINT64_FORMAT,
					v->version, v->when);
			sqlite3_bind_text(stmt, 1, sk, -1, NULL);
			sqlite3_bind_text(stmt, 2, sv, -1, NULL);

			while (SQLITE_ROW == (rc = sqlite3_step(stmt))) { }

			if (rc != SQLITE_OK && rc != SQLITE_DONE)
				GRID_WARN("VERSION saving error : %s (%d) (%s)",
						sqlite_strerror(rc), rc, hashstr_str(k));
			else {
				GRID_TRACE("VERSION saved for table %s", hashstr_str(k));
			}

			sqlite3_clear_bindings(stmt);
			sqlite3_reset(stmt);
			return FALSE;
		}

		g_tree_foreach(sq3->versions, runner, NULL);
		sqlite3_finalize_debug(rc, stmt);
	}

	return TRUE;
}

gchar*
version_dump(GTree *t)
{
	GString *gstr;

	gboolean runner(gpointer k, gpointer _v, gpointer _u) {
		struct object_version_s *v = _v;
		(void) _u;
		if (hashstr_len(k) <= 0 || !*hashstr_str(k))
			return FALSE;
		if (gstr->len > 0)
			g_string_append_c(gstr, ',');
		g_string_append_printf(gstr,
				"(%.*s,%"G_GINT64_FORMAT",%"G_GINT64_FORMAT")",
				(int)hashstr_len(k), hashstr_str(k),
				v->version, v->when);
		return FALSE;
	}

	if (!gquark_log)
		gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	SQLX_ASSERT(t != NULL);

	gstr = g_string_new("");
	g_tree_foreach(t, runner, NULL);
	return g_string_free(gstr, FALSE);
}

void
version_debug(const gchar *tag, GTree *versions)
{
	if (!GRID_TRACE_ENABLED())
		return;

	gchar *s = version_dump(versions);
	GRID_TRACE("%s %s (%s)", tag, s, __FUNCTION__);
	g_free(s);
}

static inline int
SIGN(gint64 i64)
{
	return (i64<0) ? (-1) : ((i64>0)?1:0);
}

gint64
version_diff_worst(GTree *diff)
{
	gint64 worst = 0;
	int first = 1;

	gboolean runner(gpointer k, gpointer _v, gpointer u) {
		struct object_version_s *v = _v;
		(void) u;

		if (hashstr_len(k) <= 0)
			return FALSE;

		if (!g_ascii_strcasecmp(hashstr_str(k), "main.admin"))
			return FALSE;

		if (!v->version || v->version == worst)
			return FALSE;

		if (first) {
			first = 0;
			worst = v->version;
			return FALSE;
		}

		if (ABS(worst) < ABS(v->version))
			worst = v->version;

		return FALSE;
	}

	g_tree_foreach(diff, runner, NULL);
	return worst;
}

static void
diff_dump(GTree *v0, GTree *v1, GTree *d)
{
	gchar *s;

	if (!GRID_TRACE_ENABLED())
		return;

	s = version_dump(d);
	GRID_TRACE("DIFF %s", s);
	g_free(s);

	s = version_dump(v0);
	GRID_TRACE("  v0 %s", s);
	g_free(s);

	s = version_dump(v1);
	GRID_TRACE("  v1 %s", s);
	g_free(s);

}

GError *
version_diff(GTree **diff, GTree *t0, GTree *t1)
{
	GError *err = NULL;
	GTree *d = NULL;

	gboolean runner(gpointer k, gpointer _v, gpointer _u) {
		struct object_version_s *v1, *v0, vd;

		if (hashstr_len(k) <= 0)
			return FALSE;
		if (!g_ascii_strcasecmp(hashstr_str(k), "main.admin"))
			return FALSE;
		if (!(v0 = _v)) {
			err = g_error_new(gquark_log, 500, "NULL element");
			return TRUE;
		}
		if (!(v1 = version_get(0, (GTree*)_u, k))) {
			err = g_error_new(gquark_log, 500, "Missing %s", hashstr_str(k));
			return TRUE;
		}

		vd.when = MAX(v0->when,v1->when);
		vd.version = v1->version - v0->version;
		if (!(v0 = g_tree_lookup(d, k)))
			g_tree_insert(d, hashstr_dup(k), g_memdup(&vd, sizeof(vd)));
		return FALSE;
	}

	if (!gquark_log)
		gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	GRID_TRACE2("%s(%p,%p,%p)", __FUNCTION__, diff, t0, t1);
	SQLX_ASSERT(diff != NULL);
	SQLX_ASSERT(t0 != NULL);
	SQLX_ASSERT(t1 != NULL);

	d = g_tree_new_full(hashstr_quick_cmpdata, NULL, g_free, g_free);
	g_tree_foreach(t0, runner, t1);
	g_tree_foreach(t1, runner, t0);
	diff_dump(t0, t1, d);

	if (err) {
		g_tree_destroy(d);
		return err;
	}
	else {
		*diff = d;
		return NULL;
	}
}

void
version_increment_all(GTree *t)
{
	gboolean runner(gpointer k, gpointer v, gpointer u) {
		struct object_version_s *o = v;
		(void) k; (void) u;
		o->version ++;
		o->when = time(0);
		return FALSE;
	}
	g_tree_foreach(t, runner, NULL);
}

void
version_increment(GTree *t, const gchar *tname)
{
	struct object_version_s *o;

	if (!gquark_log)
		gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);
	GRID_TRACE2("%s(%p,%s)", __FUNCTION__, t, tname);
	SQLX_ASSERT(t != NULL);
	SQLX_ASSERT(tname != NULL);

	o = version_gets(1, t, tname);
	o->version ++;
	o->when = time(0);
}

#include <TableVersion.h>
#include <BaseVersion.h>
#include <asn_codecs.h>
#include <der_encoder.h>
#include <ber_decoder.h>

GByteArray*
version_encode(GTree *t)
{
	asn_enc_rval_t rv;
	GByteArray *encoded;
	struct BaseVersion bv;

	gboolean runner(gpointer _k, gpointer _v, gpointer _u) {
		(void) _u;
		if (_k && _v && hashstr_len(_k) > 0) {
			struct object_version_s *v = _v;
			struct TableVersion *tv = g_malloc0(sizeof(*tv));
			OCTET_STRING_fromBuf(&(tv->name), hashstr_str(_k), hashstr_len(_k));
			asn_int64_to_INTEGER(&(tv->version), v->version);
			asn_int64_to_INTEGER(&(tv->when), v->when);
			asn_sequence_add(&(bv.list), tv);
		}
		return FALSE;
	}

	if (!gquark_log)
		gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	GRID_TRACE2("%s(%p)", __FUNCTION__, t);
	memset(&bv, 0, sizeof(bv));
	g_tree_foreach(t, runner, NULL);

	encoded = g_byte_array_new();
	rv = der_encode(&asn_DEF_BaseVersion, &bv, write_to_gba, encoded);
	asn_DEF_BaseVersion.free_struct(&asn_DEF_BaseVersion, &bv, TRUE);

	if (0 >= rv.encoded) {
		g_byte_array_free(encoded, TRUE);
		GRID_WARN("BaseVersion encoding error : %s", rv.failed_type->name);
		return NULL;
	}

	return encoded;
}

GTree*
version_decode(guint8 *raw, gsize rawsize)
{
	struct BaseVersion *bv = NULL;
	asn_dec_rval_t rv;
	asn_codec_ctx_t ctx;

	GRID_TRACE2("%s(%p,%"G_GSIZE_FORMAT")", __FUNCTION__, raw, rawsize);

	memset(&ctx, 0, sizeof(ctx));
	ctx.max_stack_size = 512 * 1024;
	rv = ber_decode(&ctx, &asn_DEF_BaseVersion, (void**)&bv, raw, rawsize);
	if (rv.code != RC_OK) {
		GRID_WARN("Decoder error (BaseVersion)");
		return NULL;
	}
	else {
		int i;
		GTree *t;

		SQLX_ASSERT(bv != NULL);
		t = g_tree_new_full(hashstr_quick_cmpdata, NULL, g_free, g_free);

		for (i=0; i<bv->list.count; i++) {
			struct TableVersion *tv = bv->list.array[i];
			struct object_version_s *o;

			if (!tv || !tv->name.buf || tv->name.size <= 0) {
				GRID_TRACE2("%s table with no name", __FUNCTION__);
				continue;
			}

			o = version_getslen(1, t, tv->name.buf, tv->name.size);
			asn_INTEGER_to_int64(&(tv->version), &(o->version));
			asn_INTEGER_to_int64(&(tv->when), &(o->when));
		}

		asn_DEF_BaseVersion.free_struct(&asn_DEF_BaseVersion, bv, FALSE);
		return t;
	}
}

GTree*
version_dup(GTree *version)
{
	gboolean run(gpointer k, gpointer v, gpointer u) {
		if (k && v && u) 
			g_tree_replace(u, hashstr_dup(k),
					g_memdup(v, sizeof(struct object_version_s)));
		return FALSE;
	}

	GTree *result;
	result = g_tree_new_full(hashstr_quick_cmpdata, NULL, g_free, g_free);
	g_tree_foreach(version, run, result);
	return result;
}

static GTree*
version_extract_effective_diff(TableSequence_t *seq)
{
	gint i;
	GTree *t;
	
	t = g_tree_new_full(hashstr_quick_cmpdata, NULL, g_free, g_free);

	for (i=0; i<seq->list.count ;i++) {
		Table_t *table = seq->list.array[i];
		if (table->name.size != sizeof("main.admin")-1 ||
				memcmp(table->name.buf, "main.admin", table->name.size-1)) {
			struct object_version_s *o = version_getslen(1, t, table->name.buf, table->name.size);
			o->version = 1;
		}
	}

	return t;
}

static GTree*
version_apply_diff(GTree *src, GTree *diff)
{
	GTree *result;

	gboolean runner_init(gpointer k, gpointer v, gpointer u) {
		struct object_version_s *o;
		(void) u;
		o = version_get(1, result, k);
		o->when = ((struct object_version_s*)v)->when;
		o->version = ((struct object_version_s*)v)->version;
		return FALSE;
	}
	gboolean runner_diff(gpointer k, gpointer v, gpointer u) {
		struct object_version_s *o;
		(void) u;
		o = version_get(1, result, k);
		o->when = ((struct object_version_s*)v)->when;
		o->version += ((struct object_version_s*)v)->version;
		return FALSE;
	}

	result = g_tree_new_full(hashstr_quick_cmpdata, NULL, g_free, g_free);

	g_tree_foreach(src, runner_init, NULL);
	g_tree_foreach(diff, runner_diff, NULL);
	return result;
}

GTree*
version_extract_expected(GTree *current, TableSequence_t *changes)
{
	GTree *effective_diff, *expected_version;

	effective_diff = version_extract_effective_diff(changes);
	expected_version = version_apply_diff(current, effective_diff);
	g_tree_destroy(effective_diff);

	return expected_version;
}

GError*
version_validate_diff(GTree *src, GTree *dst, gint64 *worst)
{
	gboolean reversed;
	gint64 w;
	GError *err;

	gboolean runner(gpointer k, gpointer v, gpointer u) {
		gint64 d;
		struct object_version_s *o = version_get(0, u, k);

		if (!o) {
			err = g_error_new(gquark_log, CODE_PIPEFROM, "Schema changed");
			return TRUE;
		}

		if (reversed)
			d = o->version - ((struct object_version_s*)v)->version;
		else
			d = ((struct object_version_s*)v)->version - o->version;

		if (w != 0 && SIGN(w) != SIGN(d)) {
			err = g_error_new(gquark_log, 500, "Concurrent changes");
			return TRUE;
		}

		if (ABS(d) > ABS(w))
			w = d;

		return FALSE;
	}

	err = NULL;
	w = 0;

	if (g_tree_nnodes(src) != g_tree_nnodes(dst))
		err = g_error_new(gquark_log, CODE_PIPEFROM, "Schema changed");

	if (!err) {
		reversed = FALSE;
		g_tree_foreach(src, runner, dst);
	}

	if (!err) {
		reversed = TRUE;
		g_tree_foreach(dst, runner, src);
	}

	if (!err && ABS(w) > 1)
		err = g_error_new(gquark_log,
			(w > 0 ? CODE_PIPEFROM : CODE_PIPETO),
			"Diff missed");

	if (!err && worst)
		*worst = w;

	return err;
}

