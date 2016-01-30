/*
OpenIO SDS gridd
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fnmatch.h>
#include <sys/time.h>

#include <metautils/lib/metautils.h>

#include "./server_internals.h"
#include "./srvstats.h"
#define IS(gv,T) g_variant_type_equal(g_variant_get_type(gv), T)

static GRWLock rw_lock;

static GHashTable *ht_stats = NULL;

GVariant*
srvstat_get_gvariant(const gchar *name)
{
	GVariant *gv;

	if (!name) {
		WARN("Invalid parameter (name=%p)", name);
		return NULL;
	}

	TRACE2("Looking for stat named [%s]", name);

	if (!ht_stats)
		srvstat_init();

	g_rw_lock_writer_lock (&rw_lock);
	gv = g_hash_table_lookup(ht_stats, name);
	if (gv)
		gv = g_variant_ref(gv);
	g_rw_lock_writer_unlock (&rw_lock);

	if (!gv) {
		TRACE2("Found <%s,NULL>", name);
		return NULL;
	}

	if (TRACE2_ENABLED()) {
		gchar *s = g_variant_print(gv, TRUE);
		TRACE2("Found <%s,%s>", name, s);
		g_free(s);
	}
	return gv;
}

gboolean
srvstat_set_gvariant(const gchar *name, GVariant *gv)
{
	gchar *pKey;
	
	if (!name || !gv) {
		WARN("Invalid parameter (name=%p gv=%p)", name, gv);
		return FALSE;
	}

	if (TRACE2_ENABLED()) {
		gchar *str = g_variant_print(gv, TRUE);
		TRACE2("Inserting stat <%s,%s>", name, str);
		g_free(str);
	}

	if (!ht_stats)
		srvstat_init();

	pKey = g_strdup(name);

	g_rw_lock_writer_lock (&rw_lock);
	g_hash_table_insert (ht_stats, pKey, gv);
	g_rw_lock_writer_unlock (&rw_lock);

	return TRUE;
}

static gboolean
_set_gvariant(const gchar *name, GVariant *gv)
{
	if (!srvstat_set_gvariant(name, gv)) {
		g_variant_unref(gv);
		return FALSE;
	}

	return TRUE;
}

gboolean
srvstat_set_double(const gchar *name, gdouble value)
{
	return _set_gvariant(name, g_variant_new_double(value));
}

gboolean
srvstat_get_double(const gchar *name, gdouble *value)
{
	GVariant *gv;

	if (!name || !value) {
		WARN("Invalid parameter (name=%p value=%p)", name, value);
		return FALSE;
	}

	TRACE2("Getting double stat named [%s]", name);

	if (!(gv = srvstat_get_gvariant(name)))
		return FALSE;

	if (IS(gv,G_VARIANT_TYPE_DOUBLE)) {
		*value = g_variant_get_double(gv);
		g_variant_unref(gv);
		return TRUE;
	}
	else if (IS(gv,G_VARIANT_TYPE_INT64)) {
		gint64 d = g_variant_get_double(gv);
		g_variant_unref(gv);
		*value = d;
		return TRUE;
	}
	else if (IS(gv,G_VARIANT_TYPE_UINT64)) {
		guint64 d = g_variant_get_double(gv);
		g_variant_unref(gv);
		*value = d;
		return TRUE;
	}
	else if (IS(gv,G_VARIANT_TYPE_BOOLEAN)) {
		gboolean d = g_variant_get_double(gv);
		g_variant_unref(gv);
		*value = d;
		return TRUE;
	}

	g_variant_unref(gv);
	return FALSE;
}

/* Kept for backward compatibility */
gboolean
srvstat_set (const gchar *name, gdouble value)
{
	return srvstat_set_double(name, value);
}

/* Kept for backward compatibility */
gboolean
srvstat_get (const gchar *name, gdouble *value)
{
	return srvstat_get_double(name, value);
}

gboolean
srvstat_set_u64(const gchar *name, guint64 value)
{
	return _set_gvariant(name, g_variant_new_uint64(value));
}

/* ------------------------------------------------------------------------- */

void
srvstat_del (const gchar *name)
{
	if (!ht_stats)
		srvstat_init();

	g_rw_lock_writer_lock (&rw_lock);
	g_hash_table_remove (ht_stats, name);
	g_rw_lock_writer_unlock (&rw_lock);
}

static void
gvariant_free(gpointer p)
{
	GVariant *gv;

	if (!(gv = p))
		return;
	g_variant_unref(gv);
}

void
srvstat_init (void)
{
	memset(&rw_lock,0x00,sizeof(rw_lock));
	g_rw_lock_init(&rw_lock);
	
	g_rw_lock_writer_lock (&rw_lock);
	if (!ht_stats)
		ht_stats = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, gvariant_free);
	g_rw_lock_writer_unlock (&rw_lock);
}

void
srvstat_fini (void)
{
	DEBUG("about to free the statistics");
	g_rw_lock_writer_lock (&rw_lock);
	if (ht_stats) {
		g_hash_table_destroy (ht_stats);
		ht_stats = NULL;
	}
	g_rw_lock_writer_unlock (&rw_lock);
	INFO("statistics freed");
}

void srvstat_flush (void)
{
	gboolean func_yes (gpointer k, gpointer v, gpointer u) {
		(void)k; (void)v; (void)u;
		return TRUE;
	}
	DEBUG("about to flush the statistics");
	if (!ht_stats)
		srvstat_init();
	else {
		g_rw_lock_writer_lock (&rw_lock);
		g_hash_table_foreach_remove (ht_stats, func_yes, NULL);
		g_rw_lock_writer_unlock (&rw_lock);
	}
	INFO("statistics flushed");
}

void
srvstat_foreach_gvariant(const gchar *pattern, srvstat_iterator_gvariant_f cb, void *udata)
{
	GHashTableIter iter;
	gpointer k, v;

	TRACE2("Running all stats with pattern [%s]", pattern);

	if (!pattern || !*pattern) {
		WARN("invalid parameter");
		return ;
	}
	
	if (!ht_stats)
		srvstat_init();

	g_rw_lock_writer_lock (&rw_lock);

	g_hash_table_iter_init(&iter, ht_stats);
	while (g_hash_table_iter_next(&iter, &k, &v)) {
		const gchar *name;
		GVariant *gv;
		if ((name = k) && (gv = v)) {
			gv = g_variant_ref(gv);
			if (!fnmatch(pattern, name, FNM_NOESCAPE)) {
				cb (udata, name, gv);
			}
			g_variant_unref(gv);
		}
	}

	g_rw_lock_writer_unlock (&rw_lock);
}

