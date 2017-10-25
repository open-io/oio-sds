/*
OpenIO SDS metautils
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015,2017 OpenIO SAS, as part of OpenIO SDS

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

#include "metautils.h"

GPtrArray*
metautils_list_to_gpa(GSList *orig)
{
	GPtrArray *gpa = g_ptr_array_new();
	for (; orig ; orig=orig->next)
		g_ptr_array_add(gpa, orig->data);
	g_ptr_array_add(gpa, NULL);
	return gpa;
}

void**
metautils_gpa_to_array(GPtrArray *orig, gboolean clean)
{
	if (!orig)
		return NULL;
	if (orig->len <= 0 || NULL != orig->pdata[ orig->len - 1 ])
		g_ptr_array_add(orig, NULL);
	return clean ? g_ptr_array_free(orig, FALSE) : orig->pdata;
}

void**
metautils_list_to_array(GSList *orig)
{
	return metautils_gpa_to_array(metautils_list_to_gpa(orig), TRUE);
}

static gboolean
_runner (gchar *k, gpointer v, GPtrArray *out)
{
	(void) v;
	g_ptr_array_add(out, k);
	return FALSE;
}

gchar **
gtree_string_keys (GTree *t)
{
	GPtrArray *tmp = g_ptr_array_new ();
	if (t) {
		g_tree_foreach (t, (GTraverseFunc)_runner, tmp);
	}
	return (gchar**) metautils_gpa_to_array (tmp, TRUE);
}

GSList *
metautils_gslist_precat (GSList *l0, GSList *l1)
{
	if (!l0) return l1;
	GSList *tmp;
	while (l1) {
		tmp = l1->next;
		l1->next = l0;
		l0 = l1;
		l1 = tmp;
	}
	return l0;
}

void
metautils_gpa_reverse (GPtrArray *gpa)
{
	if (!gpa || gpa->len < 1)
		return;
	guint i, j;
	for (i=0,j=gpa->len-1; i<j ;i++,j--) {
		gpointer tmp = gpa->pdata[i];
		gpa->pdata[i] = gpa->pdata[j];
		gpa->pdata[j] = tmp;
	}
}

void
metautils_gvariant_unrefv(GVariant **v)
{
	if (!v)
		return;
	for (; *v ;v++) {
		g_variant_unref(*v);
		*v = NULL;
	}
}

void
metautils_gthreadpool_push(const char *tag, GThreadPool *pool, gpointer p)
{
	static gint64 last_log = 0;
	GError *err = NULL;
	if (!g_thread_pool_push(pool, p, &err)) {
		const gint64 now = oio_ext_monotonic_time();
		if (last_log <= OLDEST(now, G_TIME_SPAN_MINUTE)) {
			last_log = now;
			GRID_WARN("%s pool error: (%d) %s", tag, err->code, err->message);
		}
		g_clear_error(&err);
	}
}

