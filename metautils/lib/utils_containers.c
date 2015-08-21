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

#include <stdlib.h>

#include "metautils_containers.h"

GSList*
metautils_array_to_list(void **orig)
{
	GSList *result = NULL;

	while (orig && *orig)
		result = g_slist_prepend(result, *(orig++));

	return g_slist_reverse(result);
}

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

GSList*
metautils_gpa_to_list(GPtrArray *gpa)
{
	GSList *result = NULL;
	guint i;

	for (i=0; i < gpa->len ;i++) {
		if (gpa->pdata[i])
			result = g_slist_prepend(result, gpa->pdata[i]);
	}

	return g_slist_reverse(result);
}

void
g_slist_free_agregated(GSList * list2)
{
	GSList *cursor2;

	for (cursor2 = list2; cursor2; cursor2 = cursor2->next)
		g_slist_free((GSList *) (cursor2->data));
	g_slist_free(list2);
}

void
g_slist_foreach_agregated(GSList * list2, GFunc callback, gpointer user_data)
{
	GSList *cursor2;

	for (cursor2 = list2; cursor2; cursor2 = cursor2->next)
		g_slist_foreach((GSList *) (cursor2->data), callback, user_data);
}

GPtrArray*
metautils_gtree_to_gpa(GTree *t, gboolean clean)
{
	gboolean run_move(gpointer k, gpointer v, gpointer u) {
		(void) k;
		g_ptr_array_add(u, v);
		return FALSE;
	}
	GPtrArray *tmp = g_ptr_array_new();
	g_tree_foreach(t, run_move, tmp);
	if (clean)
		g_tree_destroy(t);
	return tmp;
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

