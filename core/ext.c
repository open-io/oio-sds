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

#include <unistd.h>
#include <string.h>

#include <glib.h>
#include <json.h>

#include "oio_core.h"

#define PREPEND(Result,List) do { \
	next = (List)->next; \
	List->next = (Result); \
	(Result) = List; \
	List = next; \
} while (0)

static GSList*
gslist_merge_random(GSList *l1, GSList *l2)
{
	GSList *next, *result = NULL;

	while (l1 || l2) {
		if (l1 && l2) {
			if (g_random_boolean())
				PREPEND(result,l1);
			else
				PREPEND(result,l2);
		}
		else {
			if (l1)
				PREPEND(result,l1);
			else
				PREPEND(result,l2);
		}
	}

	return result;
}

static void
gslist_split_in_two(GSList *src, GSList **r1, GSList **r2)
{
	GSList *next, *l1 = NULL, *l2 = NULL;

	while (src) {
		if (src)
			PREPEND(l1, src);
		if (src)
			PREPEND(l2, src);
	}

	*r1 = l1, *r2 = l2;
}

GSList *
oio_ext_gslist_shuffle(GSList *src)
{
	GSList *l1=NULL, *l2=NULL;

	gslist_split_in_two(src, &l1, &l2);
	return gslist_merge_random(
		(l1 && l1->next) ? oio_ext_gslist_shuffle(l1) : l1,
		(l2 && l2->next) ? oio_ext_gslist_shuffle(l2) : l2);
}

void
oio_ext_array_shuffle (gpointer *array, gsize len)
{
	while (len-- > 1) {
		guint32 i = g_random_int_range (0, len+1);
		if (i == len)
			continue;
		gpointer tmp = array[i];
		array[i] = array[len];
		array[len] = tmp;
	}
}

void
oio_ext_array_partition (gpointer *array, gsize len, gboolean (*predicate)(gconstpointer))
{
	g_assert (array != NULL);
	g_assert (predicate != NULL);

	if (!len) return;

	/* qualify each item */
	gboolean good[len];
	for (gsize i=0; i<len ;i++)
		good[i] = (*predicate) (array[i]);

	/* partition the items, the predicate==TRUE first */
	for (gsize i=0; i<len ;i++) {
		if (good[i])
			continue;
		/* swap the items */
		gchar *tmp = array[len-1];
		array[len-1] = array[i];
		array[i] = tmp;
		/* swap the qualities */
		gboolean b = good[len-1];
		good[len-1] = good[i];
		good[i] = b;

		-- len;
		-- i;
	}
}

GError *
oio_ext_extract_json (struct json_object *obj,
		struct oio_ext_json_mapping_s *tab)
{
	g_assert (obj != NULL);
	g_assert (tab != NULL);
	for (struct oio_ext_json_mapping_s *p=tab; p->out ;p++)
		*(p->out) = NULL;
	if (!json_object_is_type(obj, json_type_object))
		return NEWERROR(400, "Not an object");
	for (struct oio_ext_json_mapping_s *p=tab; p->out ;p++) {
		struct json_object *o = NULL;
		if (!json_object_object_get_ex(obj, p->name, &o) || !o) {
			if (!p->mandatory)
				continue;
			return NEWERROR(400, "Missing field [%s]", p->name);
		}
		if (!json_object_is_type(o, p->type))
			return NEWERROR(400, "Invalid type for field [%s]", p->name);
		*(p->out) = o;
	}
	return NULL;
}

/* -------------------------------------------------------------------------- */

static void _free0 (gpointer p) { if (p) g_free(p); }

static GPrivate th_local_key_reqid = G_PRIVATE_INIT(_free0);

const char *
oio_ext_get_reqid (void)
{
	return g_private_get(&th_local_key_reqid);
}

void
oio_ext_set_reqid (const char *reqid)
{
	 g_private_replace (&th_local_key_reqid, g_strdup (reqid));
}

void
oio_ext_set_random_reqid (void)
{
	struct {
		pid_t pid:16;
		guint8 buf[14];
	} bulk;
	bulk.pid = getpid();
	oio_str_randomize(bulk.buf, sizeof(bulk.buf));

	char hex[33];
	oio_str_bin2hex((guint8*)&bulk, sizeof(bulk), hex, sizeof(hex));
	oio_ext_set_reqid(hex);
}

/* -------------------------------------------------------------------------- */

#include <execinfo.h>
#define STACK_MAX 8

GError *
oio_error_debug (GQuark gq, int code, const char *fmt, ...)
{
	void *frames[STACK_MAX];
	int nbframes = backtrace(frames, STACK_MAX);

	GString *gs = g_string_new("");
	char **strv = backtrace_symbols (frames, nbframes);
	if (strv) {
		for (int i=1; i<nbframes ;i++) {
			if (gs->len)
				g_string_append (gs, ", ");
			char *s, *start = strv[i];
			if (NULL != (s = strchr(start, '(')))
				start = s+1;
			if (NULL != (s = strchr(start, '+')))
				*s = 0;
			if (NULL != (s = strchr(start, ')')))
				*s = 0;
			g_string_append (gs, start);
		}
		free (strv);
	}

	va_list args;
	va_start (args, fmt);
	GError *err = g_error_new_valist (gq, code, fmt, args);
	va_end (args);

	g_prefix_error (&err, "%s ", gs->str);
	g_string_free (gs, TRUE);
	return err;
}

