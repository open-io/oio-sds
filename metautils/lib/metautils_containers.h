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

#ifndef OIO_SDS__metautils__lib__metautils_containers_h
# define OIO_SDS__metautils__lib__metautils_containers_h 1

#include <glib.h>

/** Builds a NULL-terminated array with the pointers extracted from orig. */
void** metautils_list_to_array(GSList *orig);

GPtrArray* metautils_list_to_gpa(GSList *orig);

void** metautils_gpa_to_array(GPtrArray *orig, gboolean clean);

#define metautils_gslist_shuffle oio_ext_gslist_shuffle

/** Concat both lists without any garanty on the output order.
 * Faster than g_slist_concat(). <l0> should be longer than <l1>.
 * After the call, both <l0> and <l1> MUST NOT be reused. */
GSList * metautils_gslist_precat (GSList *l0, GSList *l1);

/** Return all the keys in the tree. They are supposed to be
 * plain <gchar*>. They are not copied, free the result with
 * g_free(), not g_strfreev(). */
gchar** gtree_string_keys (GTree *t);

/** Reverse in place the elements in <gpa> */
void metautils_gpa_reverse (GPtrArray *gpa);

/** Calls g_variant_unref() on all the stored GVariant in <v>.
 * <v> is NULL-terminated. <v> is not freed. */
void metautils_gvariant_unrefv (GVariant **v);

/* Wrapper around g_thread_pool_push() that throttle-logs the error */
void metautils_gthreadpool_push(const char *tag,
		GThreadPool *pool, gpointer p);

#endif /*OIO_SDS__metautils__lib__metautils_containers_h*/
