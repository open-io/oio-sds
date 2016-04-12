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

#ifndef OIO_SDS__metautils__lib__lrutree_h
# define OIO_SDS__metautils__lib__lrutree_h 1

# include <glib.h>

#define LTO_NONE	0x00
#define LTO_NOATIME 0X01

struct lru_tree_s;

/**
 * @param compare
 * @param kfree
 * @param vfree
 * @param options a binary OR'ed combination of LTO_* flags.
 * @return NULL in case of error or a valid lru_tree_s ready to be used
 */
struct lru_tree_s* lru_tree_create(GCompareFunc compare,
		GDestroyNotify kfree, GDestroyNotify vfree, guint32 options);

/* Destroys the LRU-Tree and calls the liberation hook for each stored
   pair. */
void lru_tree_destroy(struct lru_tree_s *lt);

guint lru_tree_remove_older (struct lru_tree_s *lt, gint64 oldest);

guint lru_tree_remove_exceeding (struct lru_tree_s *lt, guint count);

void lru_tree_insert(struct lru_tree_s *lt, gpointer k, gpointer v);

gpointer lru_tree_get(struct lru_tree_s *lt, gconstpointer k);

/* Returns TRUE if the item keyed with 'k' has been removed. */
gboolean lru_tree_remove(struct lru_tree_s *lt, gconstpointer k);

void lru_tree_foreach(struct lru_tree_s *lt, GTraverseFunc h, gpointer hdata);

gint64 lru_tree_count(struct lru_tree_s *lt);

#endif /*OIO_SDS__metautils__lib__lrutree_h*/
