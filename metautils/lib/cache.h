/*
OpenIO SDS metautils
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

#ifndef OIO_SDS__metautils__lib__cache_h
# define OIO_SDS__metautils__lib__cache_h 1

struct metautils_cache_s;

/* interface */
struct metautils_cache_vtable_s{
	/* destructor */
	void (*destroy) (struct metautils_cache_s *self);

	void (*put) (struct metautils_cache_s *self, const char *k, const char *v);
	void (*del) (struct metautils_cache_s *self, const char *k);
	gchar* (*get) (struct metautils_cache_s *self, const char *k);
};

/* abstract type, every implementation must inherit from */
struct metautils_cache_abstract_s
{
	const struct metautils_cache_vtable_s *vtable;
};

static inline void
metautils_cache_put(struct metautils_cache_s *c, const char *k, const char *v)
{
	g_assert(c != NULL);
	g_assert(((struct metautils_cache_abstract_s*)c)->vtable != NULL);
	g_assert(((struct metautils_cache_abstract_s*)c)->vtable->put != NULL);
	return ((struct metautils_cache_abstract_s*)c)->vtable->put(c,k,v);
}

static inline void
metautils_cache_del(struct metautils_cache_s *c, const char *k)
{
	g_assert(c != NULL);
	g_assert(((struct metautils_cache_abstract_s*)c)->vtable != NULL);
	g_assert(((struct metautils_cache_abstract_s*)c)->vtable->del != NULL);
	return ((struct metautils_cache_abstract_s*)c)->vtable->del(c,k);
}

static inline gchar *
metautils_cache_get(struct metautils_cache_s *c, const char *k)
{
	g_assert(c != NULL);
	g_assert(((struct metautils_cache_abstract_s*)c)->vtable != NULL);
	g_assert(((struct metautils_cache_abstract_s*)c)->vtable->get != NULL);
	return ((struct metautils_cache_abstract_s*)c)->vtable->get(c,k);
}

/* Implementation specifics ------------------------------------------------- */

/* Returns a cache that stores nothing */
struct metautils_cache_s * metautils_cache_make_NOOP (void);

struct lru_tree_s;

/* Returns a cache that stores entries in a LRU_TREE */
struct metautils_cache_s * metautils_cache_make_LRU (struct lru_tree_s *lru);

#endif /*OIO_SDS__metautils__lib__cache_h*/
