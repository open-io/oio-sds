/*
OpenIO SDS cache
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

#ifndef OIO_SDS__cache__cache_h
# define OIO_SDS__cache__cache_h 1

# include <glib.h>
# include "autogen.h"

#define NO_EXPIRATION_TIME -1

enum oio_cache_status_e
{
	OIO_CACHE_OK = 0,
	OIO_CACHE_NOTFOUND,
	OIO_CACHE_FAIL,
	OIO_CACHE_DISCONNECTED,
	OIO_CACHE_TIMEOUT,
};


struct oio_cache_s;

/* interface */
struct oio_cache_vtable_s
{
	/* destructor */
	void (*destroy) (struct oio_cache_s *self);

	enum oio_cache_status_e (*put) (struct oio_cache_s *self, const char *k, const char *v);
	enum oio_cache_status_e (*del) (struct oio_cache_s *self, const char *k);
	enum oio_cache_status_e (*get) (struct oio_cache_s *self, const char *k, gchar **out);
        guint (*cleanup_older) (struct oio_cache_s *self, const gint64 expiration_time);
	guint (*cleanup_exceeding) (struct oio_cache_s *self, const guint limit);
};

/* abstract type, every implementation must inherit from */
struct oio_cache_abstract_s
{
	const struct oio_cache_vtable_s *vtable;
};

/* Wrappers to the abstract implementation */

void oio_cache_destroy(struct oio_cache_s *c);
enum oio_cache_status_e oio_cache_put(struct oio_cache_s *c, const char *k, const char *v);
enum oio_cache_status_e oio_cache_del(struct oio_cache_s *c, const char *k);
enum oio_cache_status_e oio_cache_get(struct oio_cache_s *c, const char *k,
				      gchar **out);
guint oio_cache_cleanup_older(struct oio_cache_s *c,
			      const gint64 expiration_time);
guint oio_cache_cleanup_exceeding(struct oio_cache_s *c,
				  const guint limit);

/* Implementation specifics ------------------------------------------------- */

/* Returns a cache that stores nothing */
struct oio_cache_s * oio_cache_make_NOOP (void);

struct lru_tree_s;

/* Returns a cache that stores entries in a LRU_TREE */
struct oio_cache_s * oio_cache_make_LRU (struct lru_tree_s *lru);

/* Returns a multi-layered cache */
struct oio_cache_s * oio_cache_make_multilayer (GSList *caches);
struct oio_cache_s * oio_cache_make_multilayer_var (struct oio_cache_s *first, ...);

#endif /*OIO_SDS__cache__cache_h*/
