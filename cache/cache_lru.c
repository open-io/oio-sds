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

#include <glib.h>

#include <metautils/lib/metautils.h>

#include "cache.h"

 
struct oio_cache_LRU_s;
static void _lru_destroy (struct oio_cache_s *self);
static enum oio_cache_status_e _lru_put (struct oio_cache_s *self,
					 const char *k, const char *v);
static enum oio_cache_status_e _lru_del (struct oio_cache_s *self,
					 const char *k);
static enum oio_cache_status_e _lru_get (struct oio_cache_s *self,
					 const char *k, gchar **out);
static guint _lru_cleanup_older (struct oio_cache_s *c,
				 const gint64 expiration_time);
static guint _lru_cleanup_exceeding (struct oio_cache_s *c,
				     const guint limit);

static struct oio_cache_vtable_s vtable_LRU =
{
	_lru_destroy, _lru_put, _lru_del, _lru_get,
	_lru_cleanup_older, _lru_cleanup_exceeding
};

struct oio_cache_LRU_s
{
	const struct oio_cache_vtable_s *vtable;
	struct lru_tree_s *lru;
	GRWLock lru_lock;
};

/* concurrency protection */

struct oio_cache_s *
oio_cache_make_LRU (struct lru_tree_s *lru)
{
	EXTRA_ASSERT (lru != NULL);
	struct oio_cache_LRU_s *self = SLICE_NEW0 (struct oio_cache_LRU_s);
	self->vtable = &vtable_LRU;
	self->lru = lru;
	g_rw_lock_init(&self->lru_lock);
	return (struct oio_cache_s*) self;
}

static void
_lru_destroy (struct oio_cache_s *self)
{
	struct oio_cache_LRU_s *l = (struct oio_cache_LRU_s*) self;
	if (!l)
		return;
	lru_tree_destroy (l->lru);
	l->lru = NULL;
	g_rw_lock_clear(&l->lru_lock);
	SLICE_FREE (struct oio_cache_LRU_s, l);
}

static enum oio_cache_status_e
_lru_put (struct oio_cache_s *self, const char *k, const char *v)
{
	(void) self, (void) k, (void) v;
	struct oio_cache_LRU_s *l = (struct oio_cache_LRU_s*) self;
	if (!l)
		return OIO_CACHE_FAIL;
	gpointer value = g_strdup(v);
	if (value == NULL)
		return OIO_CACHE_FAIL;
	gpointer key = g_strdup(k);
	if (key == NULL) {
		g_free(value);
		return OIO_CACHE_FAIL;
	}
	g_rw_lock_writer_lock(&(l->lru_lock));
	lru_tree_insert(l->lru, key, value);
	g_rw_lock_writer_unlock(&(l->lru_lock));
	return OIO_CACHE_OK;
}

static enum oio_cache_status_e
_lru_del (struct oio_cache_s *self, const char *k)
{
	gboolean value;
	(void) self, (void) k;
	struct oio_cache_LRU_s *l = (struct oio_cache_LRU_s*) self;
	if(!l)
		return OIO_CACHE_FAIL;
	g_rw_lock_writer_lock(&(l->lru_lock));
	value = lru_tree_remove(l->lru, (gconstpointer)k);
	g_rw_lock_writer_unlock(&(l->lru_lock));
	if(!value)
		return OIO_CACHE_NOTFOUND;
	return OIO_CACHE_OK;
}

static enum oio_cache_status_e
_lru_get (struct oio_cache_s *self, const char *k, gchar **out)
{
	gpointer value;
	(void) self, (void) k;
	g_assert (out != NULL);
	*out = NULL;
	struct oio_cache_LRU_s *l = (struct oio_cache_LRU_s*) self;
	if(!l)
		return OIO_CACHE_FAIL;
	g_rw_lock_reader_lock(&(l->lru_lock));
	value = lru_tree_get(l->lru,(gconstpointer)k);
	g_rw_lock_reader_unlock(&(l->lru_lock));
	if(value == NULL)
		return OIO_CACHE_NOTFOUND;
	gchar* result = g_strdup((gchar*)value);
	if(result == NULL)
		return OIO_CACHE_FAIL;
	*out = (gchar*) result;
	return OIO_CACHE_OK;
}

static guint
_lru_cleanup_older (struct oio_cache_s *self, const gint64 expiration_time)
{
	struct oio_cache_LRU_s *l = (struct oio_cache_LRU_s*) self;
	if (!l)
		return OIO_CACHE_FAIL;
	guint value;
	g_rw_lock_writer_lock(&(l->lru_lock));
	value = lru_tree_remove_older(l->lru, expiration_time);
	g_rw_lock_writer_unlock(&(l->lru_lock));
	return value;
}

static guint
_lru_cleanup_exceeding (struct oio_cache_s *self, const guint limit)
{
	guint value;
	struct oio_cache_LRU_s *l = (struct oio_cache_LRU_s*) self;
	if (!l)
		return OIO_CACHE_FAIL;
	g_rw_lock_writer_lock(&(l->lru_lock));
	value = lru_tree_remove_exceeding(l->lru, limit);
	g_rw_lock_writer_unlock(&(l->lru_lock));
	return value;
}
