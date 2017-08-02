/*
OpenIO SDS cache
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

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
static enum oio_cache_status_e _lru_put (struct oio_cache_s *self, const char *k, const char *v);
static enum oio_cache_status_e _lru_del (struct oio_cache_s *self, const char *k);
static enum oio_cache_status_e _lru_get (struct oio_cache_s *self, const char *k, gchar **out);

static struct oio_cache_vtable_s vtable_LRU =
{
	_lru_destroy, _lru_put, _lru_del, _lru_get
};

struct oio_cache_LRU_s
{
	const struct oio_cache_vtable_s *vtable;
	struct lru_tree_s *lru;
};

struct oio_cache_s *
oio_cache_make_LRU (struct lru_tree_s *lru)
{
	EXTRA_ASSERT (lru != NULL);
	struct oio_cache_LRU_s *self = SLICE_NEW0 (struct oio_cache_LRU_s);
	self->vtable = &vtable_LRU;
	self->lru = lru;
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
	SLICE_FREE (struct oio_cache_LRU_s, l);
}

static enum oio_cache_status_e
_lru_put (struct oio_cache_s *self, const char *k, const char *v)
{
	(void) self, (void) k, (void) v;
	return OIO_CACHE_DISCONNECTED;
}

static enum oio_cache_status_e
_lru_del (struct oio_cache_s *self, const char *k)
{
	(void) self, (void) k;
	return OIO_CACHE_NOTFOUND;
}

static enum oio_cache_status_e
_lru_get (struct oio_cache_s *self, const char *k, gchar **out)
{
	(void) self, (void) k;
	g_assert (out != NULL);
	*out = NULL;
	return OIO_CACHE_NOTFOUND;
}
