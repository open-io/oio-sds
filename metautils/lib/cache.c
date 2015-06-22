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

#include "metautils.h"

/* NOOP --------------------------------------------------------------------- */

struct metautils_cache_NOOP_s;

static void
_noop_destroy (struct metautils_cache_s *self)
{
	g_free ((struct metautils_cache_NOOP_s*)self);
}

static void
_noop_put (struct metautils_cache_s *self, const char *k, const char *v)
{
	(void) self, (void) k, (void) v;
}

static void
_noop_del (struct metautils_cache_s *self, const char *k)
{
	(void) self, (void) k;
}

static gchar *
_noop_get (struct metautils_cache_s *self, const char *k)
{
	(void) self, (void) k;
	return NULL;
}

static struct metautils_cache_vtable_s vtable_NOOP =
{
	_noop_destroy, _noop_put, _noop_del, _noop_get
};

struct metautils_cache_NOOP_s
{
	const struct metautils_cache_vtable_s *vtable;
};

struct metautils_cache_s *
metautils_cache_make_NOOP (void)
{
	struct metautils_cache_NOOP_s *self = g_malloc0 (sizeof(*self));
	self->vtable = &vtable_NOOP;
	return (struct metautils_cache_s*) self;
}

/* LRU ---------------------------------------------------------------------- */

struct metautils_cache_LRU_s;

static void _lru_destroy (struct metautils_cache_s *self);
static void _lru_put (struct metautils_cache_s *self, const char *k, const char *v);
static void _lru_del (struct metautils_cache_s *self, const char *k);
static gchar * _lru_get (struct metautils_cache_s *self, const char *k);

static struct metautils_cache_vtable_s vtable_LRU =
{
	_lru_destroy, _lru_put, _lru_del, _lru_get
};

struct metautils_cache_LRU_s
{
	const struct metautils_cache_vtable_s *vtable;
	struct lru_tree_s *lru;
};

struct metautils_cache_s *
metautils_cache_make_LRU (struct lru_tree_s *lru)
{
	EXTRA_ASSERT (lru != NULL);
	struct metautils_cache_LRU_s *self = g_malloc0 (sizeof(*self));
	self->vtable = &vtable_LRU;
	self->lru = lru;
	return (struct metautils_cache_s*) self;
}

static void
_lru_destroy (struct metautils_cache_s *self)
{
	struct metautils_cache_LRU_s *l = (struct metautils_cache_LRU_s*) self;
	if (!l)
		return;
	lru_tree_destroy (l->lru);
	l->lru = NULL;
	g_free (l);
}

static void
_lru_put (struct metautils_cache_s *self, const char *k, const char *v)
{
	(void) self, (void) k, (void) v;
}

static void
_lru_del (struct metautils_cache_s *self, const char *k)
{
	(void) self, (void) k;
}

static gchar *
_lru_get (struct metautils_cache_s *self, const char *k)
{
	(void) self, (void) k;
	return NULL;
}

