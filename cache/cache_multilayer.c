/*
OpenIO SDS cache
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <metautils/lib/metautils.h>
#include "cache.h"

struct oio_cache_multilayer_s;

static void _multilayer_destroy (struct oio_cache_s *self);
static enum oio_cache_status_e _multilayer_put (struct oio_cache_s *self, const char *k, const char *v);
static enum oio_cache_status_e _multilayer_del (struct oio_cache_s *self, const char *k);
static enum oio_cache_status_e _multilayer_get (struct oio_cache_s *self, const char *k, gchar **out);

static struct oio_cache_vtable_s vtable_multilayer =
{
	_multilayer_destroy, _multilayer_put, _multilayer_del, _multilayer_get
};

struct oio_cache_multilayer_s
{
	const struct oio_cache_vtable_s *vtable;
	GSList *caches;
};

/* Constructors ------------------------------------------------------------- */

struct oio_cache_s *
oio_cache_make_multilayer (GSList *caches)
{
	EXTRA_ASSERT (caches != NULL);
	struct oio_cache_multilayer_s *self = SLICE_NEW0 (struct oio_cache_multilayer_s);
	self->vtable = &vtable_multilayer;
	self->caches = caches;
	return (struct oio_cache_s*) self;
}

struct oio_cache_s *
oio_cache_make_multilayer_var (struct oio_cache_s *first, ...)
{
	struct oio_cache_multilayer_s *self = SLICE_NEW0 (struct oio_cache_multilayer_s);
	self->vtable = &vtable_multilayer;
	self->caches = NULL;

	va_list args;
	va_start (args, first);
	for (struct oio_cache_s *cache = first; cache; cache = va_arg(args, struct oio_cache_s *)) {
		self->caches = g_slist_prepend (self->caches, cache);
	}
	self->caches = g_slist_reverse(self->caches);
	va_end (args);

	return (struct oio_cache_s*) self;
}

/* Interface ---------------------------------------------------------------- */

static void
_multilayer_destroy (struct oio_cache_s *self)
{
	struct oio_cache_multilayer_s *c = (struct oio_cache_multilayer_s*) self;
	if (!c)
		return;
	g_slist_free_full (c->caches, (GDestroyNotify) oio_cache_destroy);
	c->caches = NULL;
	SLICE_FREE (struct oio_cache_multilayer_s, c);
}

static enum oio_cache_status_e
_multilayer_put (struct oio_cache_s *self, const char *k, const char *v)
{
	struct oio_cache_multilayer_s *c = (struct oio_cache_multilayer_s*) self;
	enum oio_cache_status_e rc = OIO_CACHE_FAIL;
	for (GSList* it = c->caches; it != NULL; it = it->next) {
		enum oio_cache_status_e cur_rc = oio_cache_put(it->data, k, v);
		if (rc != OIO_CACHE_OK)
			rc = cur_rc;
	}
	return rc;
}

static enum oio_cache_status_e
_multilayer_del (struct oio_cache_s *self, const char *k)
{
	struct oio_cache_multilayer_s *c = (struct oio_cache_multilayer_s*) self;
	enum oio_cache_status_e rc = OIO_CACHE_FAIL;
	for (GSList* it = c->caches; it != NULL; it = it->next) {
		enum oio_cache_status_e cur_rc = oio_cache_del(it->data, k);
		if (rc != OIO_CACHE_OK)
			rc = cur_rc;
	}
	return rc;
}

static enum oio_cache_status_e
_multilayer_get (struct oio_cache_s *self, const char *k, gchar **out)
{
	struct oio_cache_multilayer_s *c = (struct oio_cache_multilayer_s*) self;
	enum oio_cache_status_e rc = OIO_CACHE_FAIL;
	for (GSList* it = c->caches; it != NULL; it = it->next) {
		rc = oio_cache_get(it->data, k, out);
		if (rc == OIO_CACHE_OK)
			break;
	}
	return rc; 
}
