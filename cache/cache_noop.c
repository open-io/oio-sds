/*
OpenIO SDS cache
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

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

#include <glib.h>

#include <metautils/lib/metautils.h>

#include "cache.h"

struct oio_cache_NOOP_s
{
	const struct oio_cache_vtable_s *vtable;
};

static void
_noop_destroy (struct oio_cache_s *self)
{
	SLICE_FREE(struct oio_cache_NOOP_s, (struct oio_cache_NOOP_s*) self);
}

static enum oio_cache_status_e
_noop_put (struct oio_cache_s *self, const char *k, const char *v)
{
	(void) self, (void) k, (void) v;
	return OIO_CACHE_DISCONNECTED;
}

static enum oio_cache_status_e
_noop_del (struct oio_cache_s *self, const char *k)
{
	(void) self, (void) k;
	return OIO_CACHE_NOTFOUND;
}

static enum oio_cache_status_e
_noop_get (struct oio_cache_s *self, const char *k, gchar **out)
{
	(void) self, (void) k;
	g_assert (out != NULL);
	*out = NULL;
	return OIO_CACHE_NOTFOUND;
}

static struct oio_cache_vtable_s vtable_NOOP =
{
	_noop_destroy, _noop_put, _noop_del, _noop_get
};

struct oio_cache_s *
oio_cache_make_NOOP (void)
{
	struct oio_cache_NOOP_s *self = SLICE_NEW0 (struct oio_cache_NOOP_s);
	self->vtable = &vtable_NOOP;
	return (struct oio_cache_s*) self;
}
