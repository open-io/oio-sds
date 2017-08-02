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

#include <libmemcached/memcached.h>

#include <metautils/lib/metautils.h>

#include "cache_memcached.h"

struct oio_cache_memcached_s;

static void _memcached_destroy (struct oio_cache_s *self);
static enum oio_cache_status_e _memcached_put (struct oio_cache_s *self, const char *k, const char *v);
static enum oio_cache_status_e _memcached_del (struct oio_cache_s *self, const char *k);
static enum oio_cache_status_e _memcached_get (struct oio_cache_s *self, const char *k, gchar **out);

static struct oio_cache_vtable_s vtable_memcached =
{
	_memcached_destroy, _memcached_put, _memcached_del, _memcached_get
};

struct oio_cache_memcached_s
{
	const struct oio_cache_vtable_s *vtable;
	struct memcached_st *memc;
};

/* Constructors ------------------------------------------------------------- */

struct oio_cache_s *
oio_cache_make_memcached (const char *ip, int port)
{
	EXTRA_ASSERT (ip != NULL);
	struct oio_cache_memcached_s *self = SLICE_NEW0 (struct oio_cache_memcached_s);
	self->vtable = &vtable_memcached;

	char *config = g_strdup_printf ("--SERVER=%s:%d", ip, port);
	self->memc = memcached (config, strlen(config));
	if (!self->memc)
		return NULL;

	g_free (config);
	return (struct oio_cache_s*) self;
}

struct oio_cache_s *
oio_cache_make_memcached_config (const char *config)
{
	struct oio_cache_memcached_s *self = SLICE_NEW0 (struct oio_cache_memcached_s);
	self->vtable = &vtable_memcached;
	self->memc = memcached (config, strlen(config));
	if (!self->memc)
		return NULL;

	return (struct oio_cache_s*) self;
}

/* Handling ----------------------------------------------------------------- */

static enum oio_cache_status_e
memcached_parse_status(memcached_return_t rc)
{
	switch (rc) {
		case MEMCACHED_SUCCESS:
			return OIO_CACHE_OK;

		case MEMCACHED_CONNECTION_FAILURE:
			return OIO_CACHE_DISCONNECTED;
		
		case MEMCACHED_NOTFOUND:
			return OIO_CACHE_NOTFOUND;
		
		case MEMCACHED_TIMEOUT:
			return OIO_CACHE_TIMEOUT;

		default:
			return OIO_CACHE_FAIL;
	}
}

/* Interface ---------------------------------------------------------------- */

static void
_memcached_destroy (struct oio_cache_s *self)
{
	struct oio_cache_memcached_s *c = (struct oio_cache_memcached_s*) self;
	if (!c)
		return;
	memcached_free (c->memc);
	c->memc = NULL;
	SLICE_FREE (struct oio_cache_memcached_s, c);
}

static enum oio_cache_status_e
_memcached_put (struct oio_cache_s *self, const char *k, const char *v)
{
	struct oio_cache_memcached_s *c = (struct oio_cache_memcached_s*) self;
	memcached_return_t rc = memcached_set (c->memc, k, strlen(k), v, strlen(v), (time_t)0, (uint32_t)0);
	return memcached_parse_status(rc);
}

static enum oio_cache_status_e
_memcached_del (struct oio_cache_s *self, const char *k)
{
	struct oio_cache_memcached_s *c = (struct oio_cache_memcached_s*) self;
	memcached_return_t rc = memcached_delete (c->memc, k, strlen(k), (time_t)0);
	return memcached_parse_status(rc);
}

static enum oio_cache_status_e
_memcached_get (struct oio_cache_s *self, const char *k, gchar **out)
{
	struct oio_cache_memcached_s *c = (struct oio_cache_memcached_s*) self;
	size_t length;
	uint32_t flags;
	memcached_return_t rc;
	*out = memcached_get (c->memc, k, strlen(k), &length, &flags, &rc);
	return memcached_parse_status(rc);
}
