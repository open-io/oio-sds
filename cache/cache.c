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

#include <glib.h>

#include <metautils/lib/metautils.h>

#include "cache.h"

void
oio_cache_destroy(struct oio_cache_s *c)
{
	g_assert(c != NULL);
	g_assert(((struct oio_cache_abstract_s*)c)->vtable != NULL);
	g_assert(((struct oio_cache_abstract_s*)c)->vtable->destroy != NULL);
	return ((struct oio_cache_abstract_s*)c)->vtable->destroy(c);
}

enum oio_cache_status_e
oio_cache_del(struct oio_cache_s *c, const char *k)
{
	g_assert(c != NULL);
	g_assert(((struct oio_cache_abstract_s*)c)->vtable != NULL);
	g_assert(((struct oio_cache_abstract_s*)c)->vtable->del != NULL);
	return ((struct oio_cache_abstract_s*)c)->vtable->del(c,k);
}

enum oio_cache_status_e
oio_cache_put(struct oio_cache_s *c, const char *k, const char *v)
{
	g_assert(c != NULL);
	g_assert(((struct oio_cache_abstract_s*)c)->vtable != NULL);
	g_assert(((struct oio_cache_abstract_s*)c)->vtable->put != NULL);
	return ((struct oio_cache_abstract_s*)c)->vtable->put(c,k,v);
}

enum oio_cache_status_e
oio_cache_get(struct oio_cache_s *c, const char *k, gchar **out)
{
	g_assert(c != NULL);
	g_assert(((struct oio_cache_abstract_s*)c)->vtable != NULL);
	g_assert(((struct oio_cache_abstract_s*)c)->vtable->get != NULL);
	return ((struct oio_cache_abstract_s*)c)->vtable->get(c,k,out);
}

