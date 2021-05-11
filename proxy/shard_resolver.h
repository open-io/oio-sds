/*
OpenIO SDS sharding resolver
Copyright (C) 2021 OVH SAS

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

#ifndef OIO_SDS__proxy__shard_resolver_h
# define OIO_SDS__proxy__shard_resolver_h 1

#include <core/oio_core.h>

struct shard_resolver_s;

struct shard_resolver_s* shard_resolver_create(void);
void shard_resolver_destroy(struct shard_resolver_s *resolver);
gpointer shard_resolver_get_cached(
		struct shard_resolver_s *resolver, struct oio_url_s *url);
void shard_resolver_store(struct shard_resolver_s *resolver,
		struct oio_url_s *url, gpointer shard);
void shard_resolver_forget(struct shard_resolver_s *resolver,
		struct oio_url_s *url, gpointer shard);
void shard_resolver_forget_root(struct shard_resolver_s *resolver,
		struct oio_url_s *url);
guint shard_resolver_expire(struct shard_resolver_s *resolver);
guint shard_resolver_purge(struct shard_resolver_s *resolver);
void shard_resolver_flush(struct shard_resolver_s *resolver);

#endif /*OIO_SDS__proxy__shard_resolver_h*/
