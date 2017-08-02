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

#ifndef OIO_SDS__cache__cache_memcached_h
# define OIO_SDS__cache__cache_memcached_h 1

#include "cache.h"

struct oio_cache_s * oio_cache_make_memcached (const char *ip, int port);

struct oio_cache_s * oio_cache_make_memcached_config (const char *config);

#endif /*OIO_SDS__cache__cache_memcached_h*/
