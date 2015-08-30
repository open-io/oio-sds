/*
OpenIO SDS server
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#ifndef OIO_SDS__server__internals_h
# define OIO_SDS__server__internals_h 1

#include <metautils/metautils.h>

# ifndef GRID_STAT_PREFIX_REQ
#  define GRID_STAT_PREFIX_REQ "gridd.counter.req"
# endif

# ifndef GRID_STAT_PREFIX_TIME
#  define GRID_STAT_PREFIX_TIME "gridd.counter.time"
# endif

# ifndef HTTP_STAT_PREFIX_REQ
#  define HTTP_STAT_PREFIX_REQ "http.counter.req"
# endif

# ifndef HTTP_STAT_PREFIX_TIME
#  define HTTP_STAT_PREFIX_TIME "http.counter.time"
# endif

#ifndef SERVER_DEFAULT_MAX_IDLEDELAY
# define SERVER_DEFAULT_MAX_IDLEDELAY 300
#endif

#ifndef SERVER_DEFAULT_MAX_WORKERS
# define SERVER_DEFAULT_MAX_WORKERS 200
#endif

#endif /*OIO_SDS__server__internals_h*/
