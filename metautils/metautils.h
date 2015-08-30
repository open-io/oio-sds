/*
OpenIO SDS metautils
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

#ifndef OIO_SDS__metautils__lib__metautils_h
# define OIO_SDS__metautils__lib__metautils_h 1

# include <sys/types.h>
# include <sys/socket.h>

# include <glib.h>
# include <glib/gstdio.h>

#include <core/oio_core.h>

# include <metautils/metautils_macros.h>

# include <metautils/metatypes.h>

# include <metautils/metautils_bits.h>
# include <metautils/metautils_errors.h>
# include <metautils/metautils_strings.h>
# include <metautils/metautils_sockets.h>
# include <metautils/metautils_containers.h>
# include <metautils/metautils_gba.h>
# include <metautils/metautils_resolv.h>
# include <metautils/metautils_hashstr.h>
# include <metautils/metautils_task.h>
# include <metautils/metautils_l4v.h>
# include <metautils/metautils_svc_policy.h>
# include <metautils/metautils_syscall.h>

# include <metautils/metatype_cid.h>
# include <metautils/metatype_m0info.h>
# include <metautils/metatype_nsinfo.h>
# include <metautils/metatype_srvinfo.h>
# include <metautils/metatype_m1url.h>
# include <metautils/metatype_addrinfo.h>
# include <metautils/metatype_kv.h>
# include <metautils/metatype_metadata.h>
# include <metautils/metatype_acl.h>

# include <metautils/lrutree.h>
# include <metautils/cache.h>
# include <metautils/storage_policy.h>
# include <metautils/common_main.h>
# include <metautils/volume_lock.h>
# include <metautils/lb.h>

# include <metautils/metacomm.h>
# include <metautils/gridd_client.h>
# include <metautils/gridd_client_ext.h>
# include <metautils/gridd_client_pool.h>

#endif /*OIO_SDS__metautils__lib__metautils_h*/
