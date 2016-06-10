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

# include <metautils/lib/metautils_macros.h>

# include <sys/types.h>
# include <sys/socket.h>

# include <glib.h>
# include <glib/gstdio.h>

#include <core/oio_core.h>
#include <core/oiolb.h>
#include <core/internals.h>

# include <metautils/lib/metatypes.h>

# include <metautils/lib/metautils_bits.h>
# include <metautils/lib/metautils_errors.h>
# include <metautils/lib/metautils_strings.h>
# include <metautils/lib/metautils_sockets.h>
# include <metautils/lib/metautils_containers.h>
# include <metautils/lib/metautils_gba.h>
# include <metautils/lib/metautils_resolv.h>
# include <metautils/lib/metautils_hashstr.h>
# include <metautils/lib/metautils_task.h>
# include <metautils/lib/metautils_l4v.h>
# include <metautils/lib/metautils_svc_policy.h>
# include <metautils/lib/metautils_syscall.h>

# include <metautils/lib/metatype_m0info.h>
# include <metautils/lib/metatype_nsinfo.h>
# include <metautils/lib/metatype_srvinfo.h>
# include <metautils/lib/metatype_m1url.h>
# include <metautils/lib/metatype_addrinfo.h>
# include <metautils/lib/metatype_kv.h>
# include <metautils/lib/metatype_metadata.h>
# include <metautils/lib/metatype_acl.h>

# include <metautils/lib/lrutree.h>
# include <metautils/lib/storage_policy.h>
# include <metautils/lib/common_main.h>
# include <metautils/lib/volume_lock.h>
# include <metautils/lib/expr.h>
# include <metautils/lib/lb.h>

# include <metautils/lib/metacomm.h>
# include <metautils/lib/gridd_client.h>
# include <metautils/lib/gridd_client_ext.h>

#endif /*OIO_SDS__metautils__lib__metautils_h*/
