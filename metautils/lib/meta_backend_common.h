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

#ifndef OIO_SDS__metautils__lib__meta_backend_common_h
# define OIO_SDS__metautils__lib__meta_backend_common_h 1

# include <glib.h>
# include <metautils/lib/metautils.h>

# include <sqliterepo/sqliterepo.h>

struct meta_backend_common_s {
	gchar ns_name[LIMIT_LENGTH_NSNAME];
	namespace_info_t ns_info;
	GMutex ns_info_lock;
	const gchar *type;
	struct sqlx_repository_s *repo;

	// Managed by sqlx_service_extra, do not allocate/free
	struct grid_lbpool_s *lb;
	struct event_config_repo_s *evt_repo;
};

#endif /*OIO_SDS__metautils__lib__meta_backend_common_h*/