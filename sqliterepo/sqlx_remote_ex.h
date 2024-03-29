/*
OpenIO SDS sqliterepo
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021 OVH SAS

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

#ifndef OIO_SDS__sqliterepo__sqlx_remote_ex_h
# define OIO_SDS__sqliterepo__sqlx_remote_ex_h 1

#include <metautils/lib/metautils.h>
#include <sqliterepo/sqlx_remote.h>

/* Ask followers to download the whole database from the leader. */
GError* sqlx_remote_execute_RESYNC_many(gchar **targets, GByteArray *sid,
		const struct sqlx_name_s *name, gint64 deadline);

#endif /*OIO_SDS__sqliterepo__sqlx_remote_ex_h*/
