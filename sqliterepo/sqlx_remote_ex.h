/*
OpenIO SDS sqliterepo
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

#ifndef OIO_SDS__sqliterepo__sqlx_remote_ex_h
# define OIO_SDS__sqliterepo__sqlx_remote_ex_h 1

#include <metautils/lib/metautils.h>
#include <sqliterepo/sqlx_remote.h>

/**
 * Destroy an SQLX database.
 *
 * @param target One of the services managing the database.
 * @param sid Unused
 * @param name The name of the database
 * @param local TRUE to destroy only the database local to the service
 */
GError* sqlx_remote_execute_DESTROY(const gchar *target, GByteArray *sid,
		struct sqlx_name_s *name, gboolean local);

/**
 * Locally destroy an SQLX database on several services.
 *
 * @param targets An array of services managing the database.
 * @param sid Unused
 * @param name The name of the database
 * @param local
 */
GError* sqlx_remote_execute_DESTROY_many(gchar **targets, GByteArray *sid,
		struct sqlx_name_s *name);

#endif /*OIO_SDS__sqliterepo__sqlx_remote_ex_h*/