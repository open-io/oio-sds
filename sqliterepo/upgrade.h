/*
OpenIO SDS sqliterepo
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#ifndef OIO_SDS__sqliterepo__upgrade_h
# define OIO_SDS__sqliterepo__upgrade_h 1

# include <glib/gtypes.h>

struct sqlx_sqlite3_s;
struct sqlx_upgrader_s;

typedef GError* (sqlx_upgrade_cb) (struct sqlx_sqlite3_s *sq3,
		gpointer cb_data);

struct sqlx_upgrader_s* sqlx_upgrader_create(void);

void sqlx_upgrader_destroy(struct sqlx_upgrader_s *su);

void sqlx_upgrader_register(struct sqlx_upgrader_s *su,
		const gchar *p0, const gchar *p1,
		sqlx_upgrade_cb cb, gpointer cb_data);

GError* sqlx_upgrade_do(struct sqlx_upgrader_s *su,
		struct sqlx_sqlite3_s *sq3);

#endif /*OIO_SDS__sqliterepo__upgrade_h*/