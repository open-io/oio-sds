/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef SQLX_UPGRADE__H
# define SQLX_UPGRADE__H 1

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

#endif /* SQLX_UPGRADE__H */
