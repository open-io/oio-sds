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

#ifndef __META2_BACKEND_DBCONVERT_H__
# define __META2_BACKEND_DBCONVERT_H__ 1
# include <glib.h>
# include <sqlite3.h>

void m2v2_init_db(void);

void m2v2_clean_db(void);

GError* m2_convert_db(sqlite3 *db);

GError* m2_unconvert_db(sqlite3 *db);

#endif /* __META2_BACKEND_DBCONVERT_H__ */
