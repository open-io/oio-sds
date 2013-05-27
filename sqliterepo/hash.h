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

/**
 * @file hash.h
 */

#ifndef HC__SQLITEREPO_HASH__H
# define HC__SQLITEREPO_HASH__H 1

struct hashstr_s;

/**
 * @addtogroup sqliterepo_misc
 * @param n
 * @param t
 * @return
 */
struct hashstr_s * sqliterepo_hash_name(const gchar *n, const gchar *t);

#endif /* HC__SQLITEREPO_HASH__H */
