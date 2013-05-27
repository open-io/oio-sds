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
 * @file version.h
 */

#ifndef HC__SQLX_VERSION__H
# define HC__SQLX_VERSION__H 1

/**
 * @defgroup sqliterepo_version Databases versioning
 * @ingroup sqliterepo
 * @brief
 * @details
 *
 * @{
 */

struct TableSequence;

/**
 *
 */
struct object_version_s
{
	gint64 version; /**<  */
	gint64 when;    /**<  */
};

struct sqlx_sqlite3_s;

/**
 * @param sq3
 */
void version_reinit(struct sqlx_sqlite3_s *sq3);

/**
 * @param sq3
 * @param schema_only
 * @return
 */
gboolean version_load(struct sqlx_sqlite3_s *sq3, gboolean schema_only);

/**
 * @param sq3
 * @return
 */
gboolean version_save(struct sqlx_sqlite3_s *sq3);

/**
 * @param t
 * @return
 */
gchar* version_dump(GTree *t);

/**
 * @param tag
 * @param versions
 */
void version_debug(const gchar *tag, GTree *sq3);

/**
 * @param t
 * @param tname
 */
void version_increment(GTree *t, const gchar *tname);

/**
 * @param t
 */
void version_increment_all(GTree *t);

/**
 * @param diff
 * @param v0
 * @param v1
 */
GError* version_diff(GTree **diff, GTree *v0, GTree *v1);

/**
 * @param diff
 * @return
 */
gint64 version_diff_worst(GTree *diff);

/**
 * Computes what would be the version if the 'changes' were applied to a
 * base with the 'current' version.
 *
 * @param current
 * @param changes
 * @return
 */
GTree* version_extract_expected(GTree *current, struct TableSequence *changes);

/**
 * Builds the diff then returns the worst element
 * @param src
 * @param dst
 * @param worst
 * @return
 */
GError* version_validate_diff(GTree *src, GTree *dst, gint64 *worst);

/**
 * @param t
 * @return
 */
GByteArray* version_encode(GTree *t);

/**
 * @param raw
 * @param rawsize
 * @return
 */
GTree* version_decode(guint8 *raw, gsize rawsize);

/**
 * @param version
 * @return
 */
GTree* version_dup(GTree *version);

/** @} */

#endif
