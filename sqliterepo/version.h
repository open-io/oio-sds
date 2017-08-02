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

#ifndef OIO_SDS__sqliterepo__version_h
# define OIO_SDS__sqliterepo__version_h 1

# include <glib.h>

struct TableSequence;

struct object_version_s
{
	gint64 version;
	gint64 when;
};

struct sqlx_sqlite3_s;

/** Wraps version_extract_from_admin_tree() called on the admin table
 * cache. */
GTree* version_extract_from_admin(struct sqlx_sqlite3_s *sq3);

/** For testing purposes, prefer version_extract_from_admin()
 * for production code.
 * @see version_extract_from_admin() */
GTree* version_extract_from_admin_tree(GTree *t);

gchar* version_dump(GTree *t);

void version_debug(const gchar *tag, GTree *sq3);

/**
 * Computes what would be the version if the 'changes' were applied to a
 * base with the 'current' version.
 */
GTree* version_extract_expected(GTree *current, struct TableSequence *changes);

/**
 * Compute the diff between both versions, and returns an error if the worst
 * version is > 1 in basolute value.
 *
 * @param worst the worst difference matched, with the considering 'src - dst'
 * @return the error that occured
 */
GError* version_validate_diff(GTree *src, GTree *dst, gint64 *worst);

GTree* version_empty(void);

GByteArray* version_encode(GTree *t);

GTree* version_decode(guint8 *raw, gsize rawsize);

#endif /*OIO_SDS__sqliterepo__version_h*/
