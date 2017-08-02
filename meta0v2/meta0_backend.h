/*
OpenIO SDS meta0v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef OIO_SDS__meta0v2__meta0_backend_h
# define OIO_SDS__meta0v2__meta0_backend_h 1

# define META0_SCHEMA \
	"CREATE TABLE IF NOT EXISTS meta1 ( " \
		"prefix BLOB NOT NULL," \
		"addr TEXT NOT NULL," \
		"PRIMARY KEY(prefix,addr));" \
	"CREATE TABLE IF NOT EXISTS meta1_ref ( " \
		"addr TEXT NOT NULL," \
		"state TEXT NOT NULL," \
		"prefixes TEXT NOT NULL," \
		"PRIMARY KEY (addr));" \
	"INSERT OR IGNORE INTO admin(k,v) " \
		"VALUES (\"schema_version\",\"1.0\");" \
    "INSERT OR IGNORE INTO admin(k,v) " \
		"VALUES (\"version:main.admin\",\"1:0\");" \
    "INSERT OR IGNORE INTO admin(k,v) " \
		"VALUES (\"version:main.meta1\",\"1:0\");" \
    "INSERT OR IGNORE INTO admin(k,v) " \
		"VALUES (\"version:main.meta1_ref\",\"1:0\");"

struct meta0_backend_s;
struct sqlx_repository_s;

enum m0v2_open_type_e
{
	M0V2_OPENBASE_LOCAL        = 0x000,
	M0V2_OPENBASE_MASTERONLY   = 0x001,
	M0V2_OPENBASE_SLAVEONLY    = 0x002,
	M0V2_OPENBASE_MASTERSLAVE  = 0x003,
};

struct meta0_backend_s * meta0_backend_init(const gchar *ns, const gchar *id,
		struct sqlx_repository_s *repo);

void meta0_backend_clean(struct meta0_backend_s *m0);

void meta0_backend_reload_requested(struct meta0_backend_s *m0);

/**
 * Replace the current meta0 mapping by the content of the provided
 * JSON hash. The hash may contain holes, in which case the previous
 * entries of the mapping will be kept.
 */
GError* meta0_backend_fill_from_json(struct meta0_backend_s *m0,
		const char *json_mapping);

GError * meta0_backend_reload(struct meta0_backend_s *m0);

/* Please, be careful and know what your are about to do with this... */
GError * meta0_backend_reset(struct meta0_backend_s *m0, gboolean flag_local);

GError* meta0_backend_get_all(struct meta0_backend_s *m0,
		GPtrArray **result);

GError* meta0_backend_get_one(struct meta0_backend_s *m0,
		const guint8 *prefix, gchar ***urls);

#endif /*OIO_SDS__meta0v2__meta0_backend_h*/
