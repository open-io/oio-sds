/*
OpenIO SDS meta1v2
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#ifndef OIO_SDS__meta1v2__meta1_backend_h
# define OIO_SDS__meta1v2__meta1_backend_h 1

# define META1_SCHEMA \
	"CREATE TABLE IF NOT EXISTS users ( "\
		"cid BLOB NOT NULL PRIMARY KEY, "\
		"account TEXT NOT NULL, "\
		"user TEXT NOT NULL); "\
	"CREATE TABLE IF NOT EXISTS services ( "\
		"cid BLOB NOT NULL, "\
		"srvtype TEXT NOT NULL, "\
		"seq INT NOT NULL, "\
		"url TEXT NOT NULL, "\
		"args TEXT DEFAULT NULL, "\
		"PRIMARY KEY (cid,srvtype,seq)); " \
	"CREATE TABLE IF NOT EXISTS properties ( "\
		"cid BLOB NOT NULL, "\
		"name TEXT NOT NULL, "\
		"value TEXT NOT NULL, "\
		"PRIMARY KEY(cid,name));"\
	"INSERT OR IGNORE INTO admin(k,v) " \
		"VALUES (\"schema_version\",\"1.6\");" \
    "INSERT OR IGNORE INTO admin(k,v) " \
		"VALUES (\"version:main.admin\",\"1:0\");" \
    "INSERT OR IGNORE INTO admin(k,v) " \
		"VALUES (\"version:main.users\",\"1:0\");" \
    "INSERT OR IGNORE INTO admin(k,v) " \
		"VALUES (\"version:main.services\",\"1:0\");" \
    "INSERT OR IGNORE INTO admin(k,v) " \
		"VALUES (\"version:main.properties\",\"1:0\");" \
	"VACUUM"

# include <glib.h>
# include <metautils/lib/metatypes.h>

enum m1v2_open_type_e
{
	M1V2_OPENBASE_LOCAL       = 0x000,
	M1V2_OPENBASE_MASTERONLY  = 0x001,
	M1V2_OPENBASE_SLAVEONLY   = 0x002,
	M1V2_OPENBASE_MASTERSLAVE = 0x003,
};

enum m1v2_getsrv_e
{
	M1V2_GETSRV_RENEW  = 0x00,
	M1V2_GETSRV_REUSE  = 0x01,
	M1V2_GETSRV_DRYRUN = 0x02,
};

struct grid_lb_iterator_s;
struct meta1_prefixes_set_s;
struct sqlx_repository_s;
struct sqlx_sqlite3_s;
struct grid_lbpool_s;
struct hc_url_s;

struct meta1_backend_s;

/* Backend constructor.
 * This creates an internal sqlx_repository_t constructor. */
struct meta1_backend_s * meta1_backend_init(const gchar *ns,
		struct sqlx_repository_s *repo, struct grid_lbpool_s *glp);

/* Returns the set of prefixes internally managed
 * Please do not free the internal META1 prefixes set, this is done
 * in the meta1_backend_clean() function. */
struct meta1_prefixes_set_s* meta1_backend_get_prefixes(
		struct meta1_backend_s *m1);

/* Returns the holder of LB update policy.
 * Please do not free this internal structure, this is done
 * in the meta1_backend_clean() function. */
struct service_update_policies_s* meta1_backend_get_svcupdate(
		struct meta1_backend_s *m1);

/* Backend destructor.
 * Also cleans the SQLX repository inside. */
void meta1_backend_clean(struct meta1_backend_s *m1);


GError* meta1_backend_user_create(struct meta1_backend_s *m1,
		struct hc_url_s *url);

GError* meta1_backend_user_destroy(struct meta1_backend_s *m1,
		struct hc_url_s *url, gboolean force);

GError* meta1_backend_user_info(struct meta1_backend_s *m1,
		struct hc_url_s *url, gchar ***result);


GError* meta1_backend_services_list(struct meta1_backend_s *m1,
		struct hc_url_s *url, const gchar *srvtype, gchar ***result);

GError* meta1_backend_services_link (struct meta1_backend_s *m1,
		struct hc_url_s *url, const gchar *srvtype,
		gboolean dryrun, gboolean autocreate,
		gchar ***result);

GError* meta1_backend_services_unlink(struct meta1_backend_s *m1,
		struct hc_url_s *url, const gchar *srvtype, gchar **urlv);

GError* meta1_backend_services_poll (struct meta1_backend_s *m1,
		struct hc_url_s *url, const gchar *srvtype,
		gboolean dryrun, gboolean autocreate,
		gchar ***result);

/* @param packedurl formatted as 'SEQ|TYPE|IP:PORT|ARGS' */
GError* meta1_backend_services_config(struct meta1_backend_s *m1,
		struct hc_url_s *url, const gchar *packedurl);

/* @param packedurl formatted as 'SEQ|TYPE|IP:PORT|ARGS' */
GError* meta1_backend_services_set(struct meta1_backend_s *m1,
		struct hc_url_s *url, const gchar *packedurl,
		gboolean autocreate, gboolean force);


GError* meta1_backend_set_container_properties(struct meta1_backend_s *m1,
		struct hc_url_s *url, gchar **props, gboolean flush);

GError* meta1_backend_del_container_properties(struct meta1_backend_s *m1,
		struct hc_url_s *url, gchar **names);

GError* meta1_backend_get_container_properties(struct meta1_backend_s *m1,
		struct hc_url_s *url, gchar **names, gchar ***result);


GError *meta1_backend_services_all(struct meta1_backend_s *m1,
		struct hc_url_s *url, gchar ***result);

/* Ugly quirk */
GError* meta1_backend_open_base(struct meta1_backend_s *m1,
		struct hc_url_s *url, enum m1v2_open_type_e how,
		struct sqlx_sqlite3_s **sq3);

/* Returns whether the base associated to prefix was already created. */
gboolean meta1_backend_base_already_created(struct meta1_backend_s *m1,
		const guint8 *prefix);

typedef void (*m1b_ref_hook) (gpointer p, const gchar *ns, const gchar *ref);

gchar* meta1_backend_get_ns_name(const struct meta1_backend_s *m1);

/* Get the ip:port the current process is listening to. */
const gchar* meta1_backend_get_local_addr(struct meta1_backend_s *m1);

/* Send a notification (if enabled) with the services linked to a container. */
GError *meta1_backend_notify_services(struct meta1_backend_s *m1,
		struct hc_url_s *url);

#endif /*OIO_SDS__meta1v2__meta1_backend_h*/
