/*
OpenIO SDS meta1v2
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
	"CREATE INDEX IF NOT EXISTS prop_by_cid on properties (cid);" \
	"CREATE INDEX IF NOT EXISTS serv_by_cid on services (cid);" \
	"CREATE INDEX IF NOT EXISTS serv_by_srvtype on services (cid,srvtype);" \
	"INSERT OR IGNORE INTO admin(k,v) " \
		"VALUES (\"schema_version\",\"1.0\");" \
    "INSERT OR IGNORE INTO admin(k,v) " \
		"VALUES (\"version:main.admin\",\"1:0\");" \
    "INSERT OR IGNORE INTO admin(k,v) " \
		"VALUES (\"version:main.users\",\"1:0\");" \
    "INSERT OR IGNORE INTO admin(k,v) " \
		"VALUES (\"version:main.services\",\"1:0\");" \
    "INSERT OR IGNORE INTO admin(k,v) " \
		"VALUES (\"version:main.properties\",\"1:0\")"

# include <glib.h>
# include <metautils/lib/metautils.h>

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

struct meta1_prefixes_set_s;
struct sqlx_repository_s;
struct sqlx_sqlite3_s;
struct oio_url_s;

struct meta1_backend_s;

/* Backend constructor.
 * This creates an internal sqlx_repository_t constructor. */
GError * meta1_backend_init(struct meta1_backend_s **out,
		const char *ns, struct sqlx_repository_s *repo,
		struct oio_lb_s *lb);

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

/* @param properties a NULL-terminated array of (2*N) strings representing N
 * <key,value> pairs, where [2i] is the i-nd key and [2i+1] the i-nd value. */
GError* meta1_backend_user_create(struct meta1_backend_s *m1,
		struct oio_url_s *url, gchar **properties);

GError* meta1_backend_user_destroy(struct meta1_backend_s *m1,
		struct oio_url_s *url, gboolean force);

GError* meta1_backend_user_info(struct meta1_backend_s *m1,
		struct oio_url_s *url, gchar ***result);


GError* meta1_backend_services_list(struct meta1_backend_s *m1,
		struct oio_url_s *url, const gchar *srvtype, gchar ***result);

GError* meta1_backend_services_link (struct meta1_backend_s *m1,
		struct oio_url_s *url, const gchar *srvtype,
		gboolean dryrun, gboolean autocreate,
		gchar ***result);

GError* meta1_backend_services_unlink(struct meta1_backend_s *m1,
		struct oio_url_s *url, const gchar *srvtype, gchar **urlv);

GError* meta1_backend_services_poll (struct meta1_backend_s *m1,
		struct oio_url_s *url, const gchar *srvtype,
		gboolean dryrun, gboolean autocreate,
		gchar ***result);

/* @param packedurl formatted as 'SEQ|TYPE|IP:PORT|ARGS' */
GError* meta1_backend_services_config(struct meta1_backend_s *m1,
		struct oio_url_s *url, const gchar *packedurl);

/* @param packedurl formatted as 'SEQ|TYPE|IP:PORT|ARGS' */
GError* meta1_backend_services_set(struct meta1_backend_s *m1,
		struct oio_url_s *url, const gchar *packedurl,
		gboolean autocreate, gboolean force);

/* Find replacements for some services linked to a reference.
 *
 * @param url URLs of the reference whose services must be replaced
 * @param kept Packed list of service URLs that must be kept
 * @param replaced Packed list of service URLs that must be replaced
 * @param dryrun If true, find replacement services but do not save them
 *
 * @note
 * The elements of `kept` and `replaced` must have the same sequence number.
 *
 * @note
 * The union of `kept` and `replaced` must match exactly the list of services
 * already known by the meta1 for the same sequence number. */
GError* meta1_backend_services_relink(struct meta1_backend_s *m1,
		struct oio_url_s *url, const char *kept, const char *replaced,
		gboolean dryrun, gchar ***out);


GError* meta1_backend_set_container_properties(struct meta1_backend_s *m1,
		struct oio_url_s *url, gchar **props, gboolean flush);

GError* meta1_backend_del_container_properties(struct meta1_backend_s *m1,
		struct oio_url_s *url, gchar **names);

GError* meta1_backend_get_container_properties(struct meta1_backend_s *m1,
		struct oio_url_s *url, gchar **names, gchar ***result);


GError *meta1_backend_services_all(struct meta1_backend_s *m1,
		struct oio_url_s *url, gchar ***result);

/* Send a notification (if enabled) with the services linked to a container. */
GError *meta1_backend_notify_services(struct meta1_backend_s *m1,
		struct oio_url_s *url);

/* @param bin must be non-NULL and point to a 2-bytes buffer (at least) */
const char * meta1_backend_basename(struct meta1_backend_s *m1,
		const guint8 *bin, gchar *dst, gsize len);

#endif /*OIO_SDS__meta1v2__meta1_backend_h*/
