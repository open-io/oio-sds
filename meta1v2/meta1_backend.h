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

/**
 * @addtogroup meta1v2_backend
 * @{
 */

# ifndef  META1_TYPE_NAME
#  define META1_TYPE_NAME "meta1"
# endif

# define META1_SCHEMA \
	"CREATE TABLE IF NOT EXISTS containers ( "\
		"cid BLOB NOT NULL PRIMARY KEY, "\
		"vns TEXT NOT NULL, "\
		"cname TEXT NOT NULL); "\
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
		"VALUES (\"version:main.containers\",\"1:0\");" \
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

/* Avoids an include */
struct grid_lb_iterator_s;
struct meta1_prefixes_set_s;
struct sqlx_repository_s;
struct sqlx_sqlite3_s;
struct grid_lbpool_s;
struct hc_url_s;

/* Hidden type */
struct meta1_backend_s;

/** Backend constructor.
 *
 * This creates an internal sqlx_repository_t constructor.
 *
 * @param result
 * @param ns
 * @param basedir
 * @return
 */
struct meta1_backend_s * meta1_backend_init(const gchar *ns,
		struct sqlx_repository_s *repo,
		struct grid_lbpool_s *glp,
		struct event_config_repo_s *evt_repo);

/** Returns the set of prefixes internally managed
 *
 * Please do not free the internal META1 prefixes set, this is done
 * in the meta1_backend_clean() function.
 *
 * @param m1
 * @return a pointer
 */
struct meta1_prefixes_set_s* meta1_backend_get_prefixes(
		struct meta1_backend_s *m1);

/** Returns the holder of LB update policy.
 *
 * Please do not free this internal structure, this is done
 * in the meta1_backend_clean() function.
 *
 * @param m1
 * @return a pointer
 */
struct service_update_policies_s* meta1_backend_get_svcupdate(
		struct meta1_backend_s *m1, const char *ns_name);

/** Backend destructor.
 *
 * Also cleans the SQLX repository inside.
 *
 * @param m1
 */
void meta1_backend_clean(struct meta1_backend_s *m1);

/* ------------------------------------------------------------------------- */

/**
 * @param m1
 * @param vns
 * @param cname
 * @param cid
 * @return
 */
GError* meta1_backend_create_container(struct meta1_backend_s *m1,
		const gchar *vns, const gchar *cname, container_id_t *cid);

/**
 * @param m1
 * @param cid
 * @param flush
 * @return
 */
GError* meta1_backend_destroy_container(struct meta1_backend_s *m1,
		const container_id_t cid, gboolean flush);

/**
 * @param m1
 * @param cid
 * @param result
 */
GError* meta1_backend_info_container(struct meta1_backend_s *m1,
		const container_id_t cid, gchar ***result);

/**
 * @param m1
 * @param cid
 * @param srvtype
 * @param result
 * @return
 */
GError* meta1_backend_get_container_service_available(
		struct meta1_backend_s *m1, struct hc_url_s *url,
		const gchar *srvtype, gboolean dryrun, gchar ***result);

/**
 * @param m1
 * @param cid
 * @param srvtype
 * @parem result
 * @return
 */
GError* meta1_backend_get_container_new_service(
		struct meta1_backend_s *m1, struct hc_url_s *url,
		const gchar *srvtype, gboolean dryrun, gchar ***result);

/**
 * @param m1
 * @param url
 * @param result
 * @return
 */
GError *meta1_backend_get_all_services(struct meta1_backend_s *m1,
	const container_id_t cid, gchar ***result);

/**
 * @param m1
 * @param cid
 * @param srvtype
 * @param result
 * @return
 */
GError* meta1_backend_get_container_all_services(struct meta1_backend_s *m1,
		const container_id_t cid, const gchar *srvtype, gchar ***result);

/**
 * @param m1
 * @param cid
 * @param srvtype
 * @param urlv
 * @return
 */
GError* meta1_backend_del_container_services(struct meta1_backend_s *m1,
		const container_id_t cid, const gchar *srvtype, gchar **urlv);

/**
 * @param m1
 * @param cid
 * @param props
 * @return
 */
GError* meta1_backend_set_container_properties(struct meta1_backend_s *m1,
		const container_id_t cid, gchar **props);

/**
 * @param m1
 * @param cid
 * @param names
 * @return
 */
GError* meta1_backend_del_container_properties(struct meta1_backend_s *m1,
		const container_id_t cid, gchar **names);

/**
 * @param m1
 * @param cid
 * @param names
 * @param result
 * @return
 */
GError* meta1_backend_get_container_properties(struct meta1_backend_s *m1,
		const container_id_t cid, gchar **names, gchar ***result);

/**
 * @param m1
 * @param cid key member, not touched
 * @param packedurl formatted as 'SEQ|TYPE|IP:PORT|ARGS'
 * @return
 */
GError* meta1_backend_set_service_arguments(struct meta1_backend_s *m1,
		const container_id_t cid, const gchar *packedurl);

/**
 * @param m1
 * @param cid key member, not touched
 * @param packedurl formatted as 'SEQ|TYPE|IP:PORT|ARGS'
 * @return
 */
GError* meta1_backend_force_service(struct meta1_backend_s *m1,
		const container_id_t cid, const gchar *packedurl);

/**
 * Ugly quirk
 *
 * @param m1
 * @param cid
 * @param how
 * @param sq3
 * @return
 */
GError* meta1_backend_open_base(struct meta1_backend_s *m1,
		const container_id_t cid, enum m1v2_open_type_e how,
		struct sqlx_sqlite3_s **sq3);

/**
 * Returns whether the base associated to prefix was already created.
 * @param m1
 * @param prefix
 * @return
 */
gboolean
meta1_backend_base_already_created(struct meta1_backend_s *m1, const guint8 *prefix);

/**
 * @param p
 * @param ns
 * @param ref
 */
typedef void (*m1b_ref_hook) (gpointer p, const gchar *ns, const gchar *ref);

/**
 * @param m1
 * @param cid
 * @param srvtype
 * @param url
 * @param ref_hook
 * @param ref_hook_data
 * @return
 */
GError* meta1_backend_list_references_by_service(struct meta1_backend_s *m1,
		const container_id_t cid, const gchar *srvtype, const gchar *url,
		m1b_ref_hook ref_hook, gpointer ref_hook_data);

/**
 * @param m1
 * @param cid
 * @param ref_hook
 * @param ref_hook_data
 * @return
 */
GError* meta1_backend_list_references(struct meta1_backend_s *m1,
		const container_id_t cid,
		m1b_ref_hook ref_hook, gpointer ref_hook_data);

GError*
meta1_backend_update_m1_policy(struct meta1_backend_s *m1, const gchar *ns, const container_id_t prefix,
                        const container_id_t cid, const gchar *srvtype,
                        const gchar *excludesrv, gchar *action, gboolean checkonly, gchar **result);

/**
 *
 */
gchar* meta1_backend_get_ns_name(const struct meta1_backend_s *m1);

struct event_config_repo_s *meta1_backend_get_evt_config_repo(const struct meta1_backend_s *m1);

/**
 * Get the event configuration for a specific namespace. Will fallback
 * on parent VNS if not found.
 */
struct event_config_s *meta1_backend_get_event_config(struct meta1_backend_s *m1, const char *ns_name);

metautils_notifier_t *meta1_backend_get_notifier(struct meta1_backend_s *m1);

/**
 * Initialize the notification system for Meta1
 */
GError *meta1_backend_init_notifs(struct meta1_backend_s *m1);

/**
 * Free the notifications system of Meta1
 */
void meta1_backend_free_notifs(struct meta1_backend_s *m1);

/**
 * Initialize a topic and add it to the cache.
 * Not thread safe.
 *
 * @param name The name of the topic to initialize
 */
GError *meta1_backend_prepare_notif_topic(struct meta1_backend_s *m1,
	const gchar *topic);

/**
 * Get the ip:port the current process is listening to.
 */
const gchar* meta1_backend_get_local_addr(struct meta1_backend_s *m1);

/**
 * Send a notification (if enabled) with the services linked to a container.
 */
GError *meta1_backend_notify_services(struct meta1_backend_s *m1,
		struct hc_url_s *url);

/** @} */

#endif /*OIO_SDS__meta1v2__meta1_backend_h*/