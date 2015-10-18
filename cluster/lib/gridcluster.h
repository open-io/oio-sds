/*
OpenIO SDS cluster
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#ifndef OIO_SDS__cluster__lib__gridcluster_h
# define OIO_SDS__cluster__lib__gridcluster_h 1

#include <metautils/lib/metatypes.h>
#include <cluster/agent/gridagent.h>

#define NS_ACL_ALLOW_OPTION "allow"

#define NS_ACL_DENY_OPTION "deny"

# define OIO_CFG_ZOOKEEPER    "zookeeper"
# define OIO_CFG_CONSCIENCE   "conscience"
# define OIO_CFG_AGENT        "agent"
# define OIO_CFG_ACCOUNTAGENT "event-agent"

# define gridcluster_get_zookeeper(ns)  oio_cfg_get_value((ns), OIO_CFG_ZOOKEEPER)
# define gridcluster_get_eventagent(ns) oio_cfg_get_value((ns), OIO_CFG_ACCOUNTAGENT)
# define gridcluster_get_conscience(ns) oio_cfg_get_value((ns), OIO_CFG_CONSCIENCE)

extern gboolean oio_cluster_allow_agent;
extern gboolean oio_cluster_allow_proxy;

struct service_info_s;
void metautils_srvinfo_ensure_tags (struct service_info_s *si);

gdouble oio_sys_cpu_idle (void);
gdouble oio_sys_io_idle (const char *vol);
gdouble oio_sys_space_idle (const char *vol);

/* Requests explicitely to the conscience ----------------------------------- */

GError * conscience_remote_get_namespace (const char *cs, struct namespace_info_s **out);
GError * conscience_remote_get_services (const char *cs, const gchar *type, gboolean full, GSList **out);
GError * conscience_remote_get_types (const char *cs, GSList **out);
GError * conscience_remote_push_services (const char *cs, GSList *ls);
GError * conscience_remote_remove_services(const char *cs, const char *type, GSList *ls);

GError * conscience_agent_get_namespace (const char *cs, struct namespace_info_s **out);
GError * conscience_agent_get_services (const char *cs, const gchar *type, GSList **out);
GError * conscience_agent_get_types (const char *cs, GSList **out);
GError * conscience_agent_push_services (const char *cs, GSList *ls);
GError * conscience_agent_remove_services(const char *cs, const char *type);

/* Requests the the best target (conscience, agent proxy) ------------------- */

GError* conscience_get_namespace (const char *ns, struct namespace_info_s **out);
GError* conscience_get_services (const char *ns, const char *type, GSList **out);
GError* conscience_get_types (const char *ns, GSList **out);
GError* conscience_push_services (const char *ns, GSList *ls);
GError* conscience_remove_services (const char *ns, const char *type);

GError* register_namespace_service (const struct service_info_s *si);

/* -------------------------------------------------------------------------- */

GSList *list_local_services(GError **error);

struct task_s {
	char id[MAX_TASKID_LENGTH]; /**< The task id */
	gint64 period;              /**< how many seconds between each run */
	guint8 busy;                /**< TRUE if the task is currently running */
};

GSList *list_tasks(GError **error);

/* -------------------------------------------------------------------------- */

gboolean namespace_in_worm_mode(namespace_info_t* ns_info);

gint64 namespace_container_max_size(namespace_info_t* ns_info);

gint64 namespace_chunk_size(const namespace_info_t* ns_info, const char *ns_name);

gchar* namespace_storage_policy(const namespace_info_t* ns_info, const char *ns_name);

gboolean namespace_is_storage_policy_valid(const namespace_info_t* ns_info, const gchar *storage_policy);

gchar* namespace_data_security_value(const namespace_info_t *ns_info, const gchar *wanted_policy);

gchar* namespace_storage_policy_value(const namespace_info_t *ns_info, const gchar *wanted_policy);

/* Extract mode compression state from namespace_info
 * @return TRUE if namespace is in mode compression, FALSE otherwise */
gboolean namespace_in_compression_mode(namespace_info_t* ns_info);

gsize namespace_get_autocontainer_src_offset(namespace_info_t* ns_info);

gsize namespace_get_autocontainer_src_size(namespace_info_t* ns_info);

gsize namespace_get_autocontainer_dst_bits(namespace_info_t* ns_info);

/* Returns the services update's configuration when the Load-Balancing
 * is performed by a servce of type srvtype for each namespace and VNS. */
gchar* gridcluster_get_service_update_policy(struct namespace_info_s *nsinfo);

gint64 gridcluster_get_container_max_versions(struct namespace_info_s *nsinfo);

struct grid_lbpool_s;

GError* gridcluster_reload_lbpool(struct grid_lbpool_s *glp);

GError* gridcluster_reconfigure_lbpool(struct grid_lbpool_s *glp);

/* Get the delay before actually removing contents marked as deleted. */
gint64 gridcluster_get_keep_deleted_delay(struct namespace_info_s *nsinfo);

gchar* gridcluster_get_nsinfo_strvalue(struct namespace_info_s *nsinfo,
		const gchar *key, const gchar *def);

gint64 gridcluster_get_nsinfo_int64(struct namespace_info_s *nsinfo,
		const gchar* key, gint64 def);

gchar * gridcluster_get_agent(void);

#endif /*OIO_SDS__cluster__lib__gridcluster_h*/
