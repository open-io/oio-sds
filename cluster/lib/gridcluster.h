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

extern gboolean oio_cluster_skip_agent;

/**
 * Struct to store an agent task description
 */
struct task_s {
	char id[MAX_TASKID_LENGTH]; /**< The task id */
	gint64 period;              /**< how many seconds between each run */
	guint8 busy;                /**< TRUE if the task is currently running */
};

GError* get_namespace_info (const char *ns, struct namespace_info_s **out);

GError* list_namespace_services (const char *ns, const char *type, GSList **out);

GError* list_namespace_service_types (const char *ns, GSList **out);

GError* register_namespace_services (const char *ns, GSList *ls);

GError* register_namespace_service (const struct service_info_s *si);

GError* clear_namespace_services (const char *ns, const char *type);


GSList *list_local_services(GError **error);

GSList *list_tasks(GError **error);

/**
 * Extract mode worm state from namespace_info
 *
 * @param ns_info the namespace_info
 *
 * @return TRUE if namespace is in mode worm, FALSE otherwise
 */
gboolean namespace_in_worm_mode(namespace_info_t* ns_info);

/**
 * Extract container max size allowed from namespace_info
 *
 * @param ns_info the namespace_info
 *
 * @return the container max size allowed
 */
gint64 namespace_container_max_size(namespace_info_t* ns_info);

/**
 * Get chunk size for a specific VNS.
 *
 * @param ns_info the namespace info
 * @param ns_name the full name of the VNS to get chunk size of
 * @return the chunk size for the specified VNS, or the global one
 *   if not defined for this VNS.
 */
gint64 namespace_chunk_size(const namespace_info_t* ns_info, const char *ns_name);

/**
 * Extract namespace defined storage_policy from namespace_info
 *
 * @param ns_info the namespace_info
 *
 * @return the storage_policy defined (must be freed)
 */
gchar* namespace_storage_policy(const namespace_info_t* ns_info, const char *ns_name);

/**
 * Check if a storage policy exist for a namespace
 *
 * @param ns_info the namespace_info
 *
 * @param storage_policy the namespace_info
 *
 * @return TRUE if the storage policy exist, FALSE otherwise
 */
gboolean namespace_is_storage_policy_valid(const namespace_info_t* ns_info, const gchar *storage_policy);

/**
 * Return the value of a data security matching a storage policy (the string "DATASEC:PARAM1:PARAM2:...")
 *
 * @param ns_info the namespace_info
 *
 * @param wanted_policy the policy to extract data security value. If null, get the data security matching the namespace configured policy
 *
 * @return the data security "value"
 */
gchar* namespace_data_security_value(const namespace_info_t *ns_info, const gchar *wanted_policy);

/**
 * Return the "value" of a storage policy (the string "STG_CLASS:DATA_SEC:DATA_THREAT")
 *
 * @param ns_info the namespace_info
 *
 * @param wanted_policy the policy to extract data security value. If null, get the data security matching the namespace configured policy
 *
 * @return the storage_policy "value" (must be freed)
 */
gchar* namespace_storage_policy_value(const namespace_info_t *ns_info, const gchar *wanted_policy);

/** Extract mode compression state from namespace_info
 * @return TRUE if namespace is in mode compression, FALSE otherwise */
gboolean namespace_in_compression_mode(namespace_info_t* ns_info);

gsize namespace_get_autocontainer_src_offset(namespace_info_t* ns_info);

gsize namespace_get_autocontainer_src_size(namespace_info_t* ns_info);

gsize namespace_get_autocontainer_dst_bits(namespace_info_t* ns_info);

/** Only used by gridd */
typedef namespace_info_t* (*get_namespace_info_f) (GError **error);

/** Returns the services update's configuration when the Load-Balancing
 * is performed by a servce of type srvtype for each namespace and VNS. */
gchar* gridcluster_get_service_update_policy(struct namespace_info_s *nsinfo);

gint64 gridcluster_get_container_max_versions(struct namespace_info_s *nsinfo);

struct grid_lbpool_s;

GError* gridcluster_reload_lbpool(struct grid_lbpool_s *glp);

GError* gridcluster_reconfigure_lbpool(struct grid_lbpool_s *glp);

/**
 * Get the delay before actually removing contents marked as deleted.
 *
 * @param nsinfo A pointer to the namespace infos
 * @return The delay in seconds, or -1 if disabled (never delete)
 */
gint64 gridcluster_get_keep_deleted_delay(struct namespace_info_s *nsinfo);

gchar* gridcluster_get_nsinfo_strvalue(struct namespace_info_s *nsinfo,
		const gchar *key, const gchar *def);

gint64 gridcluster_get_nsinfo_int64(struct namespace_info_s *nsinfo,
		const gchar* key, gint64 def);

gchar * gridcluster_get_agent(void);

#endif /*OIO_SDS__cluster__lib__gridcluster_h*/
