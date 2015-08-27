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

struct task_s {
	char id[MAX_TASKID_LENGTH]; /**< The task id */
	gint64 period;              /**< how many seconds between each run */
	guint8 busy;                /**< TRUE if the task is currently running */
};

gchar * oio_cfg_get_agent(void);

namespace_info_t *get_namespace_info(const char *ns_name, GError **error);
GSList* list_namespace_services(const char *ns_name, const char *type, GError **error);
GSList* list_namespace_service_types(const char *ns_name, GError **error);
int register_namespace_service(const struct service_info_s *si, GError **error);
GSList *list_local_services(GError **error);
int clear_namespace_services(const char *ns_name, const char *type, GError **error);
GSList *list_tasks(GError **error);

gint64 namespace_get_keep_deleted_delay(const namespace_info_t *ni);
gchar* namespace_get_strvalue(const namespace_info_t *ni, const char *k, const char *d);
gint64 namespace_get_int64(const namespace_info_t *ni, const char* k, gint64 d);

gboolean namespace_in_worm_mode (const namespace_info_t* ni);
gboolean namespace_in_compression_mode (const namespace_info_t* ni);
gint64 namespace_container_max_size (const namespace_info_t* ni);
gint64 namespace_chunk_size (const namespace_info_t* ni, const char *ns_name);
gchar* namespace_storage_policy (const namespace_info_t* ni, const char *ns_name);
gboolean namespace_is_storage_policy_valid (const namespace_info_t* ni, const char *pol);
gchar* namespace_data_security_value (const namespace_info_t *ni, const char *pol);
gchar* namespace_storage_policy_value (const namespace_info_t *ni, const char *pol);
gchar* namespace_get_service_update_policy(const namespace_info_t *nsinfo);
gint64 namespace_get_container_max_versions(const namespace_info_t *nsinfo);

gsize namespace_get_autocontainer_src_offset (const namespace_info_t* ni);
gsize namespace_get_autocontainer_src_size (const namespace_info_t* ni);
gsize namespace_get_autocontainer_dst_bits (const namespace_info_t* ni);

struct grid_lbpool_s;
GError* gridcluster_reload_lbpool(struct grid_lbpool_s *glp);
GError* gridcluster_reconfigure_lbpool(struct grid_lbpool_s *glp);

#endif /*OIO_SDS__cluster__lib__gridcluster_h*/
