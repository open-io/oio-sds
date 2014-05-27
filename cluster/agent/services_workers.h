#ifndef __SERVICES_WORKERS_H__
#define __SERVICES_WORKERS_H__

#include <glib.h>

#include <metautils/lib/metatypes.h>

#include <cluster/agent/worker.h>
#include <cluster/agent/agent.h>
#include <cluster/agent/gridagent.h>

/*Server-side workers*/

int init_services_workers(GError **error);

int services_types_worker_list( worker_t *worker, GError **error );

int services_worker_push(worker_t *worker, GError **error);

int services_worker_list(worker_t *worker, GError **error);

int services_worker_list_local(worker_t *worker, GError **error);

int services_worker_clear(worker_t *worker, GError **error);

int services_worker_count(worker_t *worker, GError **error);

int services_worker_get_one(worker_t *worker, GError **error);

gboolean agent_choose_best_service(const gchar *ns_name, const gchar *srvname, struct service_info_s *si, GError **err);

gboolean agent_choose_best_service2(struct namespace_data_s *ns_data, const gchar *srvname, struct service_info_s *si, GError **err);

/*Client-side worker tasks (to the conscience)*/

int services_task_push(GError **error);

int services_task_get_types(GError **error);

int services_task_get_services(GError **error);

int services_task_check(GError ** error);

gsize agent_get_service_key(struct service_info_s *si, gchar * dst, gsize dst_size);

#endif /* __SERVICES_WORKERS_H__ */
