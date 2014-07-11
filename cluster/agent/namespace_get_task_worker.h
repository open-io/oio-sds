#ifndef NAMESPACE_GET_TASK_WORKER_H
#define NAMESPACE_GET_TASK_WORKER_H

#include <glib.h>
#include <cluster/agent/worker.h>
#include <cluster/agent/agent.h>

int start_namespace_get_task(GError **error);

int namespace_get_task_worker(worker_t *worker, GError **error);

int agent_start_indirect_ns_config(const gchar *ns_name, GError **error);

void namespace_get_task_cleaner(worker_t *worker);

namespace_data_t *get_namespace(const char *ns_name, GError **error);

GSList* namespace_get_services(struct namespace_data_s *ns_data);

gboolean namespace_is_available(const struct namespace_data_s *ns_data);

#endif	/* NAMESPACE_GET_TASK_WORKER_H */
