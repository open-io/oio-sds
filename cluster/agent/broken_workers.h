#ifndef __BROKEN_WORKERS_H__
# define __BROKEN_WORKERS_H__

#include <glib.h>

#include <cluster/agent/worker.h>

/*Server-side, reply to client requests*/

int agent_store_erroneous_container(worker_t *worker, GError **error);

int agent_fixed_erroneous_container(worker_t *worker, GError **error);

int agent_fetch_broken_all_elements(worker_t *worker, GError **error);

int agent_flush_erroneous_container(worker_t *worker, GError **error);

/*Client-side, contacts the conscience*/

/**
 * Regularily polls the consciences for broken containers
 */
int agent_start_broken_task_get(GError **error);

/**
 * Regularily forwards to the consciences the lists of broken elements
 */
int agent_start_broken_task_push(GError **error);

#endif /*__BROKEN_WORKERS_H__*/
