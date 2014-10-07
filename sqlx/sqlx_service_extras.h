#ifndef SQLX_SERVICE_EXTRAS__H
# define SQLX_SERVICE_EXTRAS__H 1

# include <glib.h>
# include <metautils/lib/metautils.h>

struct sqlx_service_extras_s {
	struct grid_lbpool_s *lb;
	struct event_config_repo_s *evt_repo;
};

/**
 * Initialize the extra structures (LB pool and event/notifications).
 */
GError *sqlx_service_extras_init(struct sqlx_service_s *ss);

/**
 * Clear the extra structures (no-op if never initialized).
 */
void sqlx_service_extras_clear(struct sqlx_service_s *ss);

/**
 * Reloads the extra (grid_lbpool_s*).
 */
void sqlx_task_reload_lb(struct sqlx_service_s *ss);

/**
 * Reload the extra event config and notifier.
 */
void sqlx_task_reload_event_config(struct sqlx_service_s *ss);


#endif
