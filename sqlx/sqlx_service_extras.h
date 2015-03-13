/*
OpenIO SDS sqlx
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

#ifndef OIO_SDS__sqlx__sqlx_service_extras_h
# define OIO_SDS__sqlx__sqlx_service_extras_h 1

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

#endif /*OIO_SDS__sqlx__sqlx_service_extras_h*/