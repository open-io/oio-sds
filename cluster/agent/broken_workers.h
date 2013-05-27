/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __BROKEN_WORKERS_H__
# define __BROKEN_WORKERS_H__

#include <glib.h>

#include <worker.h>

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
