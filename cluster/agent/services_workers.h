/*
OpenIO SDS cluster
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

#ifndef OIO_SDS__cluster__agent__services_workers_h
# define OIO_SDS__cluster__agent__services_workers_h 1

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

/*Client-side worker tasks (to the conscience)*/

int services_task_push(GError **error);

int services_task_get_types(GError **error);

int services_task_get_services(GError **error);

int services_task_check(GError ** error);

gsize agent_get_service_key(struct service_info_s *si, gchar * dst, gsize dst_size);

#endif /*OIO_SDS__cluster__agent__services_workers_h*/
