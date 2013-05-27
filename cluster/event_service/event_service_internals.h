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

#ifndef __EVENT_SERVICE_INTERNALS_H__
# define __EVENT_SERVICE_INTERNALS_H__
# include <glib.h>
# include "../events/gridcluster_events.h"

enum event_status_e { ES_ERROR_DEF=-2, ES_ERROR_TMP=-1, ES_NOTFOUND=0, ES_WORKING=1, ES_DONE=2 };

/**
 *
 * @param ueid
 * @param event
 * @param error
 * @return
 */
gboolean eventservice_manage_event(const gchar *ueid, gridcluster_event_t *event, GError **error);

/** 
 *
 * @param ueid
 * @param error
 * @return
 */
enum event_status_e eventservice_stat_event(const gchar *ueid, GError **error);

#endif /*__EVENT_SERVICE_INTERNALS_H__*/
