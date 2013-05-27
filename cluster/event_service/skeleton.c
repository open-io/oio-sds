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

#ifndef LOG_DOMAIN
# define LOG_DOMAIN "gridcluster.event_service"
#endif
#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif

#include <stdlib.h>

#include <glib.h>

#include <metautils.h>

#include "../events/gridcluster_events.h"
#include "./event_service_internals.h"

gboolean
eventservice_manage_event(const gchar *ueid, gridcluster_event_t *event, GError **error)
{
	if (!ueid || !event) {
		GSETCODE(error,500,"Internal error");
		return FALSE;
	}
	INFO("event RECV [%s]", ueid);
	/**@todo TODO replace this code by yours!*/
	return TRUE;
}

enum event_status_e
eventservice_stat_event(const gchar *ueid, GError **error)
{
	long r;
	if (!ueid) {
		GSETCODE(error,500,"Internal error");
		return ES_ERROR_TMP;
	}
	/**@todo TODO replace this code by yours!*/
	r = random();
	if (!(r%1000L))
		abort();
		
	switch (r%9) {
	case 0:
	case 1:
	case 2:
	case 3:
		NOTICE("event DONE [%s]", ueid);
		return ES_DONE;
	case 4:
	case 5:
	case 6:
	case 7:
		INFO("event INPROGRESS [%s]", ueid);
		return ES_WORKING;
	default:
		WARN("event ERROR [%s]", ueid);
		return ES_ERROR_TMP;
	}

	ALERT("You shloud never see this line, but it makes GCC happy!");
	return ES_ERROR_DEF;
}

