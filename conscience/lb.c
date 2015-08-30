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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

# include <glib.h>

#include <metautils/metautils.h>

#include "lb.h"
#include "remote.h"

GError*
gridcluster_reload_lbpool(struct grid_lbpool_s *glp)
{
	gboolean _reload_srvtype(const char *ns, const char *srvtype) {
		GSList *list_srv = NULL;
		GError *err = conscience_list_services (ns, srvtype, FALSE, FALSE, &list_srv);
		if (err) {
			GRID_WARN("Gridagent/conscience error: Failed to list the services"
					" of type [%s]: code=%d %s", srvtype, err->code,
					err->message);
			g_clear_error(&err);
			return 0;
		}

		if (list_srv) {
			GSList *l = list_srv;

			gboolean provide(struct service_info_s **p_si) {
				if (!l)
					return 0;
				*p_si = l->data;
				l->data = NULL;
				l = l->next;
				return 1;
			}
			grid_lbpool_reload(glp, srvtype, provide);
			g_slist_free(list_srv);
		}

		return 1;
	}

	GSList *list_srvtypes = NULL;
	GError *err = conscience_list_service_types (grid_lbpool_namespace(glp), &list_srvtypes);
	if (err)
		g_prefix_error(&err, "LB pool reload error: ");
	else {
		guint errors = 0;
		const char *ns = grid_lbpool_namespace(glp);

		for (GSList *l=list_srvtypes; l ;l=l->next) {
			if (!l->data)
				continue;
			if (!_reload_srvtype(ns, l->data))
				++ errors;
		}

		if (errors)
			GRID_DEBUG("Reloaded %u service types, with %u errors",
					g_slist_length(list_srvtypes), errors);
	}

	g_slist_foreach(list_srvtypes, g_free1, NULL);
	g_slist_free(list_srvtypes);
	return err;
}

