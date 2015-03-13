/*
OpenIO SDS polix
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

#ifndef OIO_SDS__polix__event_manager_h
# define OIO_SDS__polix__event_manager_h 1

#include <glib.h>

typedef struct grid_polix_s {
	gdouble timeout;
} grid_polix_t;

grid_polix_t* polix_event_create(void);

void polix_event_free(grid_polix_t* polix);

gboolean polix_event_manager(grid_polix_t *polix, const gchar *ueid,
        gridcluster_event_t *event, gboolean *flag_retry, gboolean flag_dryrun, GError **err);

#endif /*OIO_SDS__polix__event_manager_h*/