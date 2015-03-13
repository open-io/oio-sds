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

#ifndef OIO_SDS__polix__event_storage_h
# define OIO_SDS__polix__event_storage_h 1

#include <glib.h>

typedef enum event_status_e event_status_et;

typedef struct polix_event_t {
    gchar*               ueid;
    gridcluster_event_t *event;
} polix_event_t;

polix_event_t* pe_create(void);

gboolean pes_init(void);
void     pes_close(void);
gboolean pes_IsExist(const gchar* ueid);
gboolean pes_get_status(const gchar* ueid, event_status_et *status);
gboolean pes_set_status(polix_event_t *pe, event_status_et status);
gboolean pes_delete(const gchar* ueid, gboolean bAll);

#endif /*OIO_SDS__polix__event_storage_h*/