/*
OpenIO SDS snmp
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

#ifndef OIO_SDS__snmp__src__idx_management_h
# define OIO_SDS__snmp__src__idx_management_h 1

#include <glib.h>

#define MAX_DESC_LENGTH (MAX(STRLEN_ADDRINFO, LIMIT_LENGTH_VOLUMENAME) + LIMIT_LENGTH_NSNAME)

struct grid_service_data {
        int idx;
        char desc[MAX_DESC_LENGTH];
};

int get_idx_of_service(const char *service_type, struct grid_service_data *service, GError **error);

#endif /*OIO_SDS__snmp__src__idx_management_h*/
