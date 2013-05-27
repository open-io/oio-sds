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

#ifndef _IDX_MANAGEMENT_H
#define _IDX_MANAGEMENT_H

#include <glib.h>

#define MAX_DESC_LENGTH (MAX(STRLEN_ADDRINFO, LIMIT_LENGTH_VOLUMENAME) + LIMIT_LENGTH_NSNAME + 2)

struct grid_service_data {
        int idx;
        char desc[MAX_DESC_LENGTH];
};

int get_idx_of_service(const char *service_type, struct grid_service_data *service, GError **error);

#endif	/* _IDX_MANAGEMENT_H */
