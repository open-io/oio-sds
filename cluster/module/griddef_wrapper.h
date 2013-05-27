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

#ifndef __GRIDDEF_WRAPPER_H__
# define __GRIDDEF_WRAPPER_H__
# include <conscience/grid_definition.h>

gboolean gdwrap_get_nsinfo(GSList *list_nsname, GSList **list_nsinfo, GError **error);

gboolean gdwrap_get_extended_nsinfo(GSList *list_nsname, GSList **list_nsinfo, GError **error);

gboolean gdwrap_load_services_by_host(const gchar *hostname, GSList **result, GError **error);

gboolean gdwrap_load_services_by_address(const gchar *str_ip, GSList **result, GError **error);

#endif /*__GRIDDEF_WRAPPER_H__*/
