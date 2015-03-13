/*
OpenIO SDS integrity
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

#ifndef OIO_SDS__integrity__lib__alert_h
# define OIO_SDS__integrity__lib__alert_h 1

/**
 * @defgroup integrity_loop_lib_alert Alerting
 * @ingroup integrity_loop_lib
 * @{
 */

#include <glib.h>

/**
 * Sends an alert to the alerting system
 *
 * @param domain the domain this alert applies to (x.y.z)
 * @param criticity this alert criticity
 * @param message the alert message
 *
 * @return TRUE or FALSE if the alert was not successfully sent to the alerting system
 */
gboolean alert(const gchar* domain, int criticity, const gchar* message);

/** @} */

#endif /*OIO_SDS__integrity__lib__alert_h*/