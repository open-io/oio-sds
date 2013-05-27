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

/**
 * @file alert.h
 */

#ifndef ALERT_H
#define ALERT_H

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

#endif /* ALERT_H */
