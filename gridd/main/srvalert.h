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

#ifndef __SRVALERT_H__
# define __SRVALERT_H__

#include <stdarg.h>

/* Alerting functions */

/* int spoolmess(char *identifier, char *criticity, char *alertMsg); */

typedef int (*srv_alert_handler) (void* user_data, const char *id, const char *criticity, const char *msg);

/* overwrite the default (dummy) alert handler with a user defined function.
 * Returns the old user_data previously registered. By default, a NULL pointer
 * is stored in the user_data pointer */
gpointer srv_set_alert_handler (srv_alert_handler h, void *user_data);

/*sends the alert through the registered alert handler*/
int srv_send_alert(const char *id, const char *criticity, const char *msg);

/*formats the arguments and send the alert*/
int srv_send_falert(const char *id, const char *criticity, const char *fmt, ...);

int srv_send_valert(const char *id, const char *criticity, const char *fmt, va_list args);

#define SRV_SEND_INFO(ID,FMT,...) srv_send_falert(ID,"INFO",FMT,__VA_ARGS__)
#define SRV_SEND_WARNING(ID,FMT,...) srv_send_falert(ID,"WARNING",FMT,__VA_ARGS__)
#define SRV_SEND_ERROR(ID,FMT,...) srv_send_falert(ID,"ERROR",FMT,__VA_ARGS__)
#define SRV_SEND_CRITICAL(ID,FMT,...) srv_send_falert(ID,"CRITICAL",FMT,__VA_ARGS__)

#endif /*__SRVALERT_H__*/
