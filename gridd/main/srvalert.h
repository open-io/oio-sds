/*
OpenIO SDS gridd
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#ifndef OIO_SDS__gridd__main__srvalert_h
# define OIO_SDS__gridd__main__srvalert_h 1

#include <stdarg.h>

/* Alerting functions */

/*sends the alert through the registered alert handler*/
int srv_send_alert(const char *id, const char *criticity, const char *msg);

/*formats the arguments and send the alert*/
int srv_send_falert(const char *id, const char *criticity, const char *fmt, ...);

int srv_send_valert(const char *id, const char *criticity, const char *fmt, va_list args);

#define SRV_SEND_WARNING(ID,FMT,...) srv_send_falert(ID,"WARNING",FMT,__VA_ARGS__)
#define SRV_SEND_ERROR(ID,FMT,...) srv_send_falert(ID,"ERROR",FMT,__VA_ARGS__)

#endif /*OIO_SDS__gridd__main__srvalert_h*/
