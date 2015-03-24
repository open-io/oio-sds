/*
OpenIO SDS proxy
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

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

#ifndef OIO_SDS__proxy__macros_h
# define OIO_SDS__proxy__macros_h 1

#ifndef PROXYD_DEFAULT_TTL_SERVICES
#define PROXYD_DEFAULT_TTL_SERVICES 3600
#endif

#ifndef PROXYD_DEFAULT_MAX_SERVICES
#define PROXYD_DEFAULT_MAX_SERVICES 200000
#endif

#ifndef PROXYD_DEFAULT_TTL_CSM0
#define PROXYD_DEFAULT_TTL_CSM0 0
#endif

#ifndef PROXYD_DEFAULT_MAX_CSM0
#define PROXYD_DEFAULT_MAX_CSM0 0
#endif

#ifndef PROXYD_PREFIX
#define PROXYD_PREFIX "v1.0"
#endif

#ifndef PROXYD_PATH_MAXLEN
#define PROXYD_PATH_MAXLEN 2048
#endif

#ifndef PROXYD_DIR_TIMEOUT_SINGLE
#define PROXYD_DIR_TIMEOUT_SINGLE 10.0
#endif

#ifndef PROXYD_DIR_TIMEOUT_GLOBAL
#define PROXYD_DIR_TIMEOUT_GLOBAL 30.0
#endif

#ifndef PROXYD_M2_TIMEOUT_SINGLE
#define PROXYD_M2_TIMEOUT_SINGLE 10.0
#endif

#ifndef PROXYD_M2_TIMEOUT_GLOBAL
#define PROXYD_M2_TIMEOUT_GLOBAL 30.0
#endif

#ifndef PROXYD_DEFAULT_TIMEOUT_CONSCIENCE
#define PROXYD_DEFAULT_TIMEOUT_CONSCIENCE 5000 /*ms*/
#endif

#ifndef PROXYD_DEFAULT_PERIOD_DOWNSTREAM
#define PROXYD_DEFAULT_PERIOD_DOWNSTREAM 10 /*s*/
#endif

#ifndef PROXYD_DEFAULT_PERIOD_UPSTREAM
#define PROXYD_DEFAULT_PERIOD_UPSTREAM 1 /*s*/
#endif

#ifndef PROXYD_HEADER_PREFIX
#define PROXYD_HEADER_PREFIX "X-oio-"
#endif

#ifndef PROXYD_HEADER_REQID
#define PROXYD_HEADER_REQID PROXYD_HEADER_PREFIX "req-id"
#endif

#ifndef PROXYD_HEADER_NOEMPTY
#define PROXYD_HEADER_NOEMPTY PROXYD_HEADER_PREFIX "no-empty-list"
#endif

#endif /*OIO_SDS__proxy__macros_h*/
