/*
OpenIO SDS sqliterepo
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#ifndef OIO_SDS__sqliterepo__sqlx_macros_h
# define OIO_SDS__sqliterepo__sqlx_macros_h 1

#define NAME_MSGNAME_SQLX_HAS                "DB_HAS"
#define NAME_MSGNAME_SQLX_PROPSET            "DB_PSET"
#define NAME_MSGNAME_SQLX_PROPGET            "DB_PGET"
#define NAME_MSGNAME_SQLX_PROPDEL            "DB_PDEL"
#define NAME_MSGNAME_SQLX_ENABLE             "DB_ENABLE"
#define NAME_MSGNAME_SQLX_DISABLE            "DB_DISABLE"
#define NAME_MSGNAME_SQLX_FREEZE             "DB_FREEZE"
#define NAME_MSGNAME_SQLX_DISABLE_DISABLED   "DB_DISABLE_DISABLED"
#define NAME_MSGNAME_SQLX_STATUS             "DB_STATUS"
#define NAME_MSGNAME_SQLX_DESCR              "DB_DESCR"
#define NAME_MSGNAME_SQLX_ISMASTER           "DB_ISMASTER"
#define NAME_MSGNAME_SQLX_ELECTION           "DB_ELECTION"
#define NAME_MSGNAME_SQLX_EXITELECTION       "DB_LEAVE"

#define NAME_MSGNAME_SQLX_USE                "DB_USE"
#define NAME_MSGNAME_SQLX_GETVERS            "DB_GETVERS"
#define NAME_MSGNAME_SQLX_PIPETO             "DB_PIPETO"
#define NAME_MSGNAME_SQLX_PIPEFROM           "DB_PIPEFROM"
#define NAME_MSGNAME_SQLX_DUMP               "DB_DUMP"
#define NAME_MSGNAME_SQLX_RESTORE            "DB_RESTORE"
#define NAME_MSGNAME_SQLX_REPLICATE          "DB_REPLICATE"
#define NAME_MSGNAME_SQLX_RESYNC             "DB_RESYNC"

/* repository-wide */
#define NAME_MSGNAME_SQLX_INFO               "DB_INFO"
#define NAME_MSGNAME_SQLX_LEANIFY            "DB_LEAN"

/* server-wide */
#define NAME_MSGNAME_SQLX_FLUSH              "DB_FLUSH"
#define NAME_MSGNAME_SQLX_RELOAD             "DB_RELOAD"

#define NAME_MSGNAME_SQLX_QUERY              "SQLX_QUERY"
#define NAME_MSGNAME_SQLX_DESTROY            "SQLX_DESTROY"

#endif /*OIO_SDS__sqliterepo__sqlx_macros_h*/
