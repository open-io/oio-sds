/*
OpenIO SDS meta1v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

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

#ifndef OIO_SDS__meta1v2__internals_h
# define OIO_SDS__meta1v2__internals_h 1

# include <metautils/lib/metautils.h>

# ifndef META1_EVT_TOPIC
#  define META1_EVT_TOPIC "sds.meta1"
# endif

#define NAME_MSGNAME_M1V2_USERINFO    "M1_HAS"
#define NAME_MSGNAME_M1V2_USERCREATE  "M1_CREATE"
#define NAME_MSGNAME_M1V2_USERDESTROY "M1_DESTROY"
#define NAME_MSGNAME_M1V2_SRVLIST     "M1_LIST"
#define NAME_MSGNAME_M1V2_SRVLINK     "M1_LINK"
#define NAME_MSGNAME_M1V2_SRVFORCE    "M1_FORCE"
#define NAME_MSGNAME_M1V2_SRVRENEW    "M1_RENEW"
#define NAME_MSGNAME_M1V2_SRVCONFIG   "M1_CONFIG"
#define NAME_MSGNAME_M1V2_SRVUNLINK   "M1_UNLINK"
#define NAME_MSGNAME_M1V2_SRVRELINK   "M1_RELINK"
#define NAME_MSGNAME_M1V2_PROPGET     "M1_PGET"
#define NAME_MSGNAME_M1V2_PROPSET     "M1_PSET"
#define NAME_MSGNAME_M1V2_PROPDEL     "M1_PDEL"
#define NAME_MSGNAME_M1V2_GETPREFIX   "M1_ALLPREF"
#define NAME_MSGNAME_M1V2_SRVALLONM1  "M1_ALLSRV"

#endif /*OIO_SDS__meta1v2__internals_h*/
