/*
OpenIO SDS meta1v2
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

#ifndef OIO_SDS__meta1v2__internals_h
# define OIO_SDS__meta1v2__internals_h 1

/**
 * @addtogroup meta1v2_misc 
 * @{
 */

# include <metautils/lib/metautils.h>
# include <metautils/lib/metacomm.h>

#define CONNECT_RETRY_DELAY 3

# ifndef META1_EVT_TOPIC
#  define META1_EVT_TOPIC "sds.meta1"
# endif

// on references
#define NAME_MSGNAME_M1V2_HAS "M1V2_HAS"
#define NAME_MSGNAME_M1V2_CREATE "M1V2_CREATE"
#define NAME_MSGNAME_M1V2_DESTROY "M1V2_DESTROY"
// on services
#define NAME_MSGNAME_M1V2_SRVSET "M1V2_SRVSET"
#define NAME_MSGNAME_M1V2_SRVNEW "M1V2_SRVNEW"
#define NAME_MSGNAME_M1V2_SRVSETARG "M1V2_SRVSETARG"
#define NAME_MSGNAME_M1V2_SRVDEL "M1V2_SRVDEL"
#define NAME_MSGNAME_M1V2_SRVALL "M1V2_SRVALL"
#define NAME_MSGNAME_M1V2_SRVALLONM1 "M1V2_SRVALLONM1"
#define NAME_MSGNAME_M1V2_SRVAVAIL "M1V2_SRVAVAIL"
// On properties
#define NAME_MSGNAME_M1V2_CID_PROPGET "M1V2_CID_PROPGET"
#define NAME_MSGNAME_M1V2_CID_PROPSET "M1V2_CID_PROPSET"
#define NAME_MSGNAME_M1V2_CID_PROPDEL "M1V2_CID_PROPDEL"
#define NAME_MSGNAME_M1V2_GETPREFIX "M1V2_GET_PREFIXES"
#define NAME_MSGNAME_M1V2_LISTBYPREF "M1V2_LISTBYPREFIX"
#define NAME_MSGNAME_M1V2_LISTBYSERV "M1V2_LISTBYSERV"
#define NAME_MSGNAME_M1V2_UPDATEM1POLICY "M1V2_UPDATEM1POLICY"

#define NAME_HEADER_DRYRUN "DRYRUN"

MESSAGE meta1_create_message(const gchar *reqname, const container_id_t cid);

void meta1_enheader_addr_list(MESSAGE req, const gchar *fname, GSList *addr);

/** @} */

#endif /*OIO_SDS__meta1v2__internals_h*/
