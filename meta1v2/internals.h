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

MESSAGE meta1_create_message(const gchar *reqname, const container_id_t cid);

void meta1_enheader_addr_list(MESSAGE req, const gchar *fname,
		GSList *addr);

/** @} */

#endif /*OIO_SDS__meta1v2__internals_h*/
