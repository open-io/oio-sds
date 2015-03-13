/*
OpenIO SDS polix
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

#ifndef OIO_SDS__polix__gridd_module_h
# define OIO_SDS__polix__gridd_module_h 1

enum event_status_e {
	ES_ERROR_DEF = -2,
	ES_ERROR_TMP = -1,
	ES_NOTFOUND  = 0,
	ES_WORKING   = 1,
	ES_DONE      = 2
};

#ifdef MODULE_NAME
# undef MODULE_NAME
#endif
#define MODULE_NAME "polix"

#ifndef  META2_EVTFIELD_NAMESPACE
#  define META2_EVTFIELD_NAMESPACE "NS"
#endif
#ifndef  META2_EVTFIELD_CPATH
#  define META2_EVTFIELD_CPATH "CPATH"
#endif
#ifndef  META2_EVTFIELD_CID
#  define META2_EVTFIELD_CID "CID"
#endif
#ifndef META2_EVTFIELD_M2ADDR
#  define META2_EVTFIELD_M2ADDR "M2ADDR"
#endif
#ifndef META2_EVTFIELD_URL
#  define META2_EVTFIELD_URL "URL"
#endif
#ifndef META2_EVTFIELD_CHUNKS
#  define  META2_EVTFIELD_CHUNKS "CHUNKS"
#endif

//gboolean reply_set_status_code(struct reply_context_s *ctx, const gchar *str_ueid,
//	    enum event_status_e *status, GError **error);

#endif /*OIO_SDS__polix__gridd_module_h*/