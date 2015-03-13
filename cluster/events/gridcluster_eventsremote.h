/*
OpenIO SDS cluster
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

#ifndef OIO_SDS__cluster__events__gridcluster_eventsremote_h
# define OIO_SDS__cluster__events__gridcluster_eventsremote_h 1

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <cluster/events/gridcluster_events.h>

# ifndef  REQ_EVT_PUSH
#  define REQ_EVT_PUSH "REQ_EVT_PUSH"
# endif
# ifndef  REQ_EVT_STATUS
#  define REQ_EVT_STATUS "REQ_EVT_STATUS"
# endif
/* Definitive error, no retry necessary */
# ifndef  CODE_EVT_ERROR_DEF
#  define CODE_EVT_ERROR_DEF      -2
# endif
/* Temporary error, please retry _later_ */
# ifndef  CODE_EVT_ERROR_TMP
#  define CODE_EVT_ERROR_TMP      -1
# endif
# ifndef  CODE_EVT_NOTFOUND
#  define CODE_EVT_NOTFOUND        0
# endif
# ifndef  CODE_EVT_WORKINPROGRESS
#  define CODE_EVT_WORKINPROGRESS  1
# endif
# ifndef  CODE_EVT_WORKDONE
#  define CODE_EVT_WORKDONE        2
# endif

# ifndef MSG_HEADER_UEID
#  define MSG_HEADER_UEID "EUID"
# endif
# ifndef MSG_HEADER_EVENT_STATUS
#  define MSG_HEADER_EVENT_STATUS "EVENT_STATUS"
# endif
# ifndef MSG_HEADER_EVENT_MESSAGE
#  define MSG_HEADER_EVENT_MESSAGE "EVENT_MESSAGE"
# endif
# ifndef EVENT_FIELD_TYPE
#  define EVENT_FIELD_TYPE "TYPE"
# endif
# ifndef EVENT_TYPE_MAX_SIZE
#  define EVENT_TYPE_MAX_SIZE 128
# endif

/**
 * @return 
 */
gboolean gridcluster_push_event(struct metacnx_ctx_s *cnx, const gchar *ueid, gridcluster_event_t *event,
	GError **event_error, GError **error);

/**
 *
 */
gboolean gridcluster_status_event(struct metacnx_ctx_s *cnx, const gchar *ueid, GError **event_error,
	GError **error);

#endif /*OIO_SDS__cluster__events__gridcluster_eventsremote_h*/