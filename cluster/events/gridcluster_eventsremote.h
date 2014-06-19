#ifndef __GRIDCLUSTER__EVENTS_REMOTE__H__
# define __GRIDCLUSTER__EVENTS_REMOTE__H__

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

#endif /*__GRIDCLUSTER__EVENTS_REMOTE__H__*/
