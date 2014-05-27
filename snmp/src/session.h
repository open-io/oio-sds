#ifndef __HTTP_SESSION_H__
#define __HTTP_SESSION_H__ 1

#include <glib.h>

typedef struct rawx_session_s rawx_session_t;

GHashTable * rawx_client_get_statistics(rawx_session_t * session,
		const gchar *url, GError ** err);


/* Lower-level features ---------------------------------------------------- */

#include <metautils/lib/metatypes.h>

rawx_session_t* rawx_client_create_session(addr_info_t *ai, GError **err);
void rawx_client_free_session(rawx_session_t *session);
void rawx_client_session_set_timeout(rawx_session_t *session, gint cnx, gint req);

#endif
