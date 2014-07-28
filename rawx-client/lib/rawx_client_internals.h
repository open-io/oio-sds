#ifndef __RAWX_CLIENT_INTERNALS_H__
# define __RAWX_CLIENT_INTERNALS_H__

#include <neon/ne_basic.h>
#include <neon/ne_request.h>
#include <neon/ne_session.h>

#include <metautils/lib/metatypes.h>

#include <glib.h>

#include "rawx_client.h"

struct rawx_session_s
{
	GByteArray *request_id;
	addr_info_t addr;
	struct
	{
		gint cnx;
		gint req;
	} timeout;
	ne_session *neon_session;
};

int body_reader(void *userdata, const char *buf, size_t len);

GHashTable *header_parser(ne_request *request);
GHashTable *body_parser(GByteArray * buffer, GError ** err);

#endif /*__RAWX_CLIENT_INTERNALS_H__*/
