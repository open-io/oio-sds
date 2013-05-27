/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LOG_DOMAIN
#define LOG_DOMAIN "rawx.client.stats"
#endif

#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "./rawx_client_internals.h"

#include <metautils.h>

rawx_session_t* rawx_client_create_session( addr_info_t *ai, GError **err )
{
	struct sockaddr_storage ss;
	gsize ss_size = sizeof(ss);
	gchar host[256], port[16];
	rawx_session_t *session;

	session = g_try_malloc0( sizeof(rawx_session_t) );
	if (!session) {
		GSETERROR(err,"Memory allocation failure");
		goto error_session;
	}

	memcpy( &(session->addr), ai, sizeof(addr_info_t) );

	if (!addrinfo_to_sockaddr( ai, (struct sockaddr*)&ss, &ss_size )) {
		GSETERROR(err,"addr_info_t conversion error");
		goto error_addr;
	}

	memset( host, 0x00, sizeof(host) );
	memset( port, 0x00, sizeof(port) );

	if (getnameinfo ( (struct sockaddr* )&ss, ss_size, host, sizeof(host), port, sizeof(port), NI_NUMERICHOST|NI_NUMERICSERV)) {
		GSETERROR(err,"addr_info_t resolution error : %s", strerror(errno));
		goto error_addr;
	}

	session->neon_session = ne_session_create ("http", host, atoi(port));
	if (!session->neon_session) {
		GSETERROR(err,"neon session creation error");
		goto error_neon;
	}

	session->timeout.cnx = 60000;
	session->timeout.req = 60000;

	ne_set_connect_timeout (session->neon_session, session->timeout.cnx/1000);
	ne_set_read_timeout (session->neon_session, session->timeout.req/1000);

	return session;

error_neon:
error_addr:
	g_free(session);
error_session:
	return NULL;
}

void rawx_client_free_session( rawx_session_t *session )
{
	if (!session)
		return;
	ne_session_destroy( session->neon_session );
	memset( session, 0x00, sizeof(rawx_session_t) );
	g_free( session );
}

void rawx_client_session_set_timeout( rawx_session_t *session, gint cnx, gint req )
{
	if (!session)
		return;
	if (req>0) session->timeout.req = req;
	if (cnx>0) session->timeout.cnx = cnx;
}

