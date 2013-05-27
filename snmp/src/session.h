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

#ifndef __HTTP_SESSION_H__
#define __HTTP_SESSION_H__ 1

#include <glib.h>

typedef struct rawx_session_s rawx_session_t;

GHashTable * rawx_client_get_statistics(rawx_session_t * session,
		const gchar *url, GError ** err);


/* Lower-level features ---------------------------------------------------- */

#include <metatypes.h>

rawx_session_t* rawx_client_create_session(addr_info_t *ai, GError **err);
void rawx_client_free_session(rawx_session_t *session);
void rawx_client_session_set_timeout(rawx_session_t *session, gint cnx, gint req);

#endif
