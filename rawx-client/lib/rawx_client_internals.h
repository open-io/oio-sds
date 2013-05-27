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

#ifndef __RAWX_CLIENT_INTERNALS_H__
# define __RAWX_CLIENT_INTERNALS_H__

#include <glib.h>
#include <metatypes.h>

#include <neon/ne_basic.h>
#include <neon/ne_request.h>
#include <neon/ne_session.h>

#include "./rawx_client.h"

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

GHashTable *body_parser(GByteArray * buffer, GError ** err);

#endif /*__RAWX_CLIENT_INTERNALS_H__*/
