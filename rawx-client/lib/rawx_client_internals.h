/*
OpenIO SDS rawx-client
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#ifndef OIO_SDS__rawx_client__lib__rawx_client_internals_h
# define OIO_SDS__rawx_client__lib__rawx_client_internals_h 1

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

#endif /*OIO_SDS__rawx_client__lib__rawx_client_internals_h*/