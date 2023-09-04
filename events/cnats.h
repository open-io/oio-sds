/*
OpenIO SDS event queue
Copyright (C) 2023 OVH SAS

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

#ifndef OIO_SDS__event__nats_h
#define  OIO_SDS__event__nats_h 1

#include <glib.h>
#include <nats.h>

#define NATS_PREFIX "nats://"

struct nats_s
{
	gchar *hostname;
	natsConnection *conn;
	natsOptions *opts;
	jsCtx *js_ctx;
};


GError*
nats_create(const gchar *endpoint, struct nats_s **out);

GError*
nats_declare_stream(jsCtx *js_ctx, const char* stream, const char* subject);

GError*
nats_connect(struct nats_s *nats);

GError*
nats_send_msg(struct nats_s *nats, void *msg, size_t msglen,
		const gchar *routing_key);

void
nats_destroy(struct nats_s *nats);


#endif /* OIO_SDS__event__nats_h*/