/*
OpenIO SDS server
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

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.utils.transport.echo"
#endif

#include <glib.h>

#include "internals.h"
#include "network_server.h"
#include "transport_echo.h"

static int
echo_notify_input(struct network_client_s *clt)
{
	struct data_slab_s *slab;

	while (data_slab_sequence_has_data(&(clt->input))) {
		if (!(slab = data_slab_sequence_shift(&(clt->input))))
			break;
		network_client_send_slab(clt, slab);
	}
	return clt->transport.waiting_for_close ? RC_NODATA : RC_PROCESSED;
}

void
transport_echo_factory(gpointer factory_udata, struct network_client_s *clt)
{
	struct network_transport_s *transport;

	(void) factory_udata;
	transport = &(clt->transport);

	transport->client_context = NULL;
	transport->clean_context = NULL;
	transport->notify_input = echo_notify_input;
	transport->notify_error = NULL;

	network_client_allow_input(clt, TRUE);
}

