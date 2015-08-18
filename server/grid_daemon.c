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

#include <stddef.h>

#include <metautils/lib/metacomm.h>

#include "internals.h"
#include "network_server.h"
#include "stats_holder.h"
#include "transport_gridd.h"
#include "grid_daemon.h"

void
grid_daemon_bind_host(struct network_server_s *server, const gchar *url,
		struct gridd_request_dispatcher_s *dispatcher)
{
	EXTRA_ASSERT(server != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(dispatcher != NULL);
	
	/* Declares the statistics, so event requests never received will have
	 * zeroed stats */
	gridd_register_requests_stats(network_server_get_stats(server),
			dispatcher);

	network_server_bind_host_lowlatency(server, url, dispatcher,
			(network_transport_factory)transport_gridd_factory);
}

