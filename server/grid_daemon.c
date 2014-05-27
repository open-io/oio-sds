#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.utils.gridd"
#endif

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

