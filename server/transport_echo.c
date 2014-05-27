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

