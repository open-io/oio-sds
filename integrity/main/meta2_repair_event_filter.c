#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "integrity.lib.meta2_repair"
#endif

#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <db.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <grid_client.h>
#include <cluster/lib/gridcluster.h>
#include <gridcluster_remote.h>
#include <rawx-client/lib/rawx_client.h>
#include <meta2/remote/meta2_remote.h>

#include "../lib/chunk_db.h"
#include "./event_puller.h"
#include "./event_filter.h"

gboolean
fix_meta2_from_rawx(char *ns_name, char *container_name, chunk_info_t *chunk, GError **error)
{
	(void) ns_name;
	(void) container_name;
	(void) chunk;
	(void) error;
	return TRUE;
}

gboolean
repair_meta2(const struct broken_event_s *broken_event, void *data, GError **error)
{
	(void) data;

	NOTICE("Meta2_repair_event_filter process launched");
	if(!notify_broken_events_processing(broken_event, error)){
		NOTICE("Failed to notify event processing to event_puller");
	}
	else
		NOTICE("event processs notify to event puller");
	return TRUE;
}

gboolean
init_meta2_repair_event_filter(GError **error)
{
        struct broken_event_filter_s filter;

        memset(&filter, 0, sizeof(filter));

        filter.location = L_META2;
        filter.property = P_CONTAINER_ID | P_CONTENT_NAME | P_CONTENT_SIZE | P_CONTENT_CHUNK_NB | P_CONTENT_METADATA |
            P_CONTENT_SYSMETADATA | P_CHUNK_ID | P_CHUNK_SIZE | P_CHUNK_HASH | P_CHUNK_POS | P_CHUNK_METADATA;
        filter.reason = R_MISSING | R_MISMATCH | R_FORMAT;

        if (!register_event_filter(&filter, repair_meta2, NULL, error)) {
                GSETERROR(error, "Failed to register filter");
                return FALSE;
        }

        return TRUE;
}

