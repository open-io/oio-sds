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
#define LOG_DOMAIN "integrity.lib.meta2_repair"
#endif

#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <glib.h>
#include <db.h>

#include <metatypes.h>
#include <metautils.h>
#include <metacomm.h>
#include <rawx_client.h>
#include <grid_client.h>
#include <gridcluster.h>
#include <gridcluster_remote.h>
#include <meta2_remote.h>

#include "../lib/chunk_db.h"
#include "./event_puller.h"	
#include "./event_filter.h"

#if 0
static int
create_container (gs_grid_storage_t *gs, const char *name, gs_error_t **err)
{
        gs_error_t *localError = NULL;
        gs_container_t *container = NULL;

        container = gs_get_container (gs, name, 0, &localError);

	/* test if the container doesn't exist */
        if (!container) {

                container = gs_get_container (gs, name, 1, &localError);

                if (!container) {
                        ERROR("cannot find the container '%s'\n", name);
                        g_print("failed:%s\n", name);
                        goto error_container;
                } else {
                        g_print("created:%s\n", name);
                }

        } else {
                g_print("already:%s\n", name);
        }

        gs_container_free (container);

        /*forget the possible first 'not found' error*/
        if (localError)
                gs_error_free(localError);

        return 1;

error_container:
        if (err) {
                *err = localError;
        } else {
                if (localError)
                        gs_error_free(localError);
        }
        return 0;
}
#endif

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

