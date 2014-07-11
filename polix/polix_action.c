#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "polix"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <grid_client.h>
#include <gs_internals.h>

#include <metautils/lib/metautils.h>
#include <meta2v2/meta2v2_remote.h>
#include <rawx-lib/src/rawx.h>

#include "polix_action.h"

/* TODO FIXME rewrite with (a variant of gs_locate_container_by_hexid_v2()),
 * because any code out of the C client should not access to the gs_container_t
 * internals! */
char*
polix_action_get_meta2_url_byhexid(char* ns, char* hexid, GError **error)
{
	gs_grid_storage_t *gs = NULL;
	gs_error_t *gs_err = NULL;
	gs_container_t* cid = NULL;
	//struct gs_container_location_s* loc = NULL;
	char* m2_url = NULL;

	GRID_DEBUG("gs_grid_storage_init (%s)...", ns);
	if (!(gs = gs_grid_storage_init(ns, &gs_err))) {
		GSETERROR(error, "Failed to init grid storage client : %s", 
					gs_error_get_message(gs_err));
		goto clean_up;
	}
		
	GRID_DEBUG("gs_get_container_by_hexid (%s)...", hexid);
	cid = gs_get_container_by_hexid(gs, hexid, 0, &gs_err);
	if (cid == NULL) {
		if(gs_err) {
			GSETERROR(error, "Failed to locate container [%s] in namespace: %s", 
						hexid, gs_error_get_message(gs_err));
		} else {
			GSETERROR(error, "Failed to locate container [%s] in namespace: No error", 
						hexid);
		}
		goto clean_up;
	}

	if (cid->meta2_addr.port > 0) {
		char target[64];
		bzero(target, 64);
		addr_info_to_string(&(cid->meta2_addr), target, 64);		
		m2_url = g_strdup(target);
	}

clean_up:
	if(gs_err) {
		gs_error_free(gs_err);
		gs_err = NULL;
	}		

	if (cid)
		gs_container_free(cid);

	if (gs)
		gs_grid_storage_free(gs);

	return m2_url;
}




//-------------------------------------------------------------------------------
// purge request
//-------------------------------------------------------------------------------

static GError*
_delete_chunks_on_rawx(gboolean dryrun, GSList *chunks, guint32 *count, gint64* del_size)
{
	GError* error = NULL;

	GRID_DEBUG("%s, %d chunks to drop", __FUNCTION__, g_slist_length(chunks));

	for(; chunks; chunks = chunks->next) {
		if(!chunks->data)
			continue;
	
		if (dryrun == TRUE) {
	        GRID_DEBUG("(DRYRUN) Delete OK");	        
			*count = *count + 1;
			*del_size += CHUNKS_get_size((struct bean_CHUNKS_s*)chunks->data);
			continue;

		}
		
		if (!rawx_delete_v2(chunks->data, &error)) {
			char* cid = CHUNKS_get_id((struct bean_CHUNKS_s*)chunks->data)->str;
			if (!error)
				error = NEWERROR(1, "Failed to create HTTP session RAWX [%s]", cid);             
			else
				GRID_ERROR("Failed to create HTTP session RAWX [%s]", cid);

		} else {
			*count = *count + 1;
			*del_size += CHUNKS_get_size((struct bean_CHUNKS_s*)chunks->data);
		}
	}

	return error;
}




gboolean polix_action_drop_chunks(gboolean dryrun, GSList *del_chunks_list, 
		polix_action_purge_result_t* result, GError **error)
{
	guint nb_del = 0;
	gint64 del_size = 0;

	*error = _delete_chunks_on_rawx(dryrun, del_chunks_list, &nb_del, &del_size);
	
	if (result) {
		if (nb_del > 0)
			result->del_size = del_size;
		else 
			result->del_size = g_slist_length(del_chunks_list);

		result->nb_del = nb_del;
	}

	return (*error==NULL);
}




/**
 * hexid: cid on char ascii format
 * meta2_url == NULL: search url meta2 for hexid
 * timeout_request =0: used default value
 *
 */
gboolean polix_action_purge(char* namespace, char* hexid, const char* meta2_url, 
		gdouble timeout_request, gboolean dryrun, 
		polix_action_purge_result_t* result, GError **error)
{
	struct hc_url_s *url = NULL;

    if( !hexid || strlen(hexid) != 64) {
    	if (error)
			*error = NEWERROR(1, "Invalid source path (%s/%s)", namespace, hexid);
		 return FALSE;
	}

	if ( !namespace ) {
        if (error)
			*error = NEWERROR(1, "Invalid source path (%s/%s)", namespace, hexid);
		return FALSE;
	}

    // build url
	url = hc_url_empty();
	hc_url_set(url, HCURL_NS,    namespace);
	hc_url_set(url, HCURL_HEXID, hexid);	

	gboolean rc = polix_action_purge_byurl(url, meta2_url, timeout_request, dryrun, 
									result, error);

	hc_url_clean(url);

	return rc;
}



gboolean polix_action_purge_byurl(struct hc_url_s *url, const char* meta2_url,
        gdouble timeout_request, gboolean dryrun, 
		polix_action_purge_result_t* result, GError **error)
{
	GSList *del_chunks_list = NULL;

	if(!meta2_url) {
        if (error)
        	*error = NEWERROR(1, "Invalid meta2_url (%s/%s)", 
				hc_url_get(url, HCURL_NS), hc_url_get(url, HCURL_HEXID));
		return FALSE;
	}

	GRID_DEBUG("Sending PURGE to container [%s]",
			hc_url_get(url, HCURL_WHOLE));

	// sending purge request
	if(!(*error = m2v2_remote_execute_PURGE(meta2_url, NULL,
					url, dryrun, 
					(timeout_request > 0) ? timeout_request : -1,
					(timeout_request > 0) ? timeout_request : -1,
					&del_chunks_list))) {
		polix_action_drop_chunks(dryrun, del_chunks_list, result, error);
		_bean_cleanl2(del_chunks_list);
	}

	return ((*error)?FALSE:TRUE);
}





