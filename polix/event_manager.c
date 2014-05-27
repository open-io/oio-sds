#ifndef G_LOG_DOMAIN
#  define G_LOG_DOMAIN "polix"
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/queue.h>

#include <grid_client.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <cluster/lib/gridcluster.h>
#include <meta2/remote/meta2_remote.h>
#include <meta2/remote/meta2_services_remote.h>
#include <meta2v2/meta2_bean.h>
#include <meta2v2/meta2_events.h>
#include <meta2v2/generic.h>
#include <meta2v2/meta2_bean.h>

#include "event_manager.h"
#include "polix_action.h"
#include "gridd_module.h"


struct event_manager_s
{
	const gchar *type_ref;

	gboolean (*manage)(
			grid_polix_t *polix,
			const gchar *ueid,
			gridcluster_event_t *e,
			gboolean *retry,
			gboolean dryrun, 
			GError **error);
};




static GSList *
polix_event_get_unmarshall_list_field(gridcluster_event_t *event, const gchar *name)
{
	GByteArray *gba = NULL;
	GSList* list = NULL;

	gba = g_hash_table_lookup(event, name);
	if (!(gba = g_hash_table_lookup(event, name)))
    	return NULL;

	list = bean_sequence_unmarshall(gba->data, gba->len);

	return list;
}




static gboolean
polix_event_content_delete(grid_polix_t *polix, const gchar *ueid,
		gridcluster_event_t *event, gboolean *allow_retry, gboolean dryrun, GError **error)
{
	gboolean rc = FALSE;
	gchar *str_ns, *str_cid, *str_cpath, *str_m2addr;
	char* m2_url = NULL;

	(void)ueid;
	(void)allow_retry;

	str_ns    = gridcluster_event_get_string(event, META2_EVTFIELD_NAMESPACE); 
	str_cpath = gridcluster_event_get_string(event, META2_EVTFIELD_CPATH);
	str_cid   = gridcluster_event_get_string(event, META2_EVTFIELD_CID);
	str_m2addr= gridcluster_event_get_string(event, META2_EVTFIELD_M2ADDR);

	if (!str_ns) {
		GSETCODE(error, 500+EINVAL, "Invalid event : no namespace");
		goto label_exit;		
	}

	if (!str_cid) {
		GSETCODE(error, 500+EINVAL, "Invalid event : no container id");
		goto label_exit;
	}


	if (!str_m2addr) {
		m2_url = polix_action_get_meta2_url_byhexid(str_ns, str_cid, error);
		if (!m2_url) {
			GSETERROR(error, "Content purge error ID[%s] CPATH[%s]", str_cid, str_cpath);
			goto label_exit;
		} 
	} else {
		m2_url = g_strdup(str_m2addr);
	}
	GRID_DEBUG("m2_url found: [%s] for [%s/%s]", m2_url, str_ns, str_cid);

	//purge function
	polix_action_purge_result_t result;
	memset(&result, 0, sizeof(polix_action_purge_result_t));
	rc = polix_action_purge(str_ns, str_cid, m2_url, polix->timeout, 
						FALSE, &result, error);	
	if (!rc) {
		if (error && allow_retry && CODE_CONTAINER_NOTFOUND == gerror_get_code(*error)) {
			GSList* list = NULL;

			g_clear_error(error);
			*error = NULL;

			GRID_DEBUG("Used List of chunk saved on event");
			list = polix_event_get_unmarshall_list_field(event, META2_EVTFIELD_CHUNKS);
			if (list != NULL) {
				GError *err = NULL;

				memset(&result, 0, sizeof(polix_action_purge_result_t));
				rc = polix_action_drop_chunks(dryrun, list, &result, &err);

				if (!rc) {
					GSETERROR(error, "NO RETRY ALLOWED");
					GRID_ERROR("(%d) %s", err->code, err->message);
					g_clear_error(&err);
					rc = TRUE;
				}

				_bean_cleanl2(list);
			} else {
				GRID_DEBUG("No Chunk to delete");
				rc = TRUE;
			}
			*allow_retry = 0;
		}
	}

	if (!rc) {
		GSETERROR(error, "Content purge error ID[%s] CPATH[%s]", str_cid, str_cpath);
	} else {
		if(0 < result.nb_del) {
			GRID_DEBUG("%s%"G_GUINT32_FORMAT" chunks deleted ("
					"%"G_GINT64_FORMAT" bytes deleted) from %s/%s", (dryrun==TRUE)?"(DRYRUN)":"",
					result.nb_del, result.del_size, str_ns, str_cid);
		} else {
			GRID_DEBUG("No chunks deleted from %"G_GINT64_FORMAT" sized chunk's list of %s/%s",
					result.del_size, str_ns, str_cid);
		}
	}

label_exit:
	if (m2_url) 	g_free(m2_url);
	if (str_ns)	    g_free(str_ns);
	if (str_cid) 	g_free(str_cid);
	if (str_cpath)	g_free(str_cpath);
	if (str_m2addr) g_free(str_m2addr);
	
	return rc;
}


/* ------------------------------------------------------------------------- */

static struct event_manager_s MANAGERS[] =
{
	//	{"meta2.CONTAINER.create",    container_create  },
	{META2_EVTTYPE_DESTROY,   polix_event_content_delete       },
	//	{"meta2.CONTENT.put",         content_put       },
	{META2_EVTTYPE_DELETE,    polix_event_content_delete       },
	//	{"meta2.CONTENT.prop.set",    content_put       },
	//	{"meta2.CONTENT.prop.del",    content_put       },
	//	{"meta2.CONTAINER.prop.set",  container_props   },
	//	{"meta2.CONTAINER.prop.del",  container_props   },
	//	{"meta2.CONTAINER.evt.add",   container_evt_add },
	//	{"meta2.CONTAINER.evt.diff",  container_evt_diff},
	//	{"meta2.CONTAINER.evt.rm",    container_evt_rm  },
	{NULL, NULL}
};


grid_polix_t* polix_event_create(void)
{
	grid_polix_t* p = g_malloc0(sizeof(grid_polix_t));
	if (!p)
		return NULL;
	p->timeout = 0;
	return p;
}


void polix_event_free(grid_polix_t* polix)
{
	if (polix)
		g_free(polix);
}




gboolean
polix_event_manager(grid_polix_t *polix, const gchar *ueid,
		gridcluster_event_t *event, gboolean *flag_retry, gboolean flag_dryrun, GError **err)
{
	struct event_manager_s *manager;
	gchar type[256];
	gsize type_size;

	/* By default, upon error we allow the caller to retry */
	if (flag_retry)
		*flag_retry = TRUE;

	if (!polix|| !ueid || !event) {		
		GSETCODE(err, 500+EINVAL, "Invalid parameter");
		return FALSE;
	}


	GRID_DEBUG("Managing UEID[%s]", ueid);

	bzero(type, sizeof(type));
	type_size = gridcluster_event_get_type(event, type, sizeof(type));
	if (!type_size || !*type) {
		GSETCODE(err, 400, "Event has no type");
		if (flag_retry)
			*flag_retry = FALSE;
		return TRUE;
	}

	for (manager=MANAGERS; manager->type_ref ;manager++) {
		if (0 != g_ascii_strcasecmp(type, manager->type_ref))
			continue;

		GRID_DEBUG("Event manager found for UEID[%s] type[%s]", ueid, type);

		if (manager->manage(polix, ueid, event, flag_retry, flag_dryrun, err)) {
			GRID_DEBUG("Managed UEID[%s] type[%s]", ueid, type);
			return TRUE;
		}

		GRID_ERROR("Event management failed for UEID[%s] type[%s] : %s", ueid, type,
				err ? gerror_get_message(*err) : "unknown error");

		GSETERROR(err, "Event management error");
		return FALSE;
	}

	GRID_DEBUG("No event manager found for UEID[%s] type[%s]", ueid, type);
	GSETCODE(err, 400, "Unexpected event type [%s]", type);
	return FALSE;
}

