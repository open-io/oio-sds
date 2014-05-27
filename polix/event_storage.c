#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "polix"
#endif

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <math.h>

#include <metautils/lib/metautils.h>
#include <gridd/main/plugin.h>
#include <gridd/main/message_handler.h>
#include <gridd/main/srvstats.h>
#include <gridd/main/srvtimer.h>
#include <gridd/main/srvalert.h>
#include <cluster/lib/gridcluster.h>

#include "./event_storage.h"
#include "./gridd_module.h"

static GSList* g_list_pe = NULL;


typedef struct {
	polix_event_t*   pe;
	event_status_et  status;
} polix_event_storage_t;



polix_event_t* pe_create(void)
{
	polix_event_t* pe = g_malloc0(sizeof(polix_event_t));
	if (!pe)
		return NULL;

	pe->ueid = NULL;
	pe->event = NULL;
	return pe;
}


void pe_free(polix_event_t* pe)
{
	if (!pe)
		return;

	if (pe->ueid)  g_free(pe->ueid);
	if (pe->event)  g_hash_table_destroy(pe->event);
	g_free(pe);
}





gboolean pes_init(void)
{
	g_list_pe = NULL;
	return TRUE;
}


void pes_close(void)
{	
	polix_event_storage_t* pes = NULL;

	GSList* lst = g_list_pe;
	for(;lst;lst=g_slist_next(lst)) {
		pes = (polix_event_storage_t*) lst->data;
		pe_free(pes->pe);
		pes->pe = NULL;				
	}
	g_slist_free_full(g_list_pe, g_free);
}


polix_event_storage_t* pes_get(const gchar* ueid)
{
	polix_event_storage_t* pes = NULL;

	if (!ueid)
		return NULL;

	GSList* lst = g_list_pe;
	for(;lst;lst=g_slist_next(lst)) {
		pes = (polix_event_storage_t*) lst->data;
		if (g_strcmp0(ueid, pes->pe->ueid) == 0)
			break;
		else pes = NULL;
	}

	return pes;
}



gboolean pes_IsExist(const gchar* ueid)
{
	return ((pes_get(ueid))?TRUE:FALSE);
}



polix_event_storage_t* pes_add(polix_event_t *pe, event_status_et status)
{
	polix_event_storage_t* pes = NULL;

	if (!pe)
		return NULL;

	// search and delete it if already exist if not exist on list
	pes_delete(pe->ueid, FALSE);

	// init storage
	pes = g_malloc0(sizeof(polix_event_storage_t));
	if (!pes) {
		pe_free(pe);
		return NULL;
	}
	pes->pe     = pe;
	pes->status = status;

	// save event on storage
	g_list_pe = g_slist_append(g_list_pe, pes);

	return pes;
}


gboolean pes_get_status(const gchar* ueid, event_status_et *status)
{
	polix_event_storage_t* pes = NULL;
	
	if (!ueid)
		return FALSE;
	
	if (!status)
		return FALSE;

	pes = pes_get(ueid);
	if (!pes) {
		*status = ES_NOTFOUND;
		return TRUE;
	}

	*status = pes->status;
	return TRUE;
}

gboolean pes_set_status(polix_event_t *pe, event_status_et status)
{
	polix_event_storage_t* pes = NULL;
	if (!pe)
		return FALSE;

	pes = pes_add(pe, status);
	return ((pes)?TRUE:FALSE);
}

gboolean pes_delete(const gchar* ueid, gboolean bAll)
{
	polix_event_storage_t* pes = NULL;
	
	if (!ueid)
		return FALSE;

	pes = pes_get(ueid);
	if (pes) {
		if (bAll)
			pe_free(pes->pe);
		g_list_pe = g_slist_remove(g_list_pe, pes);
		g_free(pes);
	}

	return TRUE;
}


