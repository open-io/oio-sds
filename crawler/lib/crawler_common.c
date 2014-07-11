#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "atos.grid.crawler.common"
#endif //G_LOG_DOMAIN

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <metautils/lib/metautils.h>

#include <glib.h>
#include <gmodule.h>

#include "transp_layer.h"
#include "crawler_common.h"
#include "crawler-glue.h"
#include "crawler_tools.h"


const TCrawlerBusObjectInfo* crawler_getObjectInfo(void)
{
	return &dbus_glib_crawler_object_info;
}



GError*  crawler_ServiceAction_AddServices(TCrawlerBus *handle, 
		TCrawlerSvcActList* list_svc, gchar* svc_name)
{
	TCrawlerReq* r = NULL;
	GError* error  = NULL;;
	TCrawlerSvcAct* elt = NULL;

	GRID_DEBUG("Service added: %s", svc_name);

	// connected new  services
	error = crawler_bus_req_init(handle, &r, svc_name, SERVICE_PATH, SERVICE_IFACE_ACTION);
	if (error) {
		g_prefix_error(&error, "Failed to connectd to new finded actions services %s : ", 
				svc_name);
		return error;
	} 


	// add new service to internal listed
	elt = g_new0(TCrawlerSvcAct, 1);
	if (!elt) {
		crawler_bus_req_clear(&r);
		return NEWERROR(-1, "%s: Failed to allocated memory (TCrawlerSvcAct)", __FUNCTION__);
	}
	elt->req = r;
	int len = strlen(svc_name);
	elt->svc_name = g_malloc0(len+10);
	elt->bEnabled = TRUE;
	if (!elt->svc_name) {
		crawler_bus_req_clear(&r);
		g_free(elt);
		return NEWERROR(-1, "%s: Failed to allocated memory (svc_name)", __FUNCTION__);
	}

	g_strlcpy(elt->svc_name, svc_name, len + 9);
	list_svc->list = g_slist_append(list_svc->list, elt);

	return NULL;
}

GError*  crawler_ServiceAction_RemoveServices(TCrawlerSvcActList* list_svc, TCrawlerSvcAct* elt)
{
	TCrawlerSvcAct* eltCrt = NULL;
	gboolean bCrtToSearch = FALSE;

	if (list_svc->crt != NULL) {
		eltCrt = (TCrawlerSvcAct*) list_svc->crt->data;
		if (eltCrt == elt)
			bCrtToSearch = TRUE;
	} else bCrtToSearch = TRUE;

	// disconnect and free service from internal list	
	list_svc->list = g_slist_remove(list_svc->list, elt);	

	GRID_DEBUG("Services deleted: %s", elt->svc_name);
	crawler_bus_req_clear(&(elt->req));
	g_free(elt->svc_name);
	g_free(elt);

	// reWrite the next current pointer, ...
	if (bCrtToSearch == TRUE) {
		list_svc->crt = NULL;
		crawler_ServiceAction_GetNextService(list_svc, TRUE);
	}

	return NULL;
}


TCrawlerSvcAct*  crawler_ServiceAction_GetCrtService(TCrawlerSvcActList* list_svc)
{
	return (TCrawlerSvcAct*) list_svc->crt->data;
}

TCrawlerSvcAct*  crawler_ServiceAction_GetNextService(TCrawlerSvcActList* list_svc, gboolean bEnabled)
{
	GSList* pList  = NULL;
	GSList* oldCrt = NULL;	
	TCrawlerSvcAct* elt = NULL;

	//--------
	// if empty list
	if (list_svc->list == NULL)
		return NULL;

	//---------
	// if 0 or 1 item on list
	int nb = g_slist_length(list_svc->list);
	if (nb == 0) return NULL;
	if (nb == 1) {
		if ( list_svc->crt == NULL)
			list_svc->crt = list_svc->list;
		return crawler_ServiceAction_GetCrtService(list_svc);
	}

	//----------
	// n item on list...
	// save next crt
	TCrawlerSvcAct* eltOldCrt = crawler_ServiceAction_GetCrtService(list_svc);

	// search the next->next elt... for the next time
	oldCrt = list_svc->crt;
	pList  = g_slist_next(oldCrt);
	if (!pList) {
		//at the begining
		pList = list_svc->list;
	}

	// if > 1 item on the list
	list_svc->crt = NULL;
	while(pList) {
		elt = (TCrawlerSvcAct*) pList->data;
		if (elt->bEnabled == FALSE) {
			if (bEnabled == FALSE) {
				list_svc->crt = pList;	
				break;
			}
		} else {
			list_svc->crt = pList;
			break;
		}

		pList = g_slist_next(pList);
		if (!pList) {
			// at the begining
			pList = list_svc->list;
		}
		if (pList == oldCrt) {
			list_svc->crt = pList;
			break;
		}
	}

	return eltOldCrt;
}





GError*  crawler_ServiceAction_InitList(TCrawlerBus *handle, TCrawlerSvcActList** list_svc,
		char* prefix_service_action_name, char* action_name)
{
	GError* error = NULL;

	*list_svc = g_malloc0(sizeof(TCrawlerSvcActList));
	(*list_svc)->list= NULL;
	(*list_svc)->crt = NULL;

	error = crawler_ServiceAction_UpdateList(handle, *list_svc, 
			prefix_service_action_name, action_name);

	(*list_svc)->crt = (*list_svc)->list;

	return error;
}


void crawler_ServiceAction_ClearList(TCrawlerSvcActList** list_svc)
{
	TCrawlerSvcAct* elt = NULL;
	GSList* pList = NULL;
	if ((list_svc == NULL)||(*list_svc== NULL))
		return;

	pList = (*list_svc)->list;
	(*list_svc)->crt = NULL;    
	for(;pList;pList = g_slist_next(pList)) {
		elt = (TCrawlerSvcAct*) pList->data;
		GRID_INFO("%s...%d\n", elt->svc_name, elt->bEnabled);
		crawler_ServiceAction_RemoveServices(*list_svc, elt);		
	}

	g_free(*list_svc);
	*list_svc = NULL;
}


GError*  crawler_ServiceAction_UpdateList(TCrawlerBus *handle, TCrawlerSvcActList* list_svc, 
		char* prefix_service_action_name, char* action_name)
{
	char** listnames = NULL;
	static TCrawlerReq* req = NULL;
	TCrawlerSvcAct* elt = NULL;
	char** ptr = NULL;
	GSList* pList = NULL;
	GSList* pListNext = NULL;
	gboolean bOk = FALSE;
	char tmp_action_name[1024];
	GError* error = NULL;


	buildServiceName(tmp_action_name, 1024, prefix_service_action_name, action_name, 0, TRUE);

	if (!req)
		crawler_bus_reqBase_init(handle, &req);

	//--------------
	//get list of svc connectd on bus
	error = crawler_bus_reqBase_GetListNames(req, &listnames);
	if (error) {
		g_prefix_error(&error, "Failed to update List of services atcion: ");
		g_strfreev(listnames);
		listnames = NULL;
		crawler_bus_req_clear(&req);
		return error;
	}


	//--------------
	//close and delete svc_listed not existed on list connectd
	pList = list_svc->list;
	bOk = FALSE;
	for(;pList;pList = g_slist_next(pList)) {
		elt = (TCrawlerSvcAct*) pList->data;
		bOk = FALSE;

		for (ptr = listnames; *ptr; ptr++) {
			if (g_strcmp0(elt->svc_name, *ptr) == 0) {				
				bOk = TRUE;
				break;	
			}
		}
		if (bOk == FALSE) { 
			elt->bEnabled = FALSE;
		}
	}

	//--------------
	// delete all enabled = FALSE (diconnected or an errors occurs during reply request...)
	pList = list_svc->list;
	while (pList) {
		pListNext = g_slist_next(pList);
		elt = (TCrawlerSvcAct*) pList->data;
		if (elt->bEnabled == FALSE) 
			crawler_ServiceAction_RemoveServices(list_svc, elt);
		pList = pListNext;
	}



	//--------------
	// add new svc connectd if not exist on svc_listed	
	for (ptr = listnames; *ptr; ptr++) {
		pList = list_svc->list;
		bOk = FALSE;

		if (g_ascii_strncasecmp(*ptr, tmp_action_name, 
					strlen(tmp_action_name)) != 0)
			continue;

		for(;pList;pList = g_slist_next(pList)) {
			elt = (TCrawlerSvcAct*) pList->data;
			if (g_strcmp0(elt->svc_name, *ptr) == 0) {
				bOk = TRUE;
				break;
			}
		} 

		if (bOk == FALSE) {
			GError* errTmp = NULL;
			errTmp = crawler_ServiceAction_AddServices(handle, list_svc, *ptr);
			if (errTmp) {
				if (!error) error = errTmp;
				else        g_clear_error(&errTmp);
			}
		}
	}

	//--------------
	// free allocated vars
	g_strfreev(listnames);

	return error;
}


void crawler_ServiceAction_DumpList(TCrawlerSvcActList* list_svc)
{
	TCrawlerSvcAct* elt = NULL;
	GSList* pList = list_svc->list;

	GRID_INFO("Services used: \n");
	for(;pList;pList = g_slist_next(pList)) {
		elt = (TCrawlerSvcAct*) pList->data;		
		GRID_INFO("> %s ... %d\n", elt->svc_name, elt->bEnabled);
	}
	GRID_INFO("... end Services used.\n");
}

char* crawler_ServiceAction_ListToStr(TCrawlerSvcActList* list_svc)
{
	TCrawlerSvcAct* elt = NULL;
	GSList* pList = NULL;
	GString* str = NULL;
	str = g_string_new("");
	int num = 0;

	pList = list_svc->list;

	for(;pList;pList = g_slist_next(pList)) {
		elt = (TCrawlerSvcAct*) pList->data;

		if (num != 0)
			g_string_append(str, "|");
		g_string_append_printf(str, "%-60.60s %s", elt->svc_name, 
				(elt->bEnabled)?"Used":"Not used/error?");

		num++;
	}

	return g_string_free(str, FALSE);
}







struct action_context* new_action_context(void)
{
	struct action_context* new_action_ctx = g_try_malloc0(sizeof(struct action_context));

	if (NULL == new_action_ctx)
		return NULL;

	new_action_ctx->id = g_get_monotonic_time();
	new_action_ctx->pos = 0;

	return new_action_ctx;
}

void free_action_context(struct action_context* ac)
{
	if (NULL != ac) {
		if (NULL != ac->occur) {
			g_variant_unref(ac->occur);
			ac->occur = NULL;
		}
		g_free(ac);
	}
}

