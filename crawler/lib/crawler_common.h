/*
OpenIO SDS crawler
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef OIO_SDS__crawler__lib__crawler_common_h
# define OIO_SDS__crawler__lib__crawler_common_h 1

#include <glib.h>
#include <gmodule.h>

#include <dbus/dbus.h>
#include <time.h>

#include "transp_layer.h"
#include "transp_layer_cmd.h"
#include "crawler_constants.h"
#include "crawler_tools.h"

/******************************************************************************/
/* callback function                                                          */
/* request from crawler_cmd                                                   */
/* generate by generate_xx_glue_h.sh and atos.grid.crawler.xml                */
/******************************************************************************/
// crawler: callback function
gboolean crawler_command(TCrawlerBusObject *obj, const char* cmd, const char* sender,
	const char *alldata, GError **error);
gboolean crawler_ack(TCrawlerBusObject *obj, const char* cmd,  
	const char *alldata, GError **error);

// crawler_cmd: callback function
gboolean crawlerCmd_ack(TCrawlerBusObject *obj, const char* cmd,
    const char *alldata, GError **error);

/******************************************************************************/
/******************************************************************************/

const TCrawlerBusObjectInfo* crawler_getObjectInfo(void);

typedef struct {
	char*        svc_name;  // service name
	TCrawlerReq* req;       // request to connectd to

	gboolean bEnabled;      // =TRUE if autorized to transmit data, else =FALSE

} TCrawlerSvcAct;

typedef struct {
	GSList* list;      // list of  item : TCrawlerSvcAct	
	GSList* crt;       // future action to addressed a data...
                       // pointer to an item of svc_act
} TCrawlerSvcActList;

TCrawlerSvcAct*  crawler_ServiceAction_GetCrtService(TCrawlerSvcActList* list_svc);
TCrawlerSvcAct*  crawler_ServiceAction_GetNextService(TCrawlerSvcActList* list_svc, gboolean bEnabled);

GError*  crawler_ServiceAction_InitList(TCrawlerBus *handle, TCrawlerSvcActList** list_svc,
            char* prefix_service_action_name, char* action_name);
void     crawler_ServiceAction_ClearList(TCrawlerSvcActList** list_svc);
GError*  crawler_ServiceAction_UpdateList(TCrawlerBus *handle, TCrawlerSvcActList* list_svc,
            char* prefix_service_action_name, char* action_name);
void     crawler_ServiceAction_DumpList(TCrawlerSvcActList* list_svc);
char*    crawler_ServiceAction_ListToStr(TCrawlerSvcActList* list_svc);

/******************************************************************************/
/******************************************************************************/

struct action_context {
	guint64 id; /* Unique context ID (local) */
	guint pos; /* Index of currently running action for this context (starts with 0) */
	GVariant* occur; /* Context related occurence */
	time_t time_stamp; /* Beginning of the current signal send */
};

/**
 * This function initializes a new action context
 */
struct action_context* new_action_context(void);

/**
 * This method frees a given trip action context
 */
void free_action_context(struct action_context*);

/******************************************************************************/
/******************************************************************************/

#endif /*OIO_SDS__crawler__lib__crawler_common_h*/