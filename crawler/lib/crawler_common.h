#ifndef CRAWLER_COMMON_H
#define CRAWLER_COMMON_H

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





#endif
