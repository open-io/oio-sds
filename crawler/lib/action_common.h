#ifndef __ACTION_COMMON_H
#define __ACTION_COMMON_H



#include "transp_layer.h"
#include "crawler_constants.h"
#include "transp_layer_cmd.h"
#include "crawler_tools.h"


/******************************************************************************/
/* callback function                                                          */
/* request from crawler                                                       */
/* generate by generate_xx_glue_h.sh and atos.grid.action.xml                 */
/******************************************************************************/
//implements function on action_xx.c file
gboolean action_set_data_trip_ex(TCrawlerBusObject *obj, const char* sender,
    const char *alldata, GError **error);
gboolean action_command(TCrawlerBusObject *obj, const char* cmd, const char *alldata,
    char** status, GError **error);





/******************************************************************************/
/******************************************************************************/

typedef struct {
	guint64   context_id;
    int       argc;
    char**    argv;
    guint64   service_uid;
    GVariant* occur;
} TActParam;

void act_paramact_init(TActParam* pActParam);
void act_paramact_clean(TActParam* pActParam);


GVariant* act_disassembleParam(char* param_print, TActParam* pActParamOut);


const TCrawlerBusObjectInfo* act_getObjectInfo(void);
char*     act_buildResponse(gchar* action_name, int pid,  guint64 context_id, gchar* temp_msg);




#endif //__ACTION_COMMON_H


