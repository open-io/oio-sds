#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.crawler.action.common"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <metautils/lib/metautils.h>

#include <glib.h>
#include <gmodule.h>
#include <dbus/dbus.h>

#include "transp_layer.h"
#include "crawler_tools.h"
#include "action_common.h"
#include "action-glue.h"

const TCrawlerBusObjectInfo* act_getObjectInfo(void)
{
	return &dbus_glib_action_object_info;
}


void act_paramact_init(TActParam* pActParam)
{
	if (pActParam == NULL)
		return;

    pActParam->context_id  = 0;
	pActParam->argc        = -1;
	pActParam->argv        = NULL;
	pActParam->service_uid = 0;
	pActParam->occur       = NULL;
}

void act_paramact_clean(TActParam* pActParam)
{
    if (pActParam == NULL)
        return;

	if (pActParam->argv != NULL) {
		g_strfreev(pActParam->argv);
		pActParam->argv = NULL;
	}

	if (pActParam->occur)
		g_variant_unref(pActParam->occur);

	act_paramact_init(pActParam);
}



GVariant* act_disassembleParam(char* param_print, TActParam* pActParamOut)
{
	GVariant* param = NULL;
	static GVariantType* param_type = NULL;

	if (!param_type)
		param_type = g_variant_type_new(gvariant_action_param_type_string);


	param = g_variant_parse(param_type, param_print, NULL, NULL, NULL);
	if (NULL == param) {
		GRID_TRACE("Failed to get string param");
		return NULL;
	}

	if (pActParamOut != NULL) {
        if (EXIT_FAILURE == disassemble_context_occur_argc_argv_uid(param, 
					&(pActParamOut->context_id), &(pActParamOut->occur), 
					&(pActParamOut->argc), &(pActParamOut->argv), 
					&(pActParamOut->service_uid))) {
            g_variant_unref(param);
			act_paramact_clean(pActParamOut);
            GRID_TRACE("Failed to parse string param");
            return NULL;
        }
	}

	return param;
}

char* act_buildResponse(gchar* action_name, int pid,  guint64 context_id, gchar* temp_msg)
{
	GVariant* ack_parameters = NULL;
	gchar* gv_print;

	(void) action_name;
	(void) pid;

	GRID_TRACE("%s (%d) : %s", action_name, pid, temp_msg);

	GVariant* temp_msg_gv = g_variant_new_string(temp_msg);

	ack_parameters = g_variant_new(gvariant_ack_param_type_string,
			context_id, temp_msg_gv);

	gv_print = g_variant_print(ack_parameters, FALSE);	

	g_variant_unref(ack_parameters);

	return gv_print;
}


