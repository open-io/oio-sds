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

#ifndef OIO_SDS__crawler__lib__action_common_h
# define OIO_SDS__crawler__lib__action_common_h 1

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

#endif /*OIO_SDS__crawler__lib__action_common_h*/