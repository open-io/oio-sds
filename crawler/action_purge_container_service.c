#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "atos.grid.action"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <metautils/lib/metautils.h>
#include <meta2v2/meta2v2_remote.h>
#include <meta2v2/meta2_utils.h>
#include <meta2v2/generic.h>
#include <rules-motor/lib/motor.h>
#include <rawx-lib/src/rawx.h>
#include <polix/polix_action.h>


#include <glib.h>
#include <dbus/dbus.h>
#include <sqlite3.h>

#include <neon/ne_basic.h>
#include <neon/ne_request.h>
#include <neon/ne_session.h>

#include "lib/action_common.h"

static TCrawlerBus* conn;

static gboolean stop_thread;

static gchar* action_name;
static gchar* namespace_cmd_opt_name;
static gchar* dryrun_cmd_opt_name;
static gchar* timeout_cmd_opt_name;

gboolean g_dryrun_mode = FALSE;
static int service_pid;

static const gchar* occur_type_string;

static gchar     g_service_name[SERVICENAME_MAX_BYTES];
static char*     g_dbusdaemon_address = NULL;
static GMainLoop *g_main_loop = NULL;


//==============================================================================
// Listening message come from, and execute action function
//==============================================================================

/* ------- */
struct SParamMsgrx {
	gchar* namespace;
	const gchar* source_path;
	const gchar* meta2_url;
	gchar* dryrun;
	gdouble timeout_request;
};

void init_paramMsgRx(struct SParamMsgrx* pParam)
{
	if (pParam == NULL) return;

	memset(pParam, 0, sizeof(struct SParamMsgrx));
}

void clean_paramMsgRx(struct SParamMsgrx* pParam)
{
	if (pParam == NULL) return;

	if (pParam->namespace)    g_free(pParam->namespace);
	if (pParam->dryrun)       g_free(pParam->dryrun);

	init_paramMsgRx(pParam);
}

static gboolean
extract_paramMsgRx(gboolean allParam, TActParam* pActParam,
		struct SParamMsgrx* pParam)
{
	if (NULL == pParam)
		return FALSE;

	if (allParam) {
		gchar* tmp = NULL;
		// Namespace extraction
		if (!(pParam->namespace = get_argv_value(pActParam->argc,
						pActParam->argv, action_name,
						namespace_cmd_opt_name))) {
			GRID_TRACE("Failed to get namespace from args");
			return FALSE;
		}

		if (!(pParam->dryrun = get_argv_value(pActParam->argc,
						pActParam->argv, action_name,
						dryrun_cmd_opt_name))) {
			g_dryrun_mode = FALSE;
		} else {
			g_dryrun_mode = TRUE;
			if (0 == g_strcmp0(pParam->dryrun, "FALSE"))
				g_dryrun_mode = FALSE;
		}

		pParam->timeout_request = 0;
		if (NULL != (tmp =  get_argv_value(pActParam->argc,
						pActParam->argv, action_name,
						timeout_cmd_opt_name))){
			int itmp = 0;
			if (sscanf(tmp, "%d", &itmp) != 1)
				pParam->timeout_request = 0;
			else
				pParam->timeout_request = (gdouble) itmp;

			g_free(tmp);
		}
		GRID_DEBUG("Timeout Request purge: %lf", pParam->timeout_request);

		/* Checking occurence form */
		GVariantType* gvt = g_variant_type_new(occur_type_string);
		if (!g_variant_is_of_type(pActParam->occur, gvt)) {
			g_variant_type_free(gvt);
			return FALSE;
		}
		g_variant_type_free(gvt);
		gvt = NULL;

		/* ------- */
		/* Source path / meta2_url / ...  */
		pParam->source_path     = get_child_value_string(pActParam->occur, 0);
		pParam->meta2_url       = get_child_value_string(pActParam->occur, 1);
		/* ------- */
	} else {
		static char tmp[] = "";
		pParam->source_path = tmp;
		pParam->meta2_url   = tmp;
	}

	return TRUE;
}

static struct hc_url_s *
_url_from_msg(struct SParamMsgrx *msg)
{
        char* hexid = strrchr(msg->source_path, '/');
        if(!hexid || strlen(hexid) != 65)
		return NULL;

	struct hc_url_s *url = hc_url_empty();
        hc_url_set(url, HCURL_NS, msg->namespace);
        hc_url_set(url, HCURL_HEXID, hexid + 1);

	return url;
}



static GError *
_do_purge(struct SParamMsgrx *msgRx)
{
	GError *error = NULL;
	struct hc_url_s *url = NULL;

	if(!(url = _url_from_msg(msgRx)))
		return NEWERROR(1, "Invalid source path (%s)", msgRx->source_path);

	GRID_DEBUG("Sending PURGE to container [%s]",
			hc_url_get(url, HCURL_WHOLE));

	polix_action_purge_result_t result;
	memset(&result, 0, sizeof(polix_action_purge_result_t));
	if (polix_action_purge_byurl(url, msgRx->meta2_url, msgRx->timeout_request, 
							g_dryrun_mode, &result, &error)) {
	    if(0 < result.nb_del) {
	        GRID_INFO("%s%"G_GUINT32_FORMAT" chunks deleted ("
		                "%"G_GINT64_FORMAT" bytes deleted) from %s",
	                ((g_dryrun_mode == TRUE)?"(DRYRUN mode) ":""),
	                result.nb_del, result.del_size, hc_url_get(url, HCURL_WHOLE));
	    } else {
	        GRID_DEBUG("No chunks deleted from %"G_GINT64_FORMAT" sized chunk's list of %s",
	                result.del_size, hc_url_get(url, HCURL_WHOLE));
	    }
	} else {
		if (error) 
			GRID_ERROR("ERROR: (%d) %s", gerror_get_code(error), gerror_get_message(error));
		
	}

	hc_url_clean(url);

	return error;
}

static GError *
_do_purge_response(struct SParamMsgrx *msgRx, TActParam *actparam,
		const char *sender, gboolean success)
{
	GError *error = NULL;
	char tmp[(SHORT_BUFFER_SIZE * sizeof(char)) + sizeof(guint64)];
	memset(tmp, '\0', sizeof(tmp));
	g_snprintf(tmp, sizeof(tmp), "%s on %s for the context"
			" %llu and the file %s",
			(success ? ACK_OK : ACK_KO), action_name,
			(long long unsigned)actparam->context_id, msgRx->source_path);
	char *status = act_buildResponse(action_name, service_pid,
			actparam->context_id, tmp);

	static TCrawlerReq* req = NULL;
	if (req)
		crawler_bus_req_clear(&req);

	if(NULL != (error = crawler_bus_req_init(conn, &req, sender,
					SERVICE_PATH, SERVICE_IFACE_CONTROL))) {
		g_prefix_error(&error, "Crawler services connection failure %s: ",
				sender);
	} else {
		tlc_Send_Ack_noreply(req, NULL, (success? ACK_OK : ACK_KO), status);
	}

	g_free(status);

	return error;
}

gboolean action_set_data_trip_ex(TCrawlerBusObject *obj, const char* sender,
    const char *alldata, GError **error)
{
	TActParam actparam;
	struct SParamMsgrx msgRx;

	(void) obj;

	act_paramact_init(&actparam);
	init_paramMsgRx(&msgRx);

	GVariant* param = act_disassembleParam((char*) alldata, &actparam);
	if (extract_paramMsgRx(TRUE, &actparam, &msgRx)) {
		gboolean success = TRUE;
		*error = _do_purge(&msgRx);
		if(NULL != *error) {
			GRID_WARN("Container PURGE failure (%d): %s",
					(*error)->code, (*error)->message);
			g_clear_error(error);
			success = FALSE;
		}
		*error = _do_purge_response(&msgRx, &actparam, sender, success);
		if(NULL != *error) {
			GRID_WARN("PURGE response failure (%d): %s",
				(*error)->code, (*error)->message);
			g_prefix_error(error, "PURGE response failure: ");
		}
		act_paramact_clean(&actparam);
	} else {
		*error = NEWERROR(1, "Bad format for received data");
	}

	if(NULL != param)
		g_variant_unref(param);

	clean_paramMsgRx(&msgRx);

	return (NULL == *error);
}


gboolean action_command(TCrawlerBusObject *obj, const char* cmd,
		const char *alldata, char** status, GError **error)
{
	TActParam actparam;
	struct SParamMsgrx msgRx;
	act_paramact_init(&actparam);
	init_paramMsgRx(&msgRx);

	(void) obj;
	(void) status;

	GRID_DEBUG("%s...\n", __FUNCTION__);
	GVariant* param = act_disassembleParam((char*) alldata, &actparam);
	if (extract_paramMsgRx(FALSE, &actparam, &msgRx) == FALSE) {
		act_paramact_clean(&actparam);
		clean_paramMsgRx(&msgRx);
		g_variant_unref(param);
		*error = NEWERROR(1, "Bad format for received data");
		GRID_ERROR((*error)->message);
		return FALSE;
	}

	if (g_strcmp0(cmd, CMD_STARTTRIP) == 0) {
		//-----------------------
		// start process crawling		        
		GRID_INFO("start process's crawler");

		/* code here */

	} else  if (g_strcmp0(cmd, CMD_STOPTRIP) == 0) {
		//----------------------
		// end process crawling
		GRID_INFO("stop process's crawler");
		sleep(1);

		/* code here */

	} else {
		if (cmd)
			GRID_INFO("%s process's crawler", cmd);
		else
			GRID_INFO("%s process's crawler", "Unknown command");
	}

	GRID_DEBUG(">%s process's crawler\n", cmd);

	act_paramact_clean(&actparam);
	clean_paramMsgRx(&msgRx);
	 g_variant_unref(param);

	return TRUE;
}





/* GRID COMMON MAIN */
static struct grid_main_option_s *main_get_options(void)
{
	static struct grid_main_option_s options[] = {
		{ NULL, 0, {.b=NULL}, NULL }
	};

	return options;
}

static void main_action(void)
{
	GError* error = NULL;

	g_type_init();

	g_main_loop = g_main_loop_new (NULL, FALSE);

	/* DBus connexion */
	error = tlc_init_connection(&conn, g_service_name, SERVICE_PATH, 
								"" /*g_dbusdaemon_address*/ /*pour le bus system: =""*/, 
								(TCrawlerBusObjectInfo*) act_getObjectInfo());
	if (error) {
		GRID_ERROR("System D-Bus connection failed: %s",
				/*g_cfg_action_name, g_service_pid,*/ error->message);
		exit(EXIT_FAILURE);
	}



	GRID_INFO("%s (%d): System D-Bus %s action signal listening thread started...",
			action_name, service_pid, action_name);

	g_main_loop_run (g_main_loop);

	crawler_bus_Close(&conn);

	exit(EXIT_SUCCESS);
}

	static void
main_set_defaults(void)
{
	conn = NULL;
	stop_thread = FALSE;
	action_name = "action_purge_container";
	namespace_cmd_opt_name = "n";
	dryrun_cmd_opt_name = "dryrun";
	timeout_cmd_opt_name = "t";
	g_dryrun_mode = FALSE;
	service_pid = getpid();
	occur_type_string = "(ss)";

	buildServiceName(g_service_name, SERVICENAME_MAX_BYTES, 
					SERVICE_ACTION_NAME, action_name, service_pid, FALSE);
}

	static void
main_specific_fini(void)
{
}

	static gboolean
main_configure(int argc, char **args)
{
	argc = argc;
	args = args;

    if (argc >= 1)         
		g_dbusdaemon_address = getBusAddress(args[0]);
   	GRID_DEBUG("dbus_daemon address:\"%s\"", g_dbusdaemon_address);

	return TRUE;
}

	static const gchar*
main_usage(void)
{
	return "";
}

	static void
main_specific_stop(void)
{
	stop_thread = TRUE;
	g_main_loop_quit(g_main_loop);
	GRID_INFO("%s (%d): System D-Bus %s action signal listening thread stopped...",
			action_name, service_pid, action_name);
}

static struct grid_main_callbacks cb = {
	.options = main_get_options,
	.action = main_action,
	.set_defaults = main_set_defaults,
	.specific_fini = main_specific_fini,
	.configure = main_configure,
	.usage = main_usage,
	.specific_stop = main_specific_stop
};

	int
main(int argc, char **argv)
{
	g_thread_init(NULL);
	dbus_g_thread_init();
	dbus_threads_init_default();

	return grid_main(argc, argv, &cb);
}

