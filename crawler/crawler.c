#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN   "atos.grid.crawler"
#endif


#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>


#include <dbus/dbus.h>

#include <metautils/lib/metautils.h>

#include <glib.h>
#include <gmodule.h>

#include "lib/transp_layer.h"
#include "lib/transp_layer_cmd.h"
#include "lib/crawler_common.h"
#include "lib/crawler_tools.h"

#include "listener/listener_remote.h"

# ifndef TRIP_INSTALL_PATH
#  define TRIP_INSTALL_PATH "/usr/local/lib64/grid"
# endif




//==============================================================================
// constantes
//==============================================================================
#define CRAWLER_COMMAND_MAX_BYTES       64


//==============================================================================
// variables
//==============================================================================
static gchar               g_service_name[SERVICENAME_MAX_BYTES];
static TCrawlerSvcActList* g_list_svcAction = NULL; 
static GMainLoop*          g_main_loop = NULL;
static TCrawlerBus*        g_tl_conn = NULL;
static GThread*            control_tripmanage_thread;
static GThread*            control_timeout_thread;




/******************************************************************************/
/******************************************************************************/



typedef struct SCrawlerOptions {
	guint    reloadaction;

	guint    ctxmax;
	guint    ctxwait_timeout;
	guint    ctxWait_sup;    // number of 'context wait responses' at the same time max
									// limit to waitwhile counter increase (histeris )
	guint    ctxWait_inf;    // number of 'context wait responses' at the same time min
									// limit before continue while counter decrease (histeris)

	GString* trip_name;
	GString* action_names;
	GString* triplibpath;
	GString* listenerUrl;
	gboolean dryrun_mode;
} TCrawlerConsole;


static GMutex*  mutex_ctx_update; /* Mutex related to action context update */
static gboolean stop_thread; /* Flag to stop the listening threads */

static char     g_control_status[CRAWLER_COMMAND_MAX_BYTES]; /* Current control status (BYPASS, PAUSE, ...) */

static gint32  service_pid;
static guint64 service_uid;
static int     my_argc;
static char**  my_argv;
static struct  trip_lib_entry_points* trip_ep; /* Trip library entry points (library and methods) */

static GHashTable* action_ctx_table; /* Association table between unique ID of actions and their related contexts */
static gchar** action_list; /* List of action names to perform (order matters) */
static guint action_list_length;

/* Console parameters utils */
static TCrawlerConsole console;
/* ------- */

static void
main_set_defaults(void)
{
	stop_thread = FALSE;
	g_strlcpy(g_control_status, CTRL_BYPASS, CRAWLER_COMMAND_MAX_BYTES);
	service_pid = getpid();
	service_uid = g_get_monotonic_time();
	my_argc = -1;
	my_argv = NULL;
	trip_ep = NULL;
	action_ctx_table = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, (GDestroyNotify)free_action_context);
	action_list = NULL;
	action_list_length = 0;



	/* init console/options */
	memset(&console, 0, sizeof(TCrawlerConsole));

	console.ctxWait_sup = 0;
	console.ctxWait_inf = console.ctxWait_sup / 2;
	GRID_DEBUG("contexte wait (histerisis limit): %d \\/, %d /\\", console.ctxWait_sup, console.ctxWait_inf);

	console.ctxWait_sup = 0;
	console.ctxWait_inf = console.ctxWait_sup / 2;
	GRID_DEBUG("contexte wait (histerisis limit): %d \\/, %d /\\", console.ctxWait_sup, console.ctxWait_inf);

	console.reloadaction = 300;
	console.ctxwait_timeout = MAX_ACTION_TIMEOUT;

	console.ctxmax = 0; // all data if no infinite loop

	console.trip_name = NULL;
	console.action_names = NULL;
	console.triplibpath = NULL;
	console.listenerUrl = NULL;
	console.dryrun_mode = FALSE;

	g_service_name[0] = '\0';

	g_list_svcAction = NULL;

}

static void
main_specific_fini(void)
{
	stop_thread = TRUE;
	(trip_ep->trip_end)();

	g_mutex_lock(mutex_ctx_update);
	if (NULL != action_ctx_table)
		g_hash_table_destroy(action_ctx_table);
	g_mutex_unlock(mutex_ctx_update);

	if (NULL != trip_ep)
		free_trip_lib_entry_points(trip_ep);

	if (NULL != action_list)
		g_strfreev(action_list);

	GRID_INFO("%s (%d) : Crawler ended", g_service_name, service_pid);
}


static gboolean main_configure(int argc, char **args) {
	g_mutex_lock(mutex_ctx_update);
	if (NULL == action_ctx_table) {
		GRID_ERROR("%s (%d) : Context table failed to create", g_service_name, service_pid);
		g_mutex_unlock(mutex_ctx_update);
		return FALSE;
	}
	g_mutex_unlock(mutex_ctx_update);
	GRID_INFO("%s (%d) : Context table created", g_service_name, service_pid);

	/* Trip management */
	if (NULL != console.trip_name) {
		gchar* temp_trip_name = g_string_free(console.trip_name, FALSE);
		console.trip_name = g_string_new(temp_trip_name);

		gchar* temp_triplib = NULL;
		if (NULL != console.triplibpath) {
			 temp_triplib = g_string_free(console.triplibpath, FALSE);
			 console.triplibpath = g_string_new(temp_triplib);
		}	

		trip_ep = load_trip_library(temp_triplib, temp_trip_name);

		g_free(temp_trip_name);
	}
	if (NULL == trip_ep || (EXIT_FAILURE == (int)(trip_ep->trip_start)(argc, args))) {
		GRID_ERROR("%s (%d) : Trip library failed to load (Please ensure the path while contain libtrip_*.so are on LD_LIBRARY_PATH)", g_service_name, service_pid);
		return FALSE;
	}
	GRID_INFO("%s (%d) : Trip library loaded", g_service_name, service_pid);
	/* ------- */

	/* Action management */
	if (NULL != console.action_names) {
		char* temp_action_names = g_string_free(console.action_names, FALSE);
		console.action_names = g_string_new(temp_action_names);

		action_list = g_strsplit(temp_action_names, opt_value_list_separator, -1);

		g_free(temp_action_names);
	}
	if (NULL == action_list)
		return FALSE;
	while((action_list[action_list_length]))
		action_list_length++;

	if (0 == action_list_length) {
		GRID_ERROR("%s (%d) : No action to list", g_service_name, service_pid);

		return FALSE;
	}
	GRID_INFO("%s (%d) : Action list feeded", g_service_name, service_pid);
	/* ------- */


	if (console.ctxWait_sup == 0)
		console.ctxWait_inf = 0;
	else if (console.ctxWait_sup == 1)
		console.ctxWait_inf = 0;
	else {
		console.ctxWait_inf = console.ctxWait_sup / 2;
	}
	GRID_DEBUG("contexte wait (histerisis limit): %d \\/, %d /\\", 
		console.ctxWait_sup, console.ctxWait_inf);
	/* ------- */
	my_argc = argc;
	my_argv = args;
	GRID_INFO("%s (%d) : Additional parameters stored", g_service_name, service_pid);


    buildServiceName(g_service_name, SERVICENAME_MAX_BYTES,
                    SERVICE_CRAWLER_NAME, action_list[0], service_pid, FALSE);



	return TRUE;
}


static gboolean action_timeout(gpointer key, gpointer val, gpointer udata)
{
	(void) key;
	(void) udata;
	struct action_context* current_ctx = val;
	time_t current_time_stamp;
	time(&current_time_stamp);

	if (console.ctxwait_timeout > difftime(current_time_stamp,
				current_ctx->time_stamp))
		return FALSE;

	GRID_INFO("%s (%d): Context %llu removed from the context table: "
			"Expired context\n", g_service_name, service_pid,
			(unsigned long long)current_ctx->id);

	return TRUE;
}


static gpointer thread_action_timeout_check(gpointer data)
{
	time_t current_time_stamp;
	time_t current_time_stamp_reloadaction;

	(void) data;

	GRID_DEBUG("Thread timeout ack started...");
	GRID_DEBUG("console.reloadaction=%d", console.reloadaction);

	time(&current_time_stamp_reloadaction);

	while (!stop_thread ) {

		//rechargement de la list
		time(&current_time_stamp);
		if ((console.reloadaction) < difftime(current_time_stamp,
					current_time_stamp_reloadaction)) {
			GRID_DEBUG("crawler_ServiceAction_UpdateList...");
			g_mutex_lock(mutex_ctx_update);
			crawler_ServiceAction_UpdateList(g_tl_conn, g_list_svcAction,
					SERVICE_ACTION_NAME, action_list[0]);
			g_mutex_unlock(mutex_ctx_update);
			time(&current_time_stamp_reloadaction);
		}

		g_mutex_lock(mutex_ctx_update);
		if (NULL != action_ctx_table) {
			g_hash_table_foreach_remove(action_ctx_table,
					(GHRFunc)action_timeout, NULL);
		}
		g_mutex_unlock(mutex_ctx_update);

		sleep(1);
	}

	GRID_DEBUG("Thread timeout ack ended");

	return NULL;
}

/**
 * This method updates a given context
 */
static void action_ctx_update(guint64 context_id)
{
	struct action_context* action_ctx = NULL;

	g_mutex_lock(mutex_ctx_update);
	action_ctx = (struct action_context*)g_hash_table_lookup(action_ctx_table,
			&context_id);

	if (NULL != action_ctx) {
		if (action_ctx->occur) {
			g_variant_unref(action_ctx->occur);
			action_ctx->occur = NULL;
		}

		g_hash_table_remove(action_ctx_table, &(action_ctx->id));

		GRID_DEBUG("%s (%d): Context %llu removed from the context table",
				g_service_name, service_pid, (unsigned long long)context_id);

	}
	g_mutex_unlock(mutex_ctx_update);
}

gboolean crawler_command(TCrawlerBusObject *obj, const char* cmd,
		const char* sender, const char *alldata, GError **error)
{
	char* ret = NULL;
	GString* str = NULL;

	(void) obj;
	(void) alldata;
	(void) error;

	GRID_DEBUG("%s (%d): command %s received on the system D-Bus control interface",
			g_service_name, service_pid, cmd);

	if (!g_strcmp0(CTRL_LIST, cmd)) {
		g_mutex_lock(mutex_ctx_update);
		ret = crawler_ServiceAction_ListToStr(g_list_svcAction);
		g_mutex_unlock(mutex_ctx_update);



		// progress trip control signal
	} else if ( !g_strcmp0(CTRL_PROGRESS, cmd)) {
		int progression = 0;

		progression = (int)(trip_ep->trip_progress)();

		str = g_string_new("");
		g_string_append_printf(str, "%d%% achieved\nstatus = %s",
				progression, g_control_status);
		ret = g_string_free(str, FALSE);



		// CTRL_STOP,... control signal
	} else if (   (!g_strcmp0(CTRL_STOP,   cmd))
			||(!g_strcmp0(CTRL_SLOW,   cmd))
			||(!g_strcmp0(CTRL_PAUSE,  cmd))
			||(!g_strcmp0(CTRL_RESUME, cmd)) ) {
		if (!g_strcmp0(CTRL_RESUME, cmd))
			g_strlcpy(g_control_status, CTRL_BYPASS, CRAWLER_COMMAND_MAX_BYTES);
		else
			g_strlcpy(g_control_status, cmd, CRAWLER_COMMAND_MAX_BYTES);
		str = g_string_new("command executed with success");
		ret = g_string_free(str, FALSE);


		// other: unknown command
	} else {
		str = g_string_new("Command not implemented");
		ret = g_string_free(str, FALSE);
	}


	if (ret == NULL)
		return FALSE;


	// send response
	static TCrawlerReq* req = NULL;
	if (req)
		crawler_bus_req_clear(&req);

	GError* err = crawler_bus_req_init(g_tl_conn, &req, sender,
			SERVICE_PATH, SERVICE_IFACE_CONTROL);
	if (err) {
		g_prefix_error(&err, "Failed to connectd to crawler services %s : ", sender);
		GRID_WARN("Failed to send ack [%s]: %s", cmd, err->message);
		g_clear_error(&err);
	}

	tlc_Send_Ack_noreply(req, NULL, (char*)cmd, ret);

	g_free(ret);

	return TRUE;
}




gboolean crawler_ack(TCrawlerBusObject *obj, const char* cmd,
		const char *alldata, GError **error)
{
	GVariant* ack_params = NULL;
	guint64 context_id;
	GVariantType* ack_param_type = NULL;

	(void) obj;
	(void) error;

	if ((!strstr(cmd, ACK_OK))&&
			(!strstr(cmd, ACK_KO)) ) {
		GRID_DEBUG("%s (%d): ERROR: Signal %s received on the system D-Bus acknowledgement, BAD cmd",
				g_service_name, service_pid, cmd);
		return FALSE;
	}

	ack_param_type = g_variant_type_new(gvariant_ack_param_type_string);
	ack_params     = g_variant_parse(ack_param_type, alldata, NULL, NULL, NULL);
	g_variant_type_free(ack_param_type);

	if (NULL != ack_params) {
		GVariant* temp_context_id = g_variant_get_child_value(ack_params, 0);
		context_id = g_variant_get_uint64(temp_context_id);

		GRID_DEBUG("%s (%d): Signal %s received ack (context: %ld)",
				g_service_name, service_pid, cmd, context_id);

		action_ctx_update(context_id);

		g_variant_unref(temp_context_id);
		g_variant_unref(ack_params);
	} else
		GRID_DEBUG("%s (%d): ERROR: Signal %s received on the system D-Bus acknowledgement, bad ack_params",
				g_service_name, service_pid, cmd);

	return TRUE;
}




/* GRID COMMON MAIN */
static struct grid_main_option_s *
main_get_options(void)
{
	static struct grid_main_option_s options[] = {
		{ "trip",			 OT_STRING,	 {.str = &(console.trip_name)},
			"The name of the trip" },
		{ "action",			 OT_STRING,  {.str = &(console.action_names)},
			"The names of the actions" },
		{ "triplibpath",	 OT_STRING,	 {.str = &(console.triplibpath)},
			"Explicitely specify where to find the trip libraries" },
		{ "ctxwait",		 OT_UINT,	 {.u = &(console.ctxWait_sup)},
			"The maximum number of elements simultaneously sent to the actions."
			" Use if trip_xx goes fast and action_yy goes more slowly.\n"
			"Default: 0 (no limit)"},
		{"ctxmax",			 OT_UINT,	 {.u =  &(console.ctxmax)},
            "Stop after N managed elements (=0: disabled, >0: N elements"},
		{ "reloadaction",	 OT_UINT,	 {.u = (guint*) &(console.reloadaction)},
			"The time in seconds between reloads of the list of actions,\n"
			"=0: no reload, default: 300"},
		{ "listener",		 OT_STRING,	 {.str = &(console.listenerUrl)},
			"The URL of Listener if used: \"<addIP:<port>\" "},
		{ "dryrun",			 OT_BOOL,	 {.b = &(console.dryrun_mode)},
			"Dry-run mode, actions do nothing."},
		{ "ctxwait_timeout", OT_UINT,	 {.u = &(console.ctxwait_timeout)},
			"The time in seconds to wait for an element to be handled "
			"by an action, default: 5s"}
	};

	return options;
}


static gboolean sendToListener(gchar* listenerUrl, gchar* crawlerID)
{
	void* zmq_ctx = NULL;
	void* zmq_sock = NULL;
	gboolean bInit = FALSE;
	TLstError* err = NULL;

	//init zmq lib
	zmq_ctx = listener_remote_init();
	if (!zmq_ctx) {
		GRID_ERROR("zmq_init failed (%d)", errno);
		return FALSE;
	}

	// init socket
	zmq_sock = listener_remote_connect(&err, zmq_ctx, listenerUrl, 2000, -1);
	if (err != NULL) {
		GRID_ERROR("Error (%d) %s", err->code, err->message);
		listener_remote_error_clean(err);

	} else if (zmq_sock != NULL)
		bInit= TRUE;

	// build message: JSON format
	if (bInit == TRUE) {
		struct json_object *j_root;
		TLstJSONHeader msgH;

		if ((console.action_names != NULL)&&(console.action_names->len>0))
			msgH.action_name = console.action_names->str;
		else
			msgH.action_name = NULL;

		msgH.action_pid  = getpid();
		msgH.idmsg       = 0;
		g_strlcpy(msgH.status,  LISTENER_JSON_KEYNAME_HEAD_STATUS_setcrawlerid , LSTJSON_STATUS_MAX_CARACT);
		g_strlcpy(msgH.idcrawl, crawlerID, LSTJSON_IDCRAWL_MAX_CARACT);

		//build empty frame with all section
		j_root = listener_remote_json_init(&msgH, TRUE);
		if (!j_root)
			return FALSE;


		if (console.dryrun_mode == FALSE) {
			// real mode
			TLstError* err2 = listener_remote_sendJSON(zmq_sock, j_root);
			if (err2) {
				GRID_ERROR("Error send JSON message ID_crawl to listener (%d) %s", err2->code, err2->message);
				listener_remote_error_clean(err2);
			}
		} else {
			// dryrun mode
			char* buf = listener_remote_json_getStr(j_root);
			DRYRUN_SENDTOLISTENER(listenerUrl, "msg(JSON):[%s]\n",
					(buf != NULL)? buf : "JSON build failed");
		}

		listener_remote_json_clean(j_root);
	}

	// close  all
	listener_remote_close(zmq_ctx, zmq_sock);

	return TRUE;
}



static gboolean buildCrawlerID(gchar* crawlerID, int sizec, int arg)
{
	time_t t;
	struct tm *tmp;

	t = time(NULL);
	tmp = localtime(&t);
	if (tmp == NULL) {
		GRID_ERROR("Failed to build crawlerID (localtime-errno=%d)", errno);
		return FALSE;
	}

	if (strftime(crawlerID, sizec, "%04Y%02m%02d%H%02M%02S", tmp) == 0) {
		GRID_ERROR("Failed to build crawlerID (strftime-errno=%d)", errno);
		return FALSE;
	}

	g_snprintf(&crawlerID[strlen(crawlerID)], sizec - strlen(crawlerID), "_%d", arg);
	return TRUE;
}


static void addItemsToArgvArgc(gchar* crawlerID, gchar* listenerUrl)
{
	char **newv = (char **) g_malloc0((my_argc + 3) * sizeof(char*));
	if (newv != NULL) {
		if ((console.action_names != NULL)&&(console.action_names->len>0)) {

			// prepare argv
			memmove(newv, my_argv, sizeof(*newv) * my_argc);

			if (crawlerID != NULL) {
				//prepare crawlerID
				int len1 = strlen(console.action_names->str) + strlen(crawlerID) + 20;
				char* tmp1 = g_malloc0(sizeof(char)*len1);
				g_snprintf(tmp1, len1, "-%s.crawlerID=%s", console.action_names->str, crawlerID);
				newv[my_argc]   = tmp1; my_argc++;
			}

			if (listenerUrl != NULL) {
				//prepare listenerUrl
				int len2 = strlen(console.action_names->str) + strlen(listenerUrl) + 20;
				char* tmp2 = g_malloc0(sizeof(char)*len2);
				g_snprintf(tmp2, len2, "-%s.l=%s", console.action_names->str, listenerUrl);
				newv[my_argc]   = tmp2; my_argc++;
			}

			// add last argument to argv
			newv[my_argc] = 0;

			my_argv = newv;
		} else GRID_ERROR("Failed to allocated memory for add crawlerID to message to action send (na action_name)");
	} else GRID_ERROR("Failed to allocated memory for add crawlerID to message to action send");
}

static gboolean send_startend_signal( gchar* signal_tile)
{
	GVariant* signal_param = NULL;
	GVariant* pOccur = NULL;
	GError* error = NULL;

	pOccur = g_variant_new("(s)", "none");

	/* Sending NULL occurences message */
	assemble_context_occur_argc_argv_uid(&signal_param, 0, pOccur, my_argc, my_argv, service_uid);

	if (NULL == signal_param) {
		g_variant_unref(pOccur);
		GRID_ERROR("%s (%d) : System D-Bus Start/final signal sending failed"
				" in crawler, assemble_context_occur_argc_argv_uid() == NULL",
				g_service_name, service_pid);
		return FALSE;
	}

	guint i;
	gboolean bResult = TRUE;
	for (i = 0; i < action_list_length; i++) {
		if (console.dryrun_mode == TRUE) {
			//dryrun mode
			DRYRUN_SENDTOACTION("%s (%d) : %s signal %s sent on the system D-Bus interface %s\n",
					g_service_name, service_pid, signal_tile,
					action_list[i], SERVICE_IFACE_ACTION);
			g_variant_unref(signal_param);
			return TRUE;
		}


		// real mode
		gchar* s_signal_parameters = NULL;
		s_signal_parameters = g_variant_print(signal_param, FALSE);

		int nb_svc_act = g_slist_length(g_list_svcAction->list );
		for(int s=0;s<nb_svc_act;s++) {
			TCrawlerSvcAct* svc_act = crawler_ServiceAction_GetNextService(g_list_svcAction, FALSE);
			if ((svc_act == NULL)||(svc_act->bEnabled == FALSE)) {
				continue;
			}

			error = tlc_Send_CmdProc(svc_act->req, MAX_ACTION_TIMEOUT*1000,
					NULL/*crawler_command*/, NULL, signal_tile, s_signal_parameters);
			if (error) {
				GRID_ERROR("%s (%d) : System D-Bus %s signal sending failed in crawler",
						g_service_name, service_pid, signal_tile);
				bResult = FALSE;
			} else {
				GRID_DEBUG("%s (%d) : %s signal %s sent on the system D-Bus interface %s",	
						g_service_name, service_pid, signal_tile, action_list[i], 
						SERVICE_IFACE_ACTION);
			}
		}
		g_free(s_signal_parameters);
	}


	/* ------- */

	g_variant_unref(signal_param);

	return bResult;
}



gboolean send_DataTrip_toAction(TCrawlerSvcAct* svc_act,
	struct action_context* temp_action_ctx, GVariant** occur)
{
	GError* error = NULL;
	GVariant* sig_param = NULL;
	char* s_signal_parameters = NULL;

	assemble_context_occur_argc_argv_uid(&sig_param, temp_action_ctx->id,
			*occur, my_argc, my_argv, service_uid);

	if (NULL == sig_param) {
		GRID_ERROR("%s (%d): System D-Bus DataTrip signal sending failed in "
				"crawler, assemble_context_occur_argc_argv_uid() == NULL",
				g_service_name, service_pid);
		return FALSE;
	}

	s_signal_parameters = g_variant_print(sig_param, FALSE);

	if (console.dryrun_mode == FALSE) {
		error = tlc_Send_DataTripEx_noreply(svc_act->req, temp_action_ctx,
				g_service_name, s_signal_parameters);
		if (error)
			GRID_ERROR("%s (%d): System D-Bus signal sending failed in crawler %s",
					g_service_name, service_pid, error->message);
		else
			GRID_DEBUG("%s (%d): Signal %s sent on the system D-Bus "
					"interface %s for the context %llu",
					g_service_name, service_pid, action_list[0],
					SERVICE_IFACE_ACTION, (unsigned long long)temp_action_ctx->id);
	} else {
		gchar* o = g_variant_print(*occur, FALSE);
		DRYRUN_SENDTOACTION("%s (%d): [%s, %s] Signal %s sent on the system "
				"D-Bus interface %s for the context %llu\n",
				g_service_name, service_pid,
				((s_signal_parameters)?s_signal_parameters:"null"),
				((o)?o:"null"),
				action_list[0],
				SERVICE_IFACE_ACTION, (unsigned long long)temp_action_ctx->id);
		g_free(o);
	}

	if (s_signal_parameters)
		g_free(s_signal_parameters);

	g_variant_unref(sig_param);
	*occur = NULL;

	if (error) {
		g_clear_error(&error);
		return FALSE;
	}

	return TRUE;
}



void init_bus(void);

static gpointer thread_manage_trip_data(gpointer data)
{
	GVariant* occur = NULL;
	struct action_context* temp_action_ctx = NULL;
	time_t temp_time_stamp;
	guint nbctx = 0;

	(void) data;

	//send start signal to action
	gchar crawlerid[50];
	if (buildCrawlerID(crawlerid, 50, getpid()) == FALSE)
		return NULL;
	GRID_INFO("id_crawl=[%s]\n", crawlerid);

	if ((console.listenerUrl)&&(console.listenerUrl->len>0)) {

		// send message to listener
		GRID_INFO("crawler used listener with url=[%s]\n", console.listenerUrl->str);
		sendToListener(console.listenerUrl->str, crawlerid);

		// add idcrawl to argv to send to each data at action process
		addItemsToArgvArgc(crawlerid, console.listenerUrl->str);
	} else addItemsToArgvArgc(crawlerid, NULL);


	send_startend_signal(CMD_STARTTRIP );
	sleep(1);


	/* and the trip goes on... */
	occur = (GVariant*)(trip_ep->trip_next)();
	while (!stop_thread && NULL != occur) {

		// exectue command received
		while (!g_strcmp0(CTRL_PAUSE, g_control_status))
			sleep(1);

		if (!g_strcmp0(CTRL_STOP, g_control_status))
			break;
		else if (!g_strcmp0(CTRL_SLOW, g_control_status))
			sleep(SLOW_VALUE);


		/* action context creation and storage */
		temp_action_ctx = new_action_context();
		if (NULL == temp_action_ctx) {
			GRID_ERROR("Failed to allocate memory about action_context");

			if (NULL != occur) {
				g_variant_unref(occur);
				occur = NULL;
			}

			break;
		}

		time(&temp_time_stamp);
		temp_action_ctx->time_stamp = temp_time_stamp;
		temp_action_ctx->occur = NULL;

		// send msg to actions
		g_mutex_lock(mutex_ctx_update);
		TCrawlerSvcAct* svc_act = crawler_ServiceAction_GetNextService(g_list_svcAction, TRUE);
		g_mutex_unlock(mutex_ctx_update);
		if ((svc_act == NULL) || (svc_act->bEnabled == FALSE)) {
			GRID_ERROR("No service action are available\n");
			free_action_context(temp_action_ctx);
			temp_action_ctx = NULL;
		} else {
			GRID_DEBUG("%s (%d): Context %llu added to the context table",
					g_service_name, service_pid, (unsigned long long)temp_action_ctx->id);

			if (send_DataTrip_toAction(svc_act, temp_action_ctx, &occur)) {
				g_mutex_lock(mutex_ctx_update);
				g_hash_table_insert(action_ctx_table, &(temp_action_ctx->id), temp_action_ctx);
				temp_action_ctx = NULL;
				g_mutex_unlock(mutex_ctx_update);
			} else {
				free_action_context(temp_action_ctx);
				temp_action_ctx = NULL;
			}
		}

		// wait if a lot of data sending to action
		if (console.ctxWait_sup > 0) {
			GRID_DEBUG("console.ctxWait_sup: %d", console.ctxWait_sup);
			guint action_ctx_table_size = 0;
			g_mutex_lock(mutex_ctx_update);
			action_ctx_table_size = g_hash_table_size(action_ctx_table);
			g_mutex_unlock(mutex_ctx_update);
			if (action_ctx_table_size >= console.ctxWait_sup) {
				do {
					GRID_DEBUG("nb context: %d: Waiting...", action_ctx_table_size);
					sleep(1);
					g_mutex_lock(mutex_ctx_update);
					action_ctx_table_size = g_hash_table_size(action_ctx_table);
					g_mutex_unlock(mutex_ctx_update);
				} while((action_ctx_table_size > console.ctxWait_inf)&&(!stop_thread));
			}
		}


		// stop loop ?
		if (console.ctxmax > 0) {
			nbctx++;
			if (nbctx >= console.ctxmax) {
				stop_thread = TRUE;
				GRID_INFO("%d/%d context sending to action: stop crawler", nbctx, console.ctxmax);
			}
		}

		// free and get the next data
		if (NULL != occur) {
			g_variant_unref(occur);
			occur = NULL;
		}

		sleep(0);

		if (stop_thread)
			break;

		//search the next data
		occur = (GVariant*)(trip_ep->trip_next)();
	}

	if (NULL != occur) {
		g_variant_unref(occur);
		occur = NULL;
	}

	sleep(2);

	send_startend_signal(CMD_STOPTRIP);
	sleep(1);


    crawler_bus_Close(&g_tl_conn);


	g_main_loop_quit(g_main_loop);

	return NULL;
}





void init_bus(void)
{
	GError* error = NULL;

    // init bus
    error = tlc_init_connection(&g_tl_conn, g_service_name, SERVICE_PATH,
            "", //tmp, //g_dbusdaemon_address, /*pour le bus system: =""*/
            (TCrawlerBusObjectInfo*) crawler_getObjectInfo());
    if (error) {
        GRID_ERROR("System D-Bus connection failed: %s", error->message);
        exit(EXIT_FAILURE);
    }
    GRID_INFO("%s (%d) : Crawler connected", g_service_name, service_pid);

    // init action services list
    crawler_ServiceAction_InitList(g_tl_conn, &g_list_svcAction, SERVICE_ACTION_NAME, action_list[0]);

    // init update action list
    crawler_ServiceAction_UpdateList(g_tl_conn, g_list_svcAction, SERVICE_ACTION_NAME, action_list[0]);
    GRID_INFO("%s (%d) : %d Services Action to find",
            g_service_name, service_pid,  g_slist_length(g_list_svcAction->list));
    crawler_ServiceAction_DumpList(g_list_svcAction);

    // init pointer next action
    TCrawlerSvcAct* svc_act = crawler_ServiceAction_GetNextService(g_list_svcAction, TRUE);
    if (svc_act)
        GRID_DEBUG("next action to send: [%s]", svc_act->svc_name);
    else
        GRID_DEBUG("next action to send: [no]");
}



static void main_action(void)
{
	g_type_init();

	g_main_loop = g_main_loop_new (NULL, FALSE);

	init_bus();

	GRID_INFO("%s (%d) : Crawler started", g_service_name, service_pid);


	// launch thread for manage timeout about ack received
   control_timeout_thread = g_thread_create(thread_action_timeout_check, NULL, FALSE, NULL);
    if (NULL == control_timeout_thread)
        GRID_INFO("%s (%d) : System Timeout Ack management thread failed to start...", g_service_name, service_pid);
    else
        GRID_INFO("%s (%d) : System Timtout Ack management thread started...", g_service_name, service_pid);


	// launch thread for manage trip_data
	control_tripmanage_thread = g_thread_create(thread_manage_trip_data, NULL, FALSE, NULL);
	if (NULL == control_tripmanage_thread)
		GRID_INFO("%s (%d) : System Trip Data management thread failed to start...", g_service_name, service_pid);
	else
		GRID_INFO("%s (%d) : System Trip Data management thread started...", g_service_name, service_pid);


	g_main_loop_run(g_main_loop);

	stop_thread = TRUE;

	crawler_ServiceAction_ClearList(&g_list_svcAction);

	return;
}

static const gchar*
main_usage(void)
{
	return "-Otrip=<trip_name> -Oaction=<action_name><:...:...> [[-Octxmax=<nb max manage before end>] [-Oreloadaction=<waitTime>] [-Octxwait=<nb_contextWainting_if action more slowly than trip> [-Octxwait_timeout=<nb second>]] [-Olistener=<listenerUrl] -Otriplibpath=<specific_trip_library_dir_path>] -- -trip_name.param_name=<value> -action_name.param_name=<value> [...]\n";
}

static void
main_specific_stop(void)
{
	stop_thread = TRUE;

#define CRAWLER_GSTRING_FREE(str) \
    if (NULL != str) {\
		g_string_free(str, TRUE);\
		str = NULL;\
   }

	CRAWLER_GSTRING_FREE(console.trip_name);
	CRAWLER_GSTRING_FREE(console.action_names);
	CRAWLER_GSTRING_FREE(console.triplibpath);
	CRAWLER_GSTRING_FREE(console.listenerUrl);
	//CRAWLER_GSTRING_FREE(console.dbusaddress);
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
	int rc = 0;
	g_thread_init(NULL);
	dbus_g_thread_init();
	dbus_threads_init_default();

	mutex_ctx_update = g_mutex_new();

	if (!g_module_supported()) {
		g_error("GLib MODULES are not supported on this platform!");
		return 1;
	}

	rc = grid_main(argc, argv, &cb);

	if (NULL != mutex_ctx_update) {
		g_mutex_free(mutex_ctx_update);
		mutex_ctx_update = NULL;
	}
	return rc;
}
