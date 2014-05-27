#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <pthread.h>
#include <dbus/dbus.h>

#include <metautils/lib/metautils.h>

#include <glib.h>

#include "lib/crawler_constants.h"
#include "lib/crawler_common.h"
#include "lib/crawler_tools.h"
#include "lib/crawlerCmd-glue.h"





#define MAX_PIPE_LENGTH        512


static GThread  *g_progress_thread; /* The thread listening to the system D-Bus for returned progress signals */
static GThread  *g_timeout_thread;
static gboolean g_stop_thread; /* Flag to stop the listening threads */
static gboolean g_pending_command;
static GString* g_console_command;


static GMainLoop*   g_main_loop = NULL;
static gchar        g_service_name[SERVICENAME_MAX_BYTES];
static TCrawlerBus* g_tl_conn;
static TCrawlerReq* g_req;
static gchar*       g_ctrl_command;
static gint32       g_service_pid;
static GString*     g_crawler_name;








/*-------------------------------------------------------------------*/
/* transport layer of crawler                                        */
/*-------------------------------------------------------------------*/



static GError* tl_init_command(TCrawlerBus* conn, TCrawlerReq** req, gchar* crawlerName)
{
	GError* err = NULL;

	if (!crawlerName) {
		err = crawler_bus_reqBase_init(conn, req);
	} else {
		err = crawler_bus_req_init(conn, req, crawlerName, SERVICE_PATH, SERVICE_IFACE_CONTROL);
	}
	if (err) {
		g_prefix_error(&err, "Failed to connected to %s services : ",
				((crawlerName)?crawlerName:""));
		return err;
	}

	return NULL;
}



static void tl_close(TCrawlerBus** conn)
{
	if (*conn)
		crawler_bus_Close(conn);
	*conn = NULL;
}



static char** tl_send_command_strv(TCrawlerBus* conn, gchar* crawlerName, gchar* cmd, gchar* alldata)
{
	char** listnames = NULL;
	TCrawlerReq* req = NULL;
	GError* err = NULL;

	(void) alldata;

	// init request
	err = tl_init_command(conn, &req, crawlerName);
	if (err) {
		GRID_ERROR("Failed to init request, command=%s: %s", cmd, err->message);
		if (req) crawler_bus_req_clear(&req);
		g_clear_error(&err);
		return NULL;
	}

	//send command
	listnames = NULL;
	if (!g_strcmp0(CTRL_LIST, cmd)) {
		if (crawlerName == NULL) {	
			// send command to base
			err = crawler_bus_reqBase_GetListNames(req, &listnames);
		} else {
			GRID_ERROR("%s: Unknown command %s", __FUNCTION__, cmd);
		}


	} else {
		GRID_ERROR("%s: Unknown command %s", __FUNCTION__, cmd);
	}

	crawler_bus_req_clear(&req);

	return listnames;
}




static TCrawlerReq* tl_send_command(TCrawlerBus* conn, GError** error, 
		gchar* crawlerName, gchar* cmd, gchar* alldata)
{
	GError*      err = *error;
	TCrawlerReq* req = NULL;

	// init request
	err = tl_init_command(conn, &req, crawlerName);
	if (err) {
		GRID_ERROR("Failed to init request, command=%s: %s", cmd, err->message);
		if (req) crawler_bus_req_clear(&req);
		g_clear_error(&err);
		return NULL;
	}


	err = tlc_Send_CmdProcEx(req, -1 /*MAX_ACTION_TIMEOUT*1000*/,
			NULL, NULL, cmd, g_service_name, alldata );
	if (err) {
		crawler_bus_req_clear(&req);	
		return NULL;
	} 

	return req;
}



/*-------------------------------------------------------------------*/
/* callback from transport layer                                     */
/*-------------------------------------------------------------------*/


gboolean crawlerCmd_ack(TCrawlerBusObject *obj, const char* cmd,
		const char *alldata, GError **error)
{
	(void) obj;
	(void) alldata;
	(void) error;

	// analyse response
	if (!g_strcmp0(CTRL_LIST, g_ctrl_command)) {
		//-------------------------
		// command will received a list of char*
		char** listname = NULL;

		if ((alldata)&&(strlen(alldata) > 0)) {
			listname = g_strsplit(alldata, "|", 0);
		}

		g_printf("Action list:\n");
		// diplay response: list
		if (listname) {
			// dump all list to stdout
			char** ptr = listname;
			for( ;*ptr;ptr++) {
				if (ptr == NULL) break;
				if (*ptr == NULL) continue;

				g_printf ("  %s\n", *ptr);
			}
			g_strfreev (listname);
		} else {
			g_printf("0 action\n");
		}


	} else if (   (!g_strcmp0(CTRL_STOP,     cmd))
			||(!g_strcmp0(CTRL_SLOW,     cmd))
			||(!g_strcmp0(CTRL_PAUSE,    cmd))
			||(!g_strcmp0(CTRL_RESUME,   cmd))
			||(!g_strcmp0(CTRL_PROGRESS, cmd)) ) {
		//-------------------------
		if (strlen(alldata) > 0)
			g_printf("%s\n", alldata);

		else 
			g_printf("no data received from crawler\n");

	} else {
		//-------------------------
		// command will receive        
		g_printf("   %s\n", alldata);
	}

	//g_free(alldata);

	g_pending_command = FALSE;

	//g_main_loop_quit(g_main_loop);

	return TRUE;
}



/*-------------------------------------------------------------------*/
/* thread                                                            */
/*-------------------------------------------------------------------*/


static void* thread_timeout()
{
	time_t begining_time_stamp;
	time_t current_time_stamp;

	time(&begining_time_stamp);
	time(&current_time_stamp);

	if (MAX_ACTION_TIMEOUT  > difftime(current_time_stamp, begining_time_stamp))

	while(!g_stop_thread && g_pending_command) {
		time(&current_time_stamp);
		if (MAX_ACTION_TIMEOUT  < difftime(current_time_stamp, begining_time_stamp))
			break;
			
		sleep(0.1);
	}

	if (g_stop_thread)
		GRID_INFO("Stopped forced!");
	else if (g_pending_command == TRUE)
		GRID_ERROR("No response from last sending command: timeout");

	g_main_loop_quit(g_main_loop);

	return NULL;
}


static void* thread_command() 
{
	GError* error = NULL;
	char* cn = NULL;

	/* DBus connexion */
	error = tlc_init_connection(&g_tl_conn, g_service_name, SERVICE_PATH,
			"" /*pour le bus system: =""*/,
			(TCrawlerBusObjectInfo*) &dbus_glib_crawlerCmd_object_info);
	if (error) {
		GRID_ERROR("System D-Bus connection failed: %s",
				/*g_cfg_action_name, g_service_pid,*/ error->message);
		exit(EXIT_FAILURE);
	}

	if (g_crawler_name)
		cn = g_string_free(g_crawler_name, FALSE);
	g_crawler_name=NULL;

	if (cn == NULL) {
		if (!g_strcmp0(CTRL_LIST, g_ctrl_command)) {
			//-------------------------
			// command will received a list of char*
			char** listname = NULL;

			listname = tl_send_command_strv(g_tl_conn, cn, g_ctrl_command, "");
			if (listname) {
				// dump all list to stdout
				char** ptr = listname;
				for( ;*ptr;ptr++) {
					if (ptr == NULL) break;
					if (*ptr == NULL) continue;

					g_printf ("  %s\n", *ptr);
				}
				g_strfreev (listname);
			}
		}

		g_pending_command = FALSE;
		sleep(1);		
		g_main_loop_quit(g_main_loop);

	} else {
		g_req = tl_send_command(g_tl_conn, &error, cn, g_ctrl_command, "");
		if (error)
			g_clear_error(&error);
	}

	return NULL;
}




static const gchar* main_usage(void) 
{
	return "./crawler_cmd [-Oname=<crawler_name>] -Ocommand=<command>]\n./crawler_cmd -Ocommand=help\n";
}



void usage(void) 
{
	g_print("Available commands list (general command):\n");
    g_print("------------------------\n");
	g_print("./crawler_cmd -Ocommand=<command>");
    g_print("\n<command>:\n");
    g_print("\thelp\t\t:\tList help\n");
    g_print("\tlist\t\t:\tList all process_name connected to the bus\n");
	g_print("\n");

	g_print("Available commands list (specific crawler command) :\n");
	g_print("------------------------\n");
	g_print("./crawler_cmd -Oname=<crawler_name> -Ocommand=<command>");
	g_print("\n<crawler_name>:\n");
	g_print("\tobtain by ./crawler_cmd -Ocommand=list\n");
	g_print("\tcrawler_name begining with \"atos.grid.Crawler_\"\n");
	g_print("\t(i.e.: atos.grid.Crawler_action_purge_container_19100)\n");
	g_print("\n");
	g_print("\n<command>:\n");
	g_print("\tstop\t\t:\tStops the crawler\n");
	g_print("\tpause\t\t:\tPauses the crawler\n");
	g_print("\tslow\t\t:\tSlows the crawler\n");
	g_print("\tresume\t\t:\tResume a previously paused or slowed crawler\n");
	g_print("\tprogress\t:\tShows the progress percentage and the status of the crawler\n");
	g_print("\n");
}





static void main_action(void) 
{
	int ret;

	g_type_init();
	g_main_loop = g_main_loop_new (NULL, FALSE);

	if (!g_console_command) 
		return;


	//--------------
	// check command
	gchar* command = g_string_free(g_console_command, FALSE);
	g_ctrl_command = g_malloc0(sizeof(char)*30);
	g_ctrl_command[0] = '\0';

	if (g_crawler_name != NULL) {
		if      (!g_strcmp0("list",     command)) g_strlcpy(g_ctrl_command, CTRL_LIST, 30);
		else if (!g_strcmp0("stop",     command)) g_strlcpy(g_ctrl_command, CTRL_STOP, 30);
		else if (!g_strcmp0("pause",    command)) g_strlcpy(g_ctrl_command, CTRL_PAUSE, 30);
		else if (!g_strcmp0("slow",     command)) g_strlcpy(g_ctrl_command, CTRL_SLOW, 30);
		else if (!g_strcmp0("resume",   command)) g_strlcpy(g_ctrl_command, CTRL_RESUME, 30);
		else if (!g_strcmp0("progress", command)) g_strlcpy(g_ctrl_command, CTRL_PROGRESS, 30);
	} else {
		if      (!g_strcmp0("list",     command)) g_strlcpy(g_ctrl_command, CTRL_LIST, 30);
		else if (!g_strcmp0("help",     command)) g_strlcpy(g_ctrl_command, "help", 30); 
	}

	//----------------
	// execute command
	if (strlen(g_ctrl_command) == 0) {			
		GRID_INFO("%s (%d) : Unknown command '%s'\n", g_service_name, g_service_pid, command);

	} else if (!g_strcmp0("help",     g_ctrl_command)) {
		usage();

	} else {			
		g_pending_command = TRUE;

		gboolean bresult = TRUE;
		g_progress_thread = g_thread_create(thread_command, NULL, TRUE, NULL);
		if (!g_progress_thread) {
			GRID_ERROR("%s (%d) : System D-Bus returned progress thread failed to start...", 
					g_service_name, g_service_pid);
			bresult = FALSE;
		}

		g_timeout_thread = g_thread_create(thread_timeout, NULL, TRUE, NULL);
		if (!g_timeout_thread) {
			GRID_ERROR("%s (%d) : timeout thread failed to start...",
					g_service_name, g_service_pid);
			bresult = FALSE;
		}


		if (bresult) {
			g_main_loop_run(g_main_loop);
		}
	}

	if (g_req)     crawler_bus_req_clear(&g_req);
	if (g_tl_conn) tl_close(&g_tl_conn);
	g_free(command);
	g_console_command = NULL;
}

static gboolean main_configure(int argc, char **args) 
{
	if (!g_console_command)
		return FALSE;

	argc = argc;
	args = args;

	return TRUE;
}


static struct grid_main_option_s *main_get_options(void) 
{
	static struct grid_main_option_s options[] = {
		{ "name", OT_STRING, {.str = &g_crawler_name},
			"The name of destination process, give it with \'list\' command"},
		{ "command", OT_STRING, {.str = &g_console_command},
			"The command to send to the crawler" }   
	};

	return options;
}

static void main_set_defaults(void) 
{
	g_stop_thread = FALSE;
	g_pending_command = FALSE;
	g_service_pid = getpid();	

	g_console_command = NULL;

	g_ctrl_command = NULL;
	g_crawler_name = NULL;

	g_tl_conn = NULL;
	g_req     = NULL;

	buildServiceName(g_service_name, SERVICENAME_MAX_BYTES,
			SERVICE_CRAWLER_NAME, "cmd", g_service_pid, FALSE);
}

static void main_specific_fini(void) 
{
	if (NULL != g_console_command)
		g_string_free(g_console_command, TRUE);

	if (NULL != g_crawler_name)
		g_string_free(g_crawler_name, TRUE);


}

static void main_specific_stop(void) 
{
	g_stop_thread = TRUE;
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

int main(int argc, char **argv) 
{
	return grid_main(argc, argv, &cb);
}

