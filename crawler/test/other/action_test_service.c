/* THIS FILE IS NO MORE MAINTAINED */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>

#include <glib.h>
#include <dbus/dbus.h>

#include <metautils/lib/metautils.h>

#include "crawler_constants.h"
#include "crawler_common_tools.h"

#include "listener/listener_remote.h"


static DBusConnection* conn;
static void*           g_zmq_ctx;
static void*           g_zmq_sock;
static int       g_idmsgzmq  = 0;

static gboolean stop_thread;

static gchar* action_name;

static gchar*       g_cfg_listenerUrl_cmd_opt_name;
static gchar* source_cmd_opt_name;
static gchar* destination_cmd_opt_name;
static gchar* deletion_cmd_opt_name;
static gchar*       g_cfg_crawlerID_cmd_opt_name;

static int service_pid;

static const gchar* occur_type_string;
static gchar*    g_crawlerID = NULL;


gboolean alcs_listener_connect(const char* listenerUrl)
{
    static gchar s_listenerUrl[100] = "";
    gboolean bInit = FALSE;

    if ((!listenerUrl)||strlen(listenerUrl) == 0) {
        if (g_zmq_sock != NULL)
            return TRUE;
        else return FALSE;
    }

    // other listener ?
    if (g_strcmp0(s_listenerUrl, listenerUrl) != 0) {
        g_strlcpy(s_listenerUrl, listenerUrl, 99);

        // if socket alreadyinit, close it before
        listener_remote_closesocket(g_zmq_sock);
        g_zmq_sock = NULL;
    }

    if (g_zmq_sock == NULL) {
        TLstError* err = NULL;
        g_zmq_sock = listener_remote_connect(&err, g_zmq_ctx, listenerUrl, 2000, -1);
        if (err != NULL) {
            GRID_ERROR("Error (%d) %s", err->code, err->message);
            listener_remote_error_clean(err);

        } else if (g_zmq_sock != NULL)
            bInit= TRUE;
    }  else bInit = TRUE;   // already init

    return bInit;

}


/**
 *  * svc_url / svc_url: meta2, solr, ...
 *   */
void alcs_listener_sendJSON(const gchar* listenerUrl, json_object* jobj)
{
    if (alcs_listener_connect(listenerUrl) == TRUE) {

        char* buf = listener_remote_json_getStr(jobj);
        if (buf != NULL) {
            GRID_DEBUG("send to listener: [%s]\n", buf);
            TLstError* err = listener_remote_sendBuffer(g_zmq_sock, buf, strlen(buf));
            if (err != NULL) {
                GRID_ERROR("Error (%d) %s", err->code, err->message);
                listener_remote_error_clean(err);
            } else GRID_TRACE("zmq_send ok");
        } else GRID_ERROR("Faile to convert JSON to String");
    }
}

            


void alcs_listener_buildHead(TLstJSONHeader* msgH, char* name, int pid, char* status, char* idcrawl)
{
    msgH->action_name = name;
    msgH->action_pid  = pid;

    if (status)
        g_strlcpy(msgH->status, status, LSTJSON_STATUS_MAX_CARACT);
    else
        g_strlcpy(msgH->status, "", LSTJSON_STATUS_MAX_CARACT);

    msgH->idmsg      = g_idmsgzmq;  g_idmsgzmq++;

    if (idcrawl)
        g_strlcpy(msgH->idcrawl, idcrawl, LSTJSON_IDCRAWL_MAX_CARACT);
    else
        g_strlcpy(msgH->idcrawl, "", LSTJSON_IDCRAWL_MAX_CARACT);
}

/**
 *  * return char*, muszt free() the return value if != NULL
 *   */
struct json_object * alcs_listener_request_buildData(TLstJSONHeader* msgH, gchar* filename)
{
    struct json_object *j_root, /**j_head,*/ *j_datah, *j_data;

    //build frame request, with header
    j_root = listener_remote_json_init(msgH, FALSE);
    if (!j_root)
        return NULL;

    //----
    //    // build common data
    j_datah = listener_remote_json_newSection();
    if (!j_datah) {
        listener_remote_json_clean(j_root);
        return NULL;
    }

    if (  (listener_remote_json_addStringToSection(j_datah, "NAME",   (char*) filename) != NULL)) {
        listener_remote_json_clean(j_datah);
        listener_remote_json_clean(j_root);
        return NULL;
    } else
        listener_remote_json_addSection(j_root, LST_SECTION_DATAH, j_datah);



    //----
    //    // build data toi reduce by listener&reduce
    j_data = listener_remote_json_newSection();
    if (!j_data) {
        listener_remote_json_clean(j_root);
        return NULL;
    }

    //build msg: body about service
    if (  (listener_remote_json_addIntToSection(j_data, "NB_FILENAME",          1) != NULL)) {
        listener_remote_json_clean(j_data);
        listener_remote_json_clean(j_root);
        return NULL;
    } else listener_remote_json_addSection(j_root, LST_SECTION_DATAR, j_datah);


    return j_root;
}

           
/**
 *  * build requete command format json
 *   */
struct json_object * alcs_listener_request_buildCmd(TLstJSONHeader* msgH)
{
    struct json_object *j_root;

    //build empty frame with all section
    j_root = listener_remote_json_init(msgH, TRUE);
    if (!j_root)
        return NULL;

    return j_root;
}


void alcs_listener_sendData(const char* listenerUrl, gchar* filename)
{
    TLstJSONHeader msgH;
    struct json_object* jobj;
    gboolean bMeta1Only = FALSE;

    // listener utiliséOB
    if ((filename == NULL)||(strlen(filename)==0))
        return;	

    // header msg
    alcs_listener_buildHead(&msgH, action_name, service_pid,
            LISTENER_JSON_KEYNAME_HEAD_STATUS_data, g_crawlerID);

    jobj = alcs_listener_request_buildData(&msgH, filename);
    alcs_listener_sendJSON(listenerUrl, jobj);
    listener_remote_json_clean(jobj);
    

}

void alcs_listener_sendStopMsg(const char* listenerUrl)
{
    TLstJSONHeader msgH;
    struct json_object* jobj;

    if (listenerUrl == NULL)
        return;

    // header msg
     alcs_listener_buildHead(&msgH, action_name, service_pid,
            LISTENER_JSON_KEYNAME_HEAD_STATUS_stopact, g_crawlerID);

    jobj =   alcs_listener_request_buildCmd(&msgH);
    alcs_listener_sendJSON(listenerUrl, jobj);
    listener_remote_json_clean(jobj);
}





/*
 * This method is listening to the system D-Bus action interface for action signals
 **/
static void
listening_action() {
	DBusError error;
	DBusMessage* msg = NULL;
	DBusMessageIter iter;
	GVariantType* param_type = NULL;
	const char* param_print = NULL;
	GVariant* param = NULL;
	GVariant* ack_parameters = NULL;
	gchar* temp = NULL;

	/* Signal parsed parameters */
	int argc = -1;
	char** argv = NULL;

	guint64 context_id = 0;
	guint64 service_uid = 0;
	GVariant* occur = NULL;
	gchar* source_directory_path = NULL;
	const gchar* source_path = NULL;
	gchar* destination_directory_path = NULL;
	const gchar* destination_path = NULL;
	gboolean deletion = FALSE;
	gchar* crawlerID = NULL;
	gchar* tmp_listenerUrl;
	/* ------- */

	dbus_error_init(&error);

	/* Initializing the GVariant param type value */
	param_type = g_variant_type_new(gvariant_action_param_type_string);

	while ( FALSE == stop_thread ) {
		dbus_connection_read_write(conn, DBUS_LISTENING_TIMEOUT);
		msg = dbus_connection_pop_message(conn);

		if (NULL == msg)
			continue;

		GRID_TRACE("Received msg from dbus");

		/* Is the signal name corresponding to the service name */
		if (dbus_message_is_signal(msg, SERVICE_IFACE_ACTION, action_name)) {
			/* Is the signal containing at least one parameter ? */
			if (!dbus_message_iter_init(msg, &iter)) {
				GRID_TRACE("msg does not contain parameters");
				continue;
			} else {
				/* Is the parameter corresponding to a string value ? */
				if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&iter)) {
					dbus_message_unref(msg);
					GRID_TRACE("msg parameter is not a string");					
					continue;
				} else {
					/* Getting the string parameter */
					dbus_message_iter_get_basic(&iter, &param_print);

					if (NULL == (param = g_variant_parse(param_type, param_print, NULL, NULL, NULL))) {
						dbus_message_unref(msg);
						GRID_TRACE("Failed to get string param");
						continue;
					}

					if (EXIT_FAILURE == disassemble_context_occur_argc_argv_uid(
								param, &context_id, &occur, &argc, &argv, &service_uid)) {
						g_variant_unref(param);
						dbus_message_unref(msg);
						GRID_TRACE("Failed to parse string param");
						continue;
					}

					/* End type signal management (last occurence for the specific service_uid value) */
					gboolean ending_signal = FALSE;
					if (0 == context_id) {
						GVariantType* occurt = g_variant_type_new("(s)");
						if (TRUE == g_variant_is_of_type(occur, occurt)) {
							const gchar* occur_tile = g_variant_get_string(occur, NULL);
							if (!g_strcmp0(end_signal_tile, occur_tile))
								ending_signal = TRUE;
						}
						g_variant_type_free(occurt);
					}
					/* ------- */

					if (NULL == (tmp_listenerUrl = get_argv_value(argc, argv, action_name,
                                    g_cfg_listenerUrl_cmd_opt_name))) {
                        GRID_TRACE("Failed to get crawlerID from args");
                    }
					GRID_TRACE("ListenerUrl=[%s]", (tmp_listenerUrl==NULL)?"null":tmp_listenerUrl);



                    if (NULL == (crawlerID = get_argv_value(argc, argv, action_name,
                                    g_cfg_crawlerID_cmd_opt_name))) {
                        g_free(argv);
                        g_variant_unref(param);
                        dbus_message_unref(msg);
                        GRID_TRACE("Failed to get crawlerID from args");
                        continue;
                    }
					GRID_TRACE("crawlerID=[%s]", (crawlerID==NULL)?"null":crawlerID);


					/* ACTION SPECIFIC AREA */
					if (FALSE == ending_signal) {
						/* Source directory path extraction */
						if (NULL == (source_directory_path = get_argv_value(argc, argv, action_name, source_cmd_opt_name))) {
							g_free(argv);
							g_variant_unref(param);
							dbus_message_unref(msg);
							GRID_TRACE("Failed source_directory_path");
							continue;
						}

						/* ------- */
						/* Deletion boolean extraction */
						deletion = FALSE;
						/* ------- */

						GRID_TRACE("source_directory_path=[%s]", source_directory_path);
						/* Preparing the complete pathes */
						GVariantType* gvt = g_variant_type_new(occur_type_string);
						if (NULL == occur || FALSE == g_variant_is_of_type(occur, gvt)) {
							g_free(source_directory_path);
							g_free(argv);
							g_variant_unref(param);
							dbus_message_unref(msg);
							g_variant_type_free(gvt);
							GRID_TRACE("Faled to get specific signal parameter occur from message");
							continue;
						}

						g_variant_type_free(gvt);


						gchar* value = NULL;
						GVariant* temp_value = g_variant_get_child_value(occur, 0);
						if (temp_value) {
							value = g_variant_get_string(temp_value, NULL);
							g_variant_unref(temp_value);
						}

						if (value != NULL) {
							source_path = g_strconcat(source_directory_path, G_DIR_SEPARATOR_S, value, NULL);
							GRID_TRACE("source_path=[%s]", source_path);
						} else GRID_TRACE("source_path=[null]");

						/* ------- */


					if (g_crawlerID != NULL) {
                        g_free(g_crawlerID);
                        g_crawlerID = NULL;
                    }
					if ((crawlerID != NULL)&&(strlen(crawlerID)>0)) {
                        g_crawlerID = g_malloc0(strlen(crawlerID) + 10);
                        g_strlcpy(g_crawlerID, crawlerID, strlen(crawlerID)+1);
                    }


					alcs_listener_sendData(tmp_listenerUrl, source_path);



						/* Moving the file and sending the ACK signal */
						char* temp_msg = (char*)g_malloc0((SHORT_BUFFER_SIZE * sizeof(char)) + sizeof(guint64));
						sprintf(temp_msg, "%s on ACTION_TEST for the context %llu and the file %s", ACK_OK, (long long unsigned)context_id, source_path);

						GRID_INFO("%s (%d) : %s", action_name, service_pid, temp_msg);

						GVariant* temp_msg_gv = g_variant_new_string(temp_msg);

						ack_parameters = g_variant_new(gvariant_ack_param_type_string, context_id, temp_msg_gv);

						if (EXIT_FAILURE == send_signal(conn, SERVICE_OBJECT_NAME, SERVICE_IFACE_ACK, ACK_OK, ack_parameters))
							GRID_ERROR("%s (%d) : System D-Bus signal sending failed %s %s", action_name, service_pid, error.name, error.message);
						//				}
						g_variant_unref(ack_parameters);
						g_free(temp_msg);
						/* ------- */

						g_free(destination_directory_path);
						g_free(source_directory_path);

						/* XXXXXXX */
					} else {
						alcs_listener_sendStopMsg(tmp_listenerUrl);
					}

					g_free(argv);
					g_variant_unref(param);
				}
			}
		}

		dbus_message_unref(msg);
	}

	g_variant_type_free(param_type);
}

/* GRID COMMON MAIN */
static struct grid_main_option_s *
main_get_options(void) {
	static struct grid_main_option_s options[] = {
		{ NULL, 0, {.b=NULL}, NULL }
	};

	return options;
}

static void
main_action(void) {
	gchar* match_pattern = NULL;
	DBusError error;

	dbus_error_init(&error);

	//init zmq lib
	g_zmq_ctx = listener_remote_init();
	if (!g_zmq_ctx) {
		fprintf(stderr, "zmq_init failed (%d)", errno);
		exit(EXIT_FAILURE);
	}

	/* DBus connexion */
	if (EXIT_FAILURE == init_dbus_connection(&conn)) {
		GRID_ERROR("%s (%d) : System D-Bus connection failed %s %s", action_name, service_pid, error.name, error.message);

		exit(EXIT_FAILURE);
	}
	/* ------- */

	/* Signal subscription */
	match_pattern = g_strconcat("type='signal',interface='", SERVICE_IFACE_ACTION, "'", NULL);
	dbus_bus_add_match(conn, match_pattern, &error);
	dbus_connection_flush(conn);
	if (dbus_error_is_set(&error)) {
		GRID_ERROR("%s (%d) : Subscription to the system D-Bus action signals on the action interface failed %s %s", action_name, service_pid, error.name, error.message);

		g_free(match_pattern);

		exit(EXIT_FAILURE);
	}

	g_free(match_pattern);
	/* ------- */

	GRID_INFO("%s (%d) : System D-Bus %s action signal listening thread started...", action_name, service_pid, action_name);
	listening_action();

    /* zmq: exited */
    GRID_INFO("Waiting end of tramsit data...");
    listener_remote_close(g_zmq_ctx, g_zmq_sock);

	exit(EXIT_SUCCESS);
}

static void
main_set_defaults(void) {
	conn = NULL;
	stop_thread = FALSE;
	action_name = "action_test";
	source_cmd_opt_name = "s";
	destination_cmd_opt_name = "f";
	deletion_cmd_opt_name = "d";
	g_cfg_crawlerID_cmd_opt_name = "crawlerID";
	g_cfg_listenerUrl_cmd_opt_name = "l";
	service_pid = getpid();
	occur_type_string = "(s)";
}

static void
main_specific_fini(void) { }

static gboolean
main_configure(int argc, char **args) {
	argc = argc;
	args = args;

	return TRUE;
}

static const gchar*
main_usage(void) { return ""; }

static void
main_specific_stop(void) {
	stop_thread = TRUE;
	GRID_INFO("%s (%d) : System D-Bus %s action signal listening thread stopped...", action_name, service_pid, action_name);
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
main(int argc, char **argv) {
	return grid_main(argc, argv, &cb);
}
/* ------- */
