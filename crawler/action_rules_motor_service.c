#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "atos.grid.action"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <metautils/lib/metautils.h>
#include <rules-motor/lib/motor.h>
#include <rawx-lib/src/rawx.h>
#include <meta2/remote/meta2_remote.h>
#include <integrity/lib/chunk_check.h>
#include <integrity/lib/content_check.h>

#include <dbus/dbus.h>

#include "lib/action_common.h"



struct SActionRulesMotorDataWork {
    gchar* source_path; // for all
    gchar* seq;     // for SQLX: sequence
    gchar* cid;     // for SQLX: container_id (hexa)
    gchar* type;    // for SQLX: type of bdd
    gchar* svc_url; // for all
};



// motor_env and rules_reload_time_interval declared in motor.h
struct rules_motor_env_s* motor_env = NULL;
gint rules_reload_time_interval = 1L;

// m2v1_list declared in libintegrity
GSList *m2v1_list = NULL;

static TCrawlerBus* conn;

static gboolean stop_thread;

static gchar* action_name;
static gchar* namespace_cmd_opt_name;
static gchar* source_type_cmd_opt_name;

static int service_pid;

static const gchar* occur_type1_string;
static const gchar* occur_type2_string;


/* Console parameters utils */
static GString* console_log_path = NULL;
/* ------- */


static gchar     g_service_name[SERVICENAME_MAX_BYTES];
static char*    g_dbusdaemon_address = NULL;
static GMainLoop *g_main_loop = NULL;



static gboolean
chunk_check_attributes(struct chunk_textinfo_s *chunk, struct content_textinfo_s *content)
{
	return check_chunk_info(chunk, NULL) && check_content_info(content, NULL);
}

static struct meta2_raw_content_s*
get_content_info(const gchar* meta2_url, gchar* container_id_str, gchar* content_name) {
	GError* error = NULL;
	addr_info_t meta2_addr;
	struct metacnx_ctx_s cnx;
	container_id_t container_id;

	if (NULL == meta2_url || NULL == container_id_str || NULL == content_name)
		return NULL;

	memset(&meta2_addr, 0x00, sizeof(addr_info_t));
	l4_address_init_with_url(&meta2_addr, meta2_url, &error);
	if (NULL != error) {
		g_clear_error(&error);

		return NULL;
	}
	memset(&cnx, 0x00, sizeof(cnx));
	cnx.fd = -1;
	metacnx_init_with_addr(&cnx, &meta2_addr, &error);
	if (NULL != error) {
		g_clear_error(&error);

		return NULL;
	}

	container_id_hex2bin(container_id_str, strlen(container_id_str), &container_id, &error);
	struct meta2_raw_content_s* ret = meta2_remote_stat_content(&cnx, container_id, content_name, strlen(content_name), &error);
	if (NULL != error) {
		g_clear_error(&error);
		metacnx_close(&cnx);

		return NULL;
	}

	metacnx_close(&cnx);

	return ret;
}

static int
do_work(gchar* namespace, gint8 source_type, const struct SActionRulesMotorDataWork* data_work) 
{
#define EXIT_IF_NULL_OR_EMPTY(str) if ((NULL == str)||(!g_strcmp0("", str)) ) 	return EXIT_FAILURE

	if (NULL == data_work)
		return EXIT_FAILURE;

	if (  (NULL == data_work->source_path)
		||(NULL == namespace)  )
		return EXIT_FAILURE;

	if (META2_TYPE_ID == source_type) {
		EXIT_IF_NULL_OR_EMPTY(data_work->svc_url);

	} else if (SQLX_TYPE_ID == source_type) {
		EXIT_IF_NULL_OR_EMPTY(data_work->svc_url);
		EXIT_IF_NULL_OR_EMPTY(data_work->seq);
		EXIT_IF_NULL_OR_EMPTY(data_work->cid);
		EXIT_IF_NULL_OR_EMPTY(data_work->type);
	}

	if (   (   (META2_TYPE_ID == source_type)
			 ||(SQLX_TYPE_ID == source_type) )
		&& (   (NULL == data_work->svc_url)
			 ||(!g_strcmp0("", data_work->svc_url)) )  ) 
		return EXIT_FAILURE;


	if (CHUNK_TYPE_ID == source_type) { /* If the source is a chunk */
		// FIXME: there are probably memory leaks in this block
		/* Check if the chunk path is correct */
		if (!chunk_path_is_valid(data_work->source_path))
			return EXIT_FAILURE;
		/* ------- */

		/* Init */
		struct stat chunk_stat;
		bzero(&chunk_stat, sizeof(chunk_stat));
		struct crawler_chunk_data_pack_s *data_block =  g_malloc(sizeof(struct crawler_chunk_data_pack_s));
		struct content_textinfo_s content_info;
		bzero(&content_info, sizeof(content_info));
		struct chunk_textinfo_s chunk_info;
		bzero(&chunk_info, sizeof(chunk_info));
		struct chunk_textinfo_extra_s chunk_info_extra;
		bzero(&chunk_info_extra, sizeof(chunk_info_extra));
		/* ------- */

		/* Read content info from chunk attributes */
		GError* local_error = NULL;
		if (!get_rawx_info_in_attr(data_work->source_path, &local_error, &content_info, &chunk_info) ||\
				!get_extra_chunk_info(data_work->source_path, &local_error, &chunk_info_extra)) {
			chunk_textinfo_free_content(&chunk_info);
			chunk_textinfo_extra_free_content(&chunk_info_extra);
			content_textinfo_free_content(&content_info);
			g_free(data_block);
			g_clear_error(&local_error);

			return EXIT_FAILURE;
		}
		g_clear_error(&local_error);
		/* ------- */

		/* Checking chunk attributes */
		if (FALSE == chunk_check_attributes(&chunk_info, &content_info)) {
			chunk_textinfo_free_content(&chunk_info);
			chunk_textinfo_extra_free_content(&chunk_info_extra);
			content_textinfo_free_content(&content_info);
			g_free(data_block);

			return EXIT_FAILURE;
		}
		/* ------- */

		struct motor_args args;
		stat(data_work->source_path, &chunk_stat);
		chunk_crawler_data_block_init(data_block, &content_info, &chunk_info, 
							&chunk_info_extra, &chunk_stat, data_work->source_path);
		motor_args_init(&args, (gpointer)data_block, source_type, &motor_env, namespace);
		pass_to_motor((gpointer)(&args));

		/* Free */
		chunk_textinfo_free_content(&chunk_info);
		chunk_textinfo_extra_free_content(&chunk_info_extra);
		content_textinfo_free_content(&content_info);
		g_free(data_block);
		/* ------- */

	}
	else if (SQLX_TYPE_ID == source_type) {
		struct crawler_sqlx_data_pack_s *data_block = g_malloc0(sizeof(struct crawler_sqlx_data_pack_s));

		struct motor_args args;
        sqlx_crawler_data_block_init(data_block, data_work->source_path,
				(char*)data_work->seq, (char*)data_work->cid, (char*)data_work->type,  (char*)data_work->svc_url);
		motor_args_init(&args, (gpointer)data_block, source_type, &motor_env, namespace);
		pass_to_motor((gpointer)(&args));

		sqlx_crawler_data_block_free(data_block);
	}
	else if (META2_TYPE_ID == source_type) {
		struct crawler_meta2_data_pack_s *data_block = g_malloc0(sizeof(struct crawler_meta2_data_pack_s));

		struct motor_args args;
		meta2_crawler_data_block_init(data_block, data_work->source_path, (char*)data_work->svc_url);
		motor_args_init(&args, (gpointer)data_block, source_type, &motor_env, namespace);
		pass_to_motor((gpointer)(&args));

		meta2_crawler_data_block_free(data_block);
	}
	else if (CONTENT_TYPE_ID == source_type) {
		struct crawler_chunk_data_pack_s *data_block = g_malloc(sizeof(struct crawler_chunk_data_pack_s));

		gchar** my_tokens = g_strsplit(data_work->source_path, G_DIR_SEPARATOR_S, -1); 
							/* 0 is the container_id_str, and 1 is the content_name */
		if (NULL == my_tokens || NULL == my_tokens[0] || NULL == my_tokens[1]) {
			if (NULL != my_tokens)
				g_strfreev(my_tokens);

			g_free(data_block);

			return EXIT_FAILURE;
		}

		struct content_textinfo_s content_info;
		bzero(&content_info, sizeof(struct content_textinfo_s));
		struct meta2_raw_content_s* raw_info = get_content_info(data_work->svc_url, my_tokens[0], my_tokens[1]);
		if (NULL == raw_info) {
			if (NULL != my_tokens)
				g_strfreev(my_tokens);

			g_free(data_block);

			return EXIT_FAILURE;
		}
		content_info.container_id = g_strdup(my_tokens[0]);
		content_info.path = g_strdup(my_tokens[1]);
		content_info.size = g_strdup_printf("%"G_GINT64_FORMAT, raw_info->size);
		if (raw_info->metadata)
			content_info.metadata = g_strndup((gchar*)raw_info->metadata->data, raw_info->metadata->len);
		if (raw_info->system_metadata)
			content_info.system_metadata = g_strndup((gchar*)raw_info->system_metadata->data, raw_info->system_metadata->len);

		struct motor_args args;
		chunk_crawler_data_block_init(data_block, &content_info, NULL, NULL, NULL, NULL);
		motor_args_init(&args, (gpointer)data_block, source_type, &motor_env, namespace);
		pass_to_motor((gpointer)(&args));

		if (NULL != my_tokens)
           g_strfreev(my_tokens);
		content_textinfo_free_content(&content_info);
		g_free(data_block);
		meta2_raw_content_clean(raw_info);
	}

	return EXIT_SUCCESS;
}




//==============================================================================
// Listening message come from, and execute action function
//==============================================================================

/* ------- */
struct SParamMsgrx {
	gchar* namespace;
	gint8 source_type;
	struct SActionRulesMotorDataWork data_work;
	//const gchar* source_path;
	//const gchar* seq;     // for SQLX: sequence
	//const gchar* cid;     // for SQLX: container_id (hexa)
	//const gchar* type;    // for SQLX: type of bdd
	//const gchar* svc_url; // such as meta2_url/sqlx_url/...
	gchar* dryrun;
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



static gboolean extract_paramMsgRx(gboolean allParam,  TActParam* pActParam,
		struct SParamMsgrx* pParam)
{
	if (pParam == NULL) return FALSE;

	if (allParam) {
		/* Namespace extraction */
		if (NULL == (pParam->namespace = get_argv_value(pActParam->argc, pActParam->argv, 
						action_name, namespace_cmd_opt_name))) {
			return FALSE;
		}
		/* ------- */


		/* Source type extraction */
		gchar* temp_source_type = get_argv_value(pActParam->argc, pActParam->argv, 
				action_name, source_type_cmd_opt_name);
		if (temp_source_type == NULL)
			return FALSE;
		pParam->source_type = (gint8)g_ascii_strtoll(temp_source_type, NULL, 10);
		g_free(temp_source_type);
		/* ------- */

		/* Checking occurence form */
		if (NULL == pActParam->occur)
			return FALSE;

		GVariantType* gvt = g_variant_type_new(occur_type1_string);
		if ((gvt == NULL)||(FALSE == g_variant_is_of_type(pActParam->occur, gvt))) {
			if (gvt != NULL)
				g_variant_type_free(gvt);
			gvt = g_variant_type_new(occur_type2_string);
			if ((gvt == NULL)||(FALSE == g_variant_is_of_type(pActParam->occur, gvt))) {
				g_variant_type_free(gvt);
				return FALSE;
			}
		}
		g_variant_type_free(gvt);

		/* Source path */
		pParam->data_work.source_path = (gchar*) get_child_value_string(pActParam->occur, 0);

		if (   (META2_TYPE_ID == pParam->source_type) 
			|| (CONTENT_TYPE_ID == pParam->source_type) ) {
			pParam->data_work.svc_url = (gchar*) g_variant_get_string(g_variant_get_child_value(pActParam->occur, 1), NULL);

		} else if (SQLX_TYPE_ID == pParam->source_type) {
			pParam->data_work.seq     = (gchar*) g_variant_get_string(g_variant_get_child_value(pActParam->occur, 1), NULL);
			pParam->data_work.cid     = (gchar*) g_variant_get_string(g_variant_get_child_value(pActParam->occur, 2), NULL);
			pParam->data_work.type    = (gchar*) g_variant_get_string(g_variant_get_child_value(pActParam->occur, 3), NULL);
			pParam->data_work.svc_url = (gchar*) g_variant_get_string(g_variant_get_child_value(pActParam->occur, 4), NULL);

		}
	}

	return TRUE;
}




gboolean action_set_data_trip_ex(TCrawlerBusObject *obj, const char* sender,
    const char *alldata, GError **error)
{
	GError* e = NULL;
	TActParam actparam;
	struct SParamMsgrx msgRx;
	act_paramact_init(&actparam);
	init_paramMsgRx(&msgRx);

	(void) obj;

	GVariant* param = act_disassembleParam((char*) alldata, &actparam);
	if (extract_paramMsgRx(TRUE, &actparam, &msgRx) == FALSE) {
		act_paramact_clean(&actparam);
		clean_paramMsgRx(&msgRx);
		g_variant_unref(param);
		*error = NEWERROR(1, "Bad format for received data");
		return FALSE;
	}


	/**/
	/* Running the rules motor and sending the ACK signal */
	char* temp_msg = (char*)g_malloc0((SHORT_BUFFER_SIZE * sizeof(char)) + sizeof(guint64));
	if (EXIT_FAILURE == do_work(msgRx.namespace, msgRx.source_type, &(msgRx.data_work))) {
		sprintf(temp_msg, "%s on %s for the context %llu and the file %s",
				ACK_KO, action_name, (long long unsigned)actparam.context_id, msgRx.data_work.source_path);
	} else {
		sprintf(temp_msg, "%s on %s for the context %llu and the file %s",
				ACK_OK, action_name, (long long unsigned)actparam.context_id, msgRx.data_work.source_path);
	}	

	char *status = act_buildResponse(action_name, service_pid, actparam.context_id, temp_msg);
	g_free(temp_msg);


    static TCrawlerReq* req = NULL;
    if (req)
        crawler_bus_req_clear(&req);

    e = crawler_bus_req_init(conn, &req, sender, SERVICE_PATH, SERVICE_IFACE_CONTROL);
    if (e) {
        GRID_WARN("Failed to connectd to crawler services %s : ", e->message);
		g_clear_error(&e);
    }

    tlc_Send_Ack_noreply(req, NULL, ((!e)?ACK_OK:ACK_KO), status);
    g_free(status);


	act_paramact_clean(&actparam);
	clean_paramMsgRx(&msgRx);
	g_variant_unref(param);

	return TRUE;
}


gboolean action_command(TCrawlerBusObject *obj, const char* cmd, const char *alldata,
		char** status, GError **error)
{
	TActParam actparam;
	struct SParamMsgrx msgRx;
	act_paramact_init(&actparam);
	init_paramMsgRx(&msgRx);

	(void) obj;
	(void) status;

	GRID_DEBUG("%s...\n", __FUNCTION__);
	act_disassembleParam((char*) alldata, &actparam);
	if (extract_paramMsgRx(FALSE, &actparam, &msgRx) == FALSE) {
		act_paramact_clean(&actparam);
		clean_paramMsgRx(&msgRx);
		*error = NEWERROR(1, "Bad format for received data");
		GRID_ERROR((*error)->message);
		return FALSE;
	}

	if (g_strcmp0(cmd, CMD_STARTTRIP) == 0) {
		//-----------------------
		// start process crawling
		GRID_INFO("start process's crawler");

		/* code here*/

	} else  if (g_strcmp0(cmd, CMD_STOPTRIP) == 0) {
		//----------------------
		// end process crawling
		GRID_INFO("stop process's crawler");

		/* code here*/

	} else {
		if (cmd)
			GRID_INFO("%s process's crawler", cmd);
		else
			GRID_INFO("%s process's crawler", "Unknown command");
	}

	GRID_DEBUG(">%s process's crawler\n", cmd);

	act_paramact_clean(&actparam);
	clean_paramMsgRx(&msgRx);

	return TRUE;
}





/* GRID COMMON MAIN */
static struct grid_main_option_s *
main_get_options(void) {
	static struct grid_main_option_s options[] = {
		{ "log", OT_STRING, {.str = &console_log_path},
			"The path of the log4c configuration file (empty will take the default configuration)" }
	};

	return options;
}

static void
main_action(void) {

	if (NULL != console_log_path) {
		gchar* log_path = g_string_free(console_log_path, FALSE);
		log4c_init();

		if (g_strcmp0("", log_path))
			log4c_load(log_path);

		g_free(log_path);
	}

    GError* error = NULL;

    g_type_init();

    g_main_loop = g_main_loop_new (NULL, FALSE);

	/* DBur connexion */
    error = tlc_init_connection(&conn, g_service_name, SERVICE_PATH, 
			"" /*g_dbusdaemon_address*/ /*pour le bus system: =""*/, 
			(TCrawlerBusObjectInfo*) act_getObjectInfo());
    if (error) {
        GRID_ERROR("System D-Bus connection failed: %s",
                /*g_cfg_action_name, g_service_pid,*/ error->message);
        exit(EXIT_FAILURE);
    }

	motor_env_init();

	GRID_INFO("%s (%d) : System D-Bus %s action signal listening thread started...", action_name, service_pid, action_name);

    g_main_loop_run (g_main_loop);

    crawler_bus_Close(&conn);

	destroy_motor_env(&motor_env);

	exit(EXIT_SUCCESS);
}

static void
main_set_defaults(void) {
	conn = NULL;
	stop_thread = FALSE;
	action_name = "action_rules_motor";
	namespace_cmd_opt_name = "n";
	source_type_cmd_opt_name = "t";
	service_pid = getpid();
	occur_type1_string = "(sssss)";
	occur_type2_string = "(ss)";

    buildServiceName(g_service_name, SERVICENAME_MAX_BYTES,
                    SERVICE_ACTION_NAME, action_name, service_pid, FALSE);	
}

static void
main_specific_fini(void) { }

static gboolean
main_configure(int argc, char **args) {
	argc = argc;
	args = args;

    if (argc >= 1)
        g_dbusdaemon_address = getBusAddress(args[0]);
    GRID_DEBUG("dbus_daemon address:\"%s\"", g_dbusdaemon_address);

	return TRUE;
}

static const gchar*
main_usage(void) { return ""; }

static void
main_specific_stop(void) {
	stop_thread = TRUE;
	g_main_loop_quit(g_main_loop);
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
	dbus_threads_init_default();

	return grid_main(argc, argv, &cb);
}
/* ------- */
