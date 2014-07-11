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
#include <integrity/lib/check.h>
#include <integrity/lib/chunk_check.h>
#include <integrity/lib/content_check.h>

#include <sqlite3.h>
#include <glib.h>
#include <dbus/dbus.h>

#include "lib/action_common.h"


// motor_env and rules_reload_time_interval declared in motor.h
struct rules_motor_env_s* motor_env = NULL;
gint rules_reload_time_interval = 1L;

// m2v1_list declared in libintegrity
GSList *m2v1_list = NULL;

static gchar* dryrun_cmd_opt_name;


static TCrawlerBus* conn;

static gboolean stop_thread;

static gchar* action_name;

static gboolean g_dryrun_mode = FALSE;
static int service_pid;

static const gchar* occur_type_string;
static const gchar* db_temp_path;
static const gchar* db_base_name;

static GHashTable* volume_path_table; /* Association table between service identifier and its volume path  */

static gchar     g_service_name[SERVICENAME_MAX_BYTES];
static char*    g_dbusdaemon_address = NULL;
static GMainLoop *g_main_loop = NULL;

typedef gboolean (*check_func_t)(check_info_t *info, check_result_t *result, GError **p_err, gpointer udata);

typedef struct _check_t {
	const gchar *name;
	check_func_t func;
	gpointer udata;
} check_t;

#define CONTAINER_DB_SCHEMA \
	"CREATE TABLE IF NOT EXISTS chunks ( "\
	"container_id TEXT NOT NULL PRIMARY KEY, "\
	"chunk_path TEXT NOT NULL, "\
	"content_path TEXT NOT NULL);"

static gchar*
get_volume_path(const gchar* chunk_path)
{
	gchar* volume_path = NULL;

	if (NULL == chunk_path)
		return NULL;

	gchar** chunk_path_tokens = g_strsplit(chunk_path, G_DIR_SEPARATOR_S, -1);
	if (NULL == chunk_path_tokens)
		return NULL;

	guint total_levels = g_strv_length(chunk_path_tokens);

	if (total_levels < 3) {
		g_strfreev(chunk_path_tokens);
		return NULL;
	}

	for (int i = total_levels - 1; i > 0; i--) {
		g_free(chunk_path_tokens[i]);
		chunk_path_tokens[i] = NULL;
		gchar *tmp = g_strjoinv(G_DIR_SEPARATOR_S, chunk_path_tokens);
		if (getxattr(tmp, RAWXLOCK_ATTRNAME_NS, NULL, 0) > 0) {
			// Found!
			volume_path = tmp;
			break;
		} else {
			g_free(tmp);
		}
	}

	g_strfreev(chunk_path_tokens);

	return volume_path;
}

static gboolean
chunk_check_orphan(check_info_t *info, check_result_t *result,
		GError **p_err, gpointer udata)
{
	(void) udata;
	return check_chunk_orphan(info, result, p_err);
}

static gboolean
chunk_check_attributes(check_info_t *info, check_result_t *result,
		GError **p_err, gpointer udata)
{
	(void) udata;
	if (check_chunk_info(info->ck_info, p_err)
			&& check_content_info(info->ct_info, p_err)) {
		if (result)
			result->check_ok = TRUE;
		return TRUE;
	}

	GRID_DEBUG("Broken attributes for chunk [%s]", info->source_path);

	if (!result)
		return FALSE;

	// find out chunk size (ie file size)
	struct stat chunk_stat;
	errno = 0;
	const gboolean found_size = (0 == stat(info->source_path, &chunk_stat));
	const int local_err = errno;

	if (trash_chunk(info, result)) {
		if (found_size)
			check_result_append_msg(result,
					" [size=%"G_GINT64_FORMAT"]", chunk_stat.st_size);
		else
			check_result_append_msg(result,
					" [unknown size] (%s)", strerror(local_err));
	}

	return TRUE;
}

static int
_move_temp_db(const gchar *source_path, const gchar *volume_path, guint64 *p_service_uid)
{
	int ret = EXIT_FAILURE;
	gchar* db_final_path = NULL;
	gchar* db_complete_path_dryrun = NULL;
	gchar* db_complete_path = NULL;

	/* Creating the associated SQLite database path */
	db_complete_path = g_strdup_printf("%s%s%"G_GUINT64_FORMAT"_%s",
			db_temp_path, G_DIR_SEPARATOR_S, *p_service_uid, db_base_name);

	/* If it's the final occurrence (in which case we get an empty source
	 * path string), the temporary DB is moved to the volume directory */
	if (!g_strcmp0("", source_path)) {
		if (NULL == volume_path)
			goto label_error;

		db_final_path = g_strconcat(volume_path, G_DIR_SEPARATOR_S, db_base_name, NULL);

		if (g_dryrun_mode == FALSE) {
			//real mode
			if (EXIT_FAILURE == move_file(db_complete_path, db_final_path, TRUE))
				goto label_error;
		} else {
			//dryrun mode
			db_complete_path_dryrun = g_strconcat(db_complete_path, ".dryrun", NULL);
			DRYRUN_GRID("[%s] --> [%s] not executed, dryrun copy to [%s]\n",
                        db_complete_path, db_final_path, db_complete_path_dryrun);
			if (EXIT_FAILURE == move_file(db_complete_path, db_complete_path_dryrun, TRUE))
				goto label_error;
		}

		g_hash_table_remove(volume_path_table, p_service_uid);
	}

	ret = EXIT_SUCCESS;

label_error:
	g_free(db_complete_path_dryrun);
	g_free(db_final_path);
	g_free(db_complete_path);

	return ret;
}

static int
_fill_temp_db(const gchar *source_path, guint64 *p_service_uid, check_info_t *p_check_info)
{
	int ret = EXIT_FAILURE;
	sqlite3* db = NULL;
	sqlite3_stmt* stmt = NULL;
	gchar* req_string = NULL;
	gchar* db_complete_path = NULL;

	/* Creating the associated SQLite database path */
	db_complete_path = g_strdup_printf("%s%s%"G_GUINT64_FORMAT"_%s",
			db_temp_path, G_DIR_SEPARATOR_S, *p_service_uid, db_base_name);

	/* Testing the existence of the db */
	FILE* fp = fopen(db_complete_path, "rb");
	if (NULL == fp) {
		if (SQLITE_OK != sqlite3_open(db_complete_path, &db))
			goto label_error;
		/* Creating the chunk table */
		if (SQLITE_OK != sqlite3_prepare(db, CONTAINER_DB_SCHEMA, -1, &stmt, NULL))
			goto label_error;
		if (SQLITE_DONE != sqlite3_step(stmt))
			goto label_error;
		if (SQLITE_OK != sqlite3_finalize(stmt))
			goto label_error;
	}
	else {
		fclose(fp);
		if (SQLITE_OK != sqlite3_open(db_complete_path, &db))
			goto label_error;
	}

	/* Managing database */
	req_string = g_strconcat("INSERT OR REPLACE INTO chunks VALUES ( '",
			p_check_info->ct_info->container_id, "', '",
			source_path, "', '",
			p_check_info->ct_info->path, "');",
			NULL);
	if (SQLITE_OK != sqlite3_prepare(db, req_string, -1, &stmt, NULL))
		goto label_error;
	if (SQLITE_DONE != sqlite3_step(stmt))
		goto label_error;
	if (SQLITE_OK != sqlite3_finalize(stmt))
		goto label_error;

	ret = EXIT_SUCCESS;

label_error:
	sqlite3_close(db);
	g_free(db_complete_path);
	g_free(req_string);

	return ret;
}

static int
do_work(const gchar* source_path, guint64 service_uid, GSList *checks) {
	int ret = EXIT_FAILURE;
	GError* local_error = NULL;
	gchar* volume_path = NULL;
	check_info_t check_info;

	if (NULL == source_path)
		return EXIT_FAILURE;

	volume_path = g_hash_table_lookup(volume_path_table, &service_uid);

	if (!rawx_get_lock_info(volume_path,
			check_info.rawx_str_addr, sizeof(check_info.rawx_str_addr),
			check_info.ns_name, sizeof(check_info.ns_name), &local_error)
			|| local_error != NULL)
		goto label_error;
	GRID_DEBUG("Volume path: %s, namespace: '%s'", volume_path, check_info.ns_name);

	// TODO Temp db processing bypassed until we have a way to know when the
	// crawler has finished.
	if (FALSE && !g_strcmp0("", source_path)) {
		if (!_move_temp_db(source_path, volume_path, &service_uid))
			goto label_error;
	}

	/* Check if the chunk path is correct */
	if (!chunk_path_is_valid(source_path))
		goto label_error;

	/* Init */
	check_info.ct_info = g_malloc0(sizeof(struct content_textinfo_s));
	check_info.ck_info = g_malloc0(sizeof(struct chunk_textinfo_s));
	check_info.ck_extra = g_malloc0(sizeof(struct chunk_textinfo_extra_s));

	/* Read content info from chunk attributes */
	if (!get_rawx_info_in_attr(source_path, &local_error, check_info.ct_info, check_info.ck_info) ||
			!get_extra_chunk_info(source_path, &local_error, check_info.ck_extra))
		goto label_error;

	bzero(check_info.rawx_vol, sizeof(check_info.rawx_vol));
	memcpy(check_info.rawx_vol, volume_path, strlen(volume_path));
	bzero(check_info.source_path, sizeof(check_info.source_path));
	memcpy(check_info.source_path, source_path, strlen(source_path));
	check_info.options = NULL;
	if (g_dryrun_mode) {
		check_info.options = check_option_new();
		check_option_set_bool(check_info.options, CHECK_OPTION_DRYRUN, TRUE);
	}
	/* Running checks */
	GSList *c_iter = checks;
	check_t *check = NULL;
	check_result_t *result = NULL;
	for (; c_iter; c_iter = g_slist_next(c_iter)) {
		check = c_iter->data;
		GRID_DEBUG("Starting check [%s] on chunk [%s]", check->name, check_info.source_path);
		result = check_result_new();
		if (!check->func(&check_info, result, &local_error, check->udata)) {
			GRID_ERROR("Check [%s] failed on chunk [%s], error was [%s]",
					check->name, source_path,
					local_error ? local_error->message : "unspecified");
			goto label_error;
		} else {
			if (!result->check_ok) {
				if (result->msg)
					GRID_INFO("Check [%s] on chunk [%s]: %s",
							check->name, check_info.source_path, result->msg->str);
				else
					GRID_INFO("Check [%s] on chunk [%s]: KO (no details)",
							check->name, check_info.source_path);
				goto label_error;
			}
		}
		check_result_clear(&result, NULL);
	}

	// TODO Temp db processing bypassed until we have a way to know when the
	// crawler has finished.
	if (FALSE && !_fill_temp_db(source_path, &service_uid, &check_info))
		goto label_error;

	ret = EXIT_SUCCESS;

label_error:
	if (local_error)
		GRID_ERROR("%s", local_error->message);
	check_result_clear(&result, NULL);
	chunk_textinfo_free_content(check_info.ck_info);
	g_free(check_info.ck_info);
	chunk_textinfo_extra_free_content(check_info.ck_extra);
	g_free(check_info.ck_extra);
	content_textinfo_free_content(check_info.ct_info);
	g_free(check_info.ct_info);
	check_option_destroy(check_info.options);
	g_clear_error(&local_error);

	return ret;
}




//==============================================================================
// Listening message come from, and execute action function
//==============================================================================
/* ------- */
struct SParamMsgrx {
    const gchar* source_path;
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

    if (pParam->dryrun)       g_free(pParam->dryrun);
    
    init_paramMsgRx(pParam);
}
            

static gboolean extract_paramMsgRx(gboolean allParam,  TActParam* pActParam,
        struct SParamMsgrx* pParam)
{
    if (pParam == NULL)
        return FALSE;


    if (allParam == TRUE) {
		/* Checking occurence form */
        GVariantType* gvt = g_variant_type_new(occur_type_string);
        if (FALSE == g_variant_is_of_type(pActParam->occur, gvt)) {
            g_variant_type_free(gvt);
			return FALSE;
        }
        g_variant_type_free(gvt);

        /* ------- */
        if (NULL == (pParam->dryrun = get_argv_value(pActParam->argc, pActParam->argv, action_name,
                        dryrun_cmd_opt_name))) {
            g_dryrun_mode = FALSE;
		} else {
            g_dryrun_mode = TRUE;
            if (g_strcmp0(pParam->dryrun, "FALSE") == 0)
                g_dryrun_mode = FALSE;
        }

		/* Source path */
		pParam->source_path = get_child_value_string(pActParam->occur, 0);

    } else {
		pParam->source_path = ""; 
	}

	return TRUE;
}

static void
_add_check(GSList **checks, const gchar *name, check_func_t f, gpointer udata)
{
	check_t new_check = {.name = g_strdup(name), .func = f, .udata = udata};
	*checks = g_slist_append(*checks, g_memdup(&new_check, sizeof(new_check)));
}

static GSList*
_init_checks()
{
	GSList *checks = NULL;
	_add_check(&checks, "Chunk attributes", &chunk_check_attributes, NULL);
	_add_check(&checks, "Orphan chunk", &chunk_check_orphan, NULL);
	return checks;
}

static void
_free_checks(GSList *checks)
{
	void _free_check_name(gpointer _check, gpointer _udata)
	{
		check_t *check = _check;
		(void) _udata;
		g_free((gpointer) check->name);
	}
	g_slist_foreach(checks, _free_check_name, NULL);
	g_slist_free_full(checks, g_free);
}

gboolean action_set_data_trip_ex(TCrawlerBusObject *obj, const char* sender,
    const char *alldata, GError **error)
{
	int resultat = 0;
    TActParam actparam;
    struct SParamMsgrx msgRx;
    act_paramact_init(&actparam);
    init_paramMsgRx(&msgRx);

	(void) obj;

    GVariant* param = act_disassembleParam((char*) alldata, &actparam);
    if (extract_paramMsgRx(TRUE, &actparam, &msgRx ) == FALSE) {
        act_paramact_clean(&actparam);
        clean_paramMsgRx(&msgRx);
        g_variant_unref(param);
        *error = NEWERROR(1, "Bad format for received data");
        return FALSE;
    }


    /**/

	if ((msgRx.source_path) && (strlen(msgRx.source_path) > 0)) {
	    /* Populate the association table between service unique identifier and its volume path */
    	if (NULL == g_hash_table_lookup(volume_path_table, &(actparam.service_uid)))
        	g_hash_table_insert(volume_path_table, &(actparam.service_uid), get_volume_path(msgRx.source_path));
	}

	GSList *checks = _init_checks();
	resultat = do_work(msgRx.source_path, actparam.service_uid, checks);
	_free_checks(checks);


    // save response
	char* temp_msg = (char*)g_malloc0((SHORT_BUFFER_SIZE * sizeof(char)) + sizeof(guint64));
	sprintf(temp_msg, "%s on %s for the context %llu and the file %s", 
			((resultat!=EXIT_FAILURE)?ACK_OK:ACK_KO), action_name, 
			(long long unsigned)actparam.context_id, msgRx.source_path);
    char* status = act_buildResponse(action_name, service_pid, actparam.context_id, temp_msg);
    g_free(temp_msg);

	
    static TCrawlerReq* req = NULL;
    if (req)
        crawler_bus_req_clear(&req);

    GError* err = crawler_bus_req_init(conn, &req, sender, SERVICE_PATH, SERVICE_IFACE_CONTROL);
    if (err) {
        g_prefix_error(&err, "Failed to connectd to crawler services %s : ",
                        sender);
		GRID_WARN("Failed to send ack [%s]: %s", msgRx.source_path, err->message);
		g_clear_error(&err);
   }

    tlc_Send_Ack_noreply(req, NULL, ((resultat!=EXIT_FAILURE)?ACK_OK:ACK_KO), status);
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
static struct grid_main_option_s *
main_get_options(void) {
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



    GRID_INFO("%s (%d) : System D-Bus %s action signal listening thread started...", action_name, service_pid, action_name);

    g_main_loop_run (g_main_loop);

    crawler_bus_Close(&conn);

    exit(EXIT_SUCCESS);

}

static void
main_set_defaults(void) {
	conn = NULL;
	stop_thread = FALSE;
	action_name = "action_integrity";
    dryrun_cmd_opt_name = "dryrun";
	service_pid = getpid();
	occur_type_string = "(ss)";
	db_temp_path = "/tmp";
	db_base_name = "container.db";
	volume_path_table = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, (GDestroyNotify)g_free);

    buildServiceName(g_service_name, SERVICENAME_MAX_BYTES,
                    SERVICE_ACTION_NAME, action_name, service_pid, FALSE);

}

static void
main_specific_fini(void) {
	if (NULL != volume_path_table)
		g_hash_table_destroy(volume_path_table);
	free_m2v1_list();
}

static gboolean
main_configure(int argc, char **args) {
	// enable logging
	g_setenv("GS_DEBUG_ENABLE", "0", TRUE);

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
