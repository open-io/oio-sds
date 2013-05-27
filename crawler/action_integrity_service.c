/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <glib.h>
#include <dbus/dbus.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sqlite3.h>

#include "crawler_constants.h"
#include "crawler_common_tools.h"

#include "../metautils/lib/loggers.h"
#include "../metautils/lib/common_main.h"
#include "../rules-motor/lib/motor.h"
#include "../rawx-lib/src/rawx.h"

static DBusConnection* conn;

static gboolean stop_thread;

static gchar* action_name;

static int service_pid;

static const gchar* occur_type_string;
static const gchar* db_temp_path;
static const gchar* db_base_name;

static GHashTable* volume_path_table; /* Association table between service identifier and its volume path  */

#define CONTAINER_DB_SCHEMA \
	"CREATE TABLE IF NOT EXISTS chunks ( "\
                "container_id TEXT NOT NULL PRIMARY KEY, "\
                "chunk_path TEXT NOT NULL, "\
                "content_path TEXT NOT NULL);"

static gchar*
get_volume_path(const gchar* chunk_path) {
	if (NULL == chunk_path)
		return NULL;

	gchar** chunk_path_tokens = g_strsplit(chunk_path, G_DIR_SEPARATOR_S, -1);
	if (NULL == chunk_path_tokens)
		return NULL;

	/* Finding the array length */
	int total_levels = 0;
	gchar* ptr = chunk_path_tokens[0];
	while (NULL != ptr) {
		total_levels++;
		ptr = chunk_path_tokens[total_levels];
	}
	/* ------- */

	if (3 > total_levels)
		return NULL;

	/* Freeing the last 3 occurences and replacing the NULL value */
	int i;
	for (i = total_levels - 1; i >= total_levels - 3; i--)
		g_free(chunk_path_tokens[i]);
	chunk_path_tokens[total_levels - 3] = NULL;
	/* ------- */

	gchar* volume_path = g_strjoinv(G_DIR_SEPARATOR_S, chunk_path_tokens);

	g_strfreev(chunk_path_tokens);

	return volume_path;
}

static gboolean
chunk_check_attributes(struct chunk_textinfo_s *chunk, struct content_textinfo_s *content) {
        if (!chunk->path)
                return FALSE;

        if (!chunk->id)
                return FALSE;

        if (!chunk->size)
                return FALSE;

        if (!chunk->hash)
                return FALSE;

        if (!chunk->position)
                return FALSE;

        if (!content->path)
                return FALSE;

        if (!content->size)
                return FALSE;

        if (!content->chunk_nb)
                return FALSE;

        if (!content->container_id)
                return FALSE;

        return TRUE;
}

static int
do_work(const gchar* source_path, guint64 service_uid) {
	if (NULL == source_path)
		return EXIT_FAILURE;

	/* Creating the associated SQLite database path */
        gchar* db_complete_path = (char*)g_malloc0((SHORT_BUFFER_SIZE * sizeof(char)) + sizeof(guint64));
        sprintf(db_complete_path, "%s%s%llu_%s", db_temp_path, G_DIR_SEPARATOR_S, (long long unsigned)service_uid, db_base_name);
        /* ------- */

	/* If it's the final occurence (which is caracterized by an empty source path string), the temporary DB is moved to the volume directory */
	if (!g_strcmp0("", source_path)) {
		gchar* volume_path = g_hash_table_lookup(volume_path_table, &service_uid);
		if (NULL == volume_path) {
                        g_free(db_complete_path);

                        return EXIT_FAILURE;
		}
		
		gchar* db_final_path = g_strconcat(volume_path, G_DIR_SEPARATOR_S, db_base_name, NULL);
		if (EXIT_FAILURE == move_file(db_complete_path, db_final_path, TRUE)) {
			g_free(db_complete_path);
			g_free(db_final_path);

			return EXIT_FAILURE;
		}
		g_free(db_final_path);

		g_hash_table_remove(volume_path_table, &service_uid);

		g_free(db_complete_path);

		return EXIT_SUCCESS;
	}
	/* ------- */

	/* Check if the chunk path is correct */
	if (!chunk_path_is_valid(source_path)) {
		g_free(db_complete_path);

		return EXIT_FAILURE;
	}
	/* ------- */

	/* Init */
        struct content_textinfo_s content_info;
        bzero(&content_info, sizeof(content_info));
        struct chunk_textinfo_s chunk_info;
        bzero(&chunk_info, sizeof(chunk_info));
        struct chunk_textinfo_extra_s chunk_info_extra;
        bzero(&chunk_info_extra, sizeof(chunk_info_extra));
        /* ------- */

	/* Read content info from chunk attributes */
	GError* local_error = NULL;
        if (!get_rawx_info_in_attr(source_path, &local_error, &content_info, &chunk_info) ||\
		!get_extra_chunk_info(source_path, &local_error, &chunk_info_extra)) {
		chunk_textinfo_free_content(&chunk_info);
		chunk_textinfo_extra_free_content(&chunk_info_extra);
		content_textinfo_free_content(&content_info);
		g_clear_error(&local_error);
		g_free(db_complete_path);

		return EXIT_FAILURE;
	}
	g_clear_error(&local_error);
	/* ------- */

	/* Checking chunk attributes */
       	if (FALSE == chunk_check_attributes(&chunk_info, &content_info)) {
        	chunk_textinfo_free_content(&chunk_info);
        	chunk_textinfo_extra_free_content(&chunk_info_extra);
        	content_textinfo_free_content(&content_info);
		g_free(db_complete_path);

                return EXIT_FAILURE;
        }
        /* ------- */

	/* Testing the existance of the db */
	sqlite3* db = NULL;
        sqlite3_stmt* stmt = NULL;
	FILE* fp = fopen(db_complete_path, "rb");
	if (NULL == fp) {
		if (SQLITE_OK != sqlite3_open(db_complete_path, &db)) {
			chunk_textinfo_free_content(&chunk_info);
                	chunk_textinfo_extra_free_content(&chunk_info_extra);
                	content_textinfo_free_content(&content_info);
                	g_free(db_complete_path);

                	return EXIT_FAILURE;
        	}

		/* Creating the chunk table */
		if (SQLITE_OK != sqlite3_prepare(db, CONTAINER_DB_SCHEMA, -1, &stmt, NULL)) {
			chunk_textinfo_free_content(&chunk_info);
                        chunk_textinfo_extra_free_content(&chunk_info_extra);
                        content_textinfo_free_content(&content_info);
			sqlite3_close(db);
			g_free(db_complete_path);

			return EXIT_FAILURE;
		}
		if (SQLITE_DONE != sqlite3_step(stmt)) {
			chunk_textinfo_free_content(&chunk_info);
                        chunk_textinfo_extra_free_content(&chunk_info_extra);
                        content_textinfo_free_content(&content_info);
			sqlite3_close(db);
                        g_free(db_complete_path);

                        return EXIT_FAILURE;
		}
		if (SQLITE_OK != sqlite3_finalize(stmt)) {
			chunk_textinfo_free_content(&chunk_info);
                        chunk_textinfo_extra_free_content(&chunk_info_extra);
                        content_textinfo_free_content(&content_info);
			sqlite3_close(db);
                        g_free(db_complete_path);

                        return EXIT_FAILURE;
		}
		/* ------- */
	}
	else {
		fclose(fp);

		if (SQLITE_OK != sqlite3_open(db_complete_path, &db)) {
			chunk_textinfo_free_content(&chunk_info);
                        chunk_textinfo_extra_free_content(&chunk_info_extra);
                        content_textinfo_free_content(&content_info);
                        g_free(db_complete_path);

                        return EXIT_FAILURE;
                }
	}
	/* ------- */

	/* Managing database */
	gchar* req_string = g_strconcat("INSERT OR REPLACE INTO chunks VALUES ( '", content_info.container_id, "', '", source_path, "', '", content_info.path, "');", NULL);
	if (SQLITE_OK != sqlite3_prepare(db, req_string, -1, &stmt, NULL)) {
		chunk_textinfo_free_content(&chunk_info);
                chunk_textinfo_extra_free_content(&chunk_info_extra);
                content_textinfo_free_content(&content_info);
		sqlite3_close(db);
		g_free(db_complete_path);
		g_free(req_string);

		return EXIT_FAILURE;
	}
	if (SQLITE_DONE != sqlite3_step(stmt)) {
		chunk_textinfo_free_content(&chunk_info);
                chunk_textinfo_extra_free_content(&chunk_info_extra);
                content_textinfo_free_content(&content_info);
		sqlite3_close(db);
		g_free(db_complete_path);
		g_free(req_string);

		return EXIT_FAILURE;
	}
	if (SQLITE_OK != sqlite3_finalize(stmt)) {
		chunk_textinfo_free_content(&chunk_info);
                chunk_textinfo_extra_free_content(&chunk_info_extra);
                content_textinfo_free_content(&content_info);
		sqlite3_close(db);
		g_free(db_complete_path);
		g_free(req_string);

		return EXIT_FAILURE;
	}
	/* ------- */
	
	/* Closing and freeing data */
	chunk_textinfo_free_content(&chunk_info);
        chunk_textinfo_extra_free_content(&chunk_info_extra);
        content_textinfo_free_content(&content_info);
	sqlite3_close(db);
	g_free(db_complete_path);
	g_free(req_string);
	/* ------- */	

	return EXIT_SUCCESS;
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

	/* Signal parsed parameters */
	int argc = -1;
        char** argv = NULL;

	guint64 context_id = 0;
	guint64 service_uid = 0;
	GVariant* occur = NULL;
	const gchar* source_path = NULL;
	/* ------- */

	dbus_error_init(&error);

	param_type = g_variant_type_new(gvariant_action_param_type_string); /* Initializing the GVariant param type value */

        while ( FALSE == stop_thread ) {
                dbus_connection_read_write(conn, DBUS_LISTENING_TIMEOUT);
                msg = dbus_connection_pop_message(conn);

                if (NULL == msg)
                        continue;

                if (dbus_message_is_signal(msg, signal_action_interface_name, action_name)) { /* Is the signal name corresponding to the service name */
			if (!dbus_message_iter_init(msg, &iter)) { /* Is the signal containing at least one parameter ? */
                                dbus_message_unref(msg);

				continue;
			}
                        else {
				if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&iter)) { /* Is the parameter corresponding to a string value ? */
					dbus_message_unref(msg);

					continue;
				}
                                else {
                                	dbus_message_iter_get_basic(&iter, &param_print); /* Getting the string parameter */

					if (NULL == (param = g_variant_parse(param_type, param_print, NULL, NULL, NULL))) {
						dbus_message_unref(msg);

						continue;
					}

					if (EXIT_FAILURE == disassemble_context_occur_argc_argv_uid(param, &context_id, &occur, &argc, &argv, &service_uid)) {
						g_variant_unref(param);
						dbus_message_unref(msg);

						continue;
					}

					/* End type signal management (last occurence for the specific service_uid value) */
					gboolean ending_signal = FALSE;
                                        if (0 == context_id) {
                                                GVariantType* occurt = g_variant_type_new("s");
                                                if (TRUE == g_variant_is_of_type(occur, occurt)) {
                                                        const gchar* occur_tile = g_variant_get_string(occur, NULL);
                                                        if (!g_strcmp0(end_signal_tile, occur_tile))
                                                                ending_signal = TRUE;
                                                }
                                                g_variant_type_free(occurt);
                                        }
					/* ------- */

					/* ACTION SPECIFIC AREA */

					if (FALSE == ending_signal) {
						/* Checking occurence form */
						GVariantType* gvt = g_variant_type_new(occur_type_string);
						if (FALSE == g_variant_is_of_type(occur, gvt)) {
							g_free(argv);
                                                	g_variant_unref(param);
                                                	dbus_message_unref(msg);
							g_variant_type_free(gvt);

							continue;
						}
						g_variant_type_free(gvt);
						/* ------- */

						/* Source path */
						source_path = g_variant_get_string(g_variant_get_child_value(occur, 0), NULL);
						/* ------- */

						/* Populate the association table between service unique identifier and its volume path */
                                        	if (NULL == g_hash_table_lookup(volume_path_table, &service_uid))
                                                	g_hash_table_insert(volume_path_table, &service_uid, get_volume_path(source_path));
                                        	/* ------- */
					}
					else
						source_path = "";

					/* Making chunk verifications and sending the ACK signal */
					char* temp_msg = (char*)g_malloc0((SHORT_BUFFER_SIZE * sizeof(char)) + sizeof(guint64));
					if (EXIT_FAILURE == do_work(source_path, service_uid)) {
						if (FALSE == ending_signal) {
                                			sprintf(temp_msg, "%s on %s for the context %llu and the file %s", ACK_KO, action_name, (long long unsigned)context_id, source_path);

                                			GRID_INFO("%s (%d) : %s", action_name, service_pid, temp_msg);

							GVariant* temp_msg_gv = g_variant_new_string(temp_msg);

                                			ack_parameters = g_variant_new(gvariant_ack_param_type_string, context_id, temp_msg_gv);

                                			if (EXIT_FAILURE == send_signal(conn, signal_object_name, signal_ack_interface_name, ACK_KO, ack_parameters))
                                        			GRID_ERROR("%s (%d) : System D-Bus signal sending failed %s %s", action_name, service_pid, error.name, error.message);

							g_variant_unref(ack_parameters);
						}
                        		}
					else {
						if (FALSE == ending_signal) {
                                                	sprintf(temp_msg, "%s on %s for the context %llu and the file %s", ACK_OK, action_name, (long long unsigned)context_id, source_path);

                                                	GRID_INFO("%s (%d) : %s", action_name, service_pid, temp_msg);

							GVariant* temp_msg_gv = g_variant_new_string(temp_msg);

                                        	        ack_parameters = g_variant_new(gvariant_ack_param_type_string, context_id, temp_msg_gv);

                                                	if (EXIT_FAILURE == send_signal(conn, signal_object_name, signal_ack_interface_name, ACK_OK, ack_parameters))
                                                        	GRID_ERROR("%s (%d) : System D-Bus signal sending failed %s %s", action_name, service_pid, error.name, error.message);
							g_variant_unref(ack_parameters);
						}
					}
                                        g_free(temp_msg);
					/* ------- */

					/* XXXXXXX */

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

	log4c_init();

        dbus_error_init(&error);

        /* DBus connexion */
        if (EXIT_FAILURE == init_dbus_connection(&conn)) {
                GRID_ERROR("%s (%d) : System D-Bus connection failed %s %s", action_name, service_pid, error.name, error.message);

                exit(EXIT_FAILURE);
        }
        /* ------- */

        /* Signal subscription */
        match_pattern = g_strconcat("type='signal',interface='", signal_action_interface_name, "'", NULL);
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

        exit(EXIT_SUCCESS);
}

static void
main_set_defaults(void) {
	conn = NULL;
	stop_thread = FALSE;
	action_name = "action_integrity";
	service_pid = getpid();
	occur_type_string = "(ss)";
	db_temp_path = "/tmp";
	db_base_name = "container.db";
	volume_path_table = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, (GDestroyNotify)g_free);
}

static void
main_specific_fini(void) {
	if (NULL != volume_path_table)
		g_hash_table_destroy(volume_path_table);
}

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
