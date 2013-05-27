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

#include "crawler_constants.h"
#include "crawler_common_tools.h"

#include "../metautils/lib/loggers.h"
#include "../metautils/lib/common_main.h"
#include "../rules-motor/lib/motor.h"
#include "../rawx-lib/src/rawx.h"
#include "../meta2/remote/meta2_remote.h"

static DBusConnection* conn;

static gboolean stop_thread;

static gchar* action_name;
static gchar* namespace_cmd_opt_name;
static gchar* source_type_cmd_opt_name;

static int service_pid;

static const gchar* occur_type_string;

/* Console parameters utils */
static GString* console_log_path = NULL;
/* ------- */

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
do_work(const gchar* source_path, gchar* namespace, gint8 source_type, const gchar* meta2_url) {
	if (NULL == source_path || NULL == namespace || (META2_TYPE_ID == source_type && (NULL == meta2_url || (!g_strcmp0("", meta2_url)))))
		return EXIT_FAILURE;

	if (CHUNK_TYPE_ID == source_type) { /* If the source is a chunk */
		/* Check if the chunk path is correct */
		if (!chunk_path_is_valid(source_path))
			return EXIT_FAILURE;
		/* ------- */

		/* Init */
                struct stat chunk_stat;
                bzero(&chunk_stat, sizeof(chunk_stat));
                struct crawler_chunk_data_pack_s *data_block =  malloc(sizeof(struct crawler_chunk_data_pack_s));
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
                        free(data_block);
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
			free(data_block);

			return EXIT_FAILURE;
		}
		/* ------- */

		struct motor_args args;
		stat(source_path, &chunk_stat);
        	chunk_crawler_data_block_init(data_block, &content_info, &chunk_info, &chunk_info_extra, &chunk_stat, source_path);
		motor_args_init(&args, (gpointer)data_block, source_type, &motor_env, namespace);
		pass_to_motor((gpointer)(&args));

		/* Free */
		chunk_textinfo_free_content(&chunk_info);
		chunk_textinfo_extra_free_content(&chunk_info_extra);
		content_textinfo_free_content(&content_info);
		free(data_block);
		/* ------- */
	}
	else if (META2_TYPE_ID == source_type) {
		struct crawler_meta2_data_pack_s *data_block =  malloc(sizeof(struct crawler_meta2_data_pack_s));
		
		struct motor_args args;	
		meta2_crawler_data_block_init(data_block, source_path, (char*)meta2_url);
		motor_args_init(&args, (gpointer)data_block, source_type, &motor_env, namespace);
		pass_to_motor((gpointer)(&args));

		/* Free */
                free(data_block);
		/* ------- */
	}
	else if (CONTENT_TYPE_ID == source_type) {
		struct crawler_chunk_data_pack_s *data_block = g_malloc(sizeof(struct crawler_chunk_data_pack_s));

		gchar** my_tokens = g_strsplit(source_path, G_DIR_SEPARATOR_S, -1); /* 0 is the container_id_str, and 1 is the content_name */
        	if (NULL == my_tokens || NULL == my_tokens[0] || NULL == my_tokens[1]) {
                	if (NULL != my_tokens)
                        	g_strfreev(my_tokens);
			
			free(data_block);

			return EXIT_FAILURE;
		}

		struct content_textinfo_s content_info;
		bzero(&content_info, sizeof(struct content_textinfo_s));
		struct meta2_raw_content_s* raw_info = get_content_info(meta2_url, my_tokens[0], my_tokens[1]);
		if (NULL == raw_info) {
			if (NULL != my_tokens)
                                g_strfreev(my_tokens);

			free(data_block);

                        return EXIT_FAILURE;
		}
		content_info.container_id = my_tokens[0];
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

		content_textinfo_free_content(&content_info);
		g_free(data_block);
		g_free(raw_info);
	}

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
	const gchar* meta2_url = NULL;
	gint8 source_type;
	gchar* namespace = NULL;
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
						/* Namespace extraction */
						if (NULL == (namespace = get_argv_value(argc, argv, action_name, namespace_cmd_opt_name))) {
                                                	g_free(argv);
                                                	g_variant_unref(param);
                                                	dbus_message_unref(msg);

                                                	continue;
                                        	}
						/* ------- */

						/* Source type extraction */
						gchar* temp_source_type = get_argv_value(argc, argv, action_name, source_type_cmd_opt_name);
						source_type = (gint8)g_ascii_strtoll(temp_source_type, NULL, 10);
						g_free(temp_source_type);
						/* ------- */

						/* Checking occurence form */
						GVariantType* gvt = g_variant_type_new(occur_type_string);
						if (NULL == occur || FALSE == g_variant_is_of_type(occur, gvt)) {
							g_free(argv);
                                                	g_variant_unref(param);
                                                	dbus_message_unref(msg);
							g_variant_type_free(gvt);
							g_free(namespace);

							continue;
						}
						g_variant_type_free(gvt);
						/* ------- */

						/* Source path */
						source_path = g_variant_get_string(g_variant_get_child_value(occur, 0), NULL);
						/* ------- */

						/* If the specified source type is container, Meta 2 URL */
						if (META2_TYPE_ID == source_type || CONTENT_TYPE_ID == source_type) {
							GVariant* temp_meta2_url = g_variant_get_child_value(occur, 1);
							if (NULL != temp_meta2_url) {
								meta2_url = g_variant_get_string(temp_meta2_url, NULL);

								g_variant_unref(temp_meta2_url);
							}
						}
						/* ------- */

						/* Running the rules motor and sending the ACK signal */
						char* temp_msg = (char*)g_malloc0((SHORT_BUFFER_SIZE * sizeof(char)) + sizeof(guint64));
						if (EXIT_FAILURE == do_work(source_path, namespace, source_type, meta2_url)) {
                                			sprintf(temp_msg, "%s on %s for the context %llu and the file %s", ACK_KO, action_name, (long long unsigned)context_id, source_path);

                                			GRID_INFO("%s (%d) : %s", action_name, service_pid, temp_msg);

							GVariant* temp_msg_gv = g_variant_new_string(temp_msg);

                	                		ack_parameters = g_variant_new(gvariant_ack_param_type_string, context_id, temp_msg_gv);

                        	        		if (EXIT_FAILURE == send_signal(conn, signal_object_name, signal_ack_interface_name, ACK_KO, ack_parameters))
                                	        		GRID_ERROR("%s (%d) : System D-Bus signal sending failed %s %s", action_name, service_pid, error.name, error.message);
                        			}
						else {
                                                	sprintf(temp_msg, "%s on %s for the context %llu and the file %s", ACK_OK, action_name, (long long unsigned)context_id, source_path);

                                                	GRID_INFO("%s (%d) : %s", action_name, service_pid, temp_msg);

							GVariant* temp_msg_gv = g_variant_new_string(temp_msg);

                                                	ack_parameters = g_variant_new(gvariant_ack_param_type_string, context_id, temp_msg_gv);

                                                	if (EXIT_FAILURE == send_signal(conn, signal_object_name, signal_ack_interface_name, ACK_OK, ack_parameters))
                                                        	GRID_ERROR("%s (%d) : System D-Bus signal sending failed %s %s", action_name, service_pid, error.name, error.message);
						}

						g_variant_unref(ack_parameters);
        	                                g_free(temp_msg);
						/* ------- */

						g_free(namespace);

						/* XXXXXXX */
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
                { "log", OT_STRING, {.str = &console_log_path},
		"The path of the log4c configuration file (empty will take the default configuration)" }
        };

        return options;
}

static void
main_action(void) {
        gchar* match_pattern = NULL;
        DBusError error;

	if (NULL != console_log_path) {
		gchar* log_path = g_string_free(console_log_path, FALSE);
		log4c_init();

		if (g_strcmp0("", log_path))
			log4c_load(log_path);

		g_free(log_path);
	}

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

	motor_env_init();
	
        GRID_INFO("%s (%d) : System D-Bus %s action signal listening thread started...", action_name, service_pid, action_name);
        listening_action();

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
	occur_type_string = "(ss)";
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
