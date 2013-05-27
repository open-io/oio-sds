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
#include <autogen.h>
#include <generic.h>

#include <neon/ne_basic.h>
#include <neon/ne_request.h>
#include <neon/ne_session.h>

#include "crawler_constants.h"
#include "crawler_common_tools.h"

#include "../meta2v2/meta2v2_remote.h"
#include "../metautils/lib/loggers.h"
#include "../metautils/lib/common_main.h"
#include "../metautils/lib/hc_url.h"
#include "../meta2v2/meta2_utils.h"
#include "../meta2v2/generic.h"
#include "../rules-motor/lib/motor.h"
#include "../rawx-lib/src/rawx.h"

static DBusConnection* conn;

static gboolean stop_thread;

static gchar* action_name;
static gchar* namespace_cmd_opt_name;

static int service_pid;

static const gchar* occur_type_string;

static void
_fire_delete_request(const char *host, int port, const char *target, guint *count)
{
	GRID_TRACE("%s", __FUNCTION__);
	ne_session* s = ne_session_create("http", host, port);
	if (NULL != s) {
		ne_set_connect_timeout(s, 10);
		ne_set_read_timeout(s, 30);

		GRID_DEBUG("DELETE http://%s:%d%s", host, port, target);
		ne_request* r = ne_request_create(s, "DELETE", target);
		if (NULL != r) {
			switch (ne_request_dispatch(r)) {
				case NE_OK:
					GRID_DEBUG("%s (%d) : Delete OK", action_name, service_pid);
					*count = *count + 1;
					break;
				default:
					GRID_DEBUG("%s (%d) : Delete request KO : Request failed", action_name, service_pid);
					break;
			}
			ne_request_destroy(r);
		} else {
			GRID_ERROR("%s (%d) : Failed to create request", action_name, service_pid);
		}
		ne_session_destroy (s);
	}
}

static void
_delete_chunks_on_rawx(GSList *chunks, guint32 *count)
{
	GRID_TRACE("%s, %d chunks to drop", __FUNCTION__, g_slist_length(chunks));
	for(; chunks; chunks = chunks->next) {
		if(!chunks->data)
			continue;
		char* cid = CHUNKS_get_id((struct bean_CHUNKS_s*)chunks->data)->str; /* rawx://ip:port/VOL/ID */
		char **toks = g_strsplit(cid + 7, "/", 2); /* Extracting ip:port */
		if (toks && (2 == g_strv_length(toks))) {
			char **hp = g_strsplit(toks[0], ":", 2); /* Splitting ip:port */
			if (hp && (2 == g_strv_length(hp))) {
				_fire_delete_request(hp[0], atoi(hp[1]), strrchr(cid, '/'), count);
			} else {
				GRID_ERROR("%s (%d) : Failed to create HTTP session RAWX [%s]", action_name, service_pid, toks[0]);
			}
			g_strfreev(hp);
		} else {
			GRID_ERROR("%s (%d) : Wrong chunk bean URL format (ip:port)", action_name, service_pid);
		}
		g_strfreev(toks);
	}

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
	gchar* namespace = NULL;
	/* ------- */

	dbus_error_init(&error);

	param_type = g_variant_type_new(gvariant_action_param_type_string); /* Initializing the GVariant param type value */

        while ( FALSE == stop_thread ) {
                dbus_connection_read_write(conn, DBUS_LISTENING_TIMEOUT);
                msg = dbus_connection_pop_message(conn);

                if (NULL == msg)
                        continue;

		GRID_TRACE("Received msg from dbus");

                if (dbus_message_is_signal(msg, signal_action_interface_name, action_name)) { /* Is the signal name corresponding to the service name */
			if (!dbus_message_iter_init(msg, &iter)) { /* Is the signal containing at least one parameter ? */
                                dbus_message_unref(msg);
				GRID_TRACE("msg does not contain parameters");
				continue;
			}
                        else {
				if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&iter)) { /* Is the parameter corresponding to a string value ? */
					dbus_message_unref(msg);
					GRID_TRACE("msg parameter is not a string");
					continue;
				}
                                else {
                                	dbus_message_iter_get_basic(&iter, &param_print); /* Getting the string parameter */

					if (NULL == (param = g_variant_parse(param_type, param_print, NULL, NULL, NULL))) {
						dbus_message_unref(msg);
						GRID_TRACE("Failed to get string param");
						continue;
					}

					if (EXIT_FAILURE == disassemble_context_occur_argc_argv_uid(param, &context_id, &occur, &argc, &argv, &service_uid)) {
						g_variant_unref(param);
						dbus_message_unref(msg);
						GRID_TRACE("Failed to parse string param");
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
					GRID_TRACE("ending_signal is %s", ending_signal == 0 ? "FALSE" : "TRUE");

					if (FALSE == ending_signal) {
						/* Namespace extraction */
                                                if (NULL == (namespace = get_argv_value(argc, argv, action_name, namespace_cmd_opt_name))) {
                                                        g_free(argv);
                                                        g_variant_unref(param);
                                                        dbus_message_unref(msg);
							GRID_TRACE("Failed to get namespace from args");
                                                        continue;
                                                }
                                                /* ------- */

						/* Checking occurence form */
                                                GVariantType* gvt = g_variant_type_new(occur_type_string);
                                                if (FALSE == g_variant_is_of_type(occur, gvt)) {
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
						GVariant* temp_source_path = g_variant_get_child_value(occur, 0);
						if (temp_source_path) {
							source_path = g_variant_get_string(temp_source_path, NULL);

							g_variant_unref(temp_source_path);
						}
						GVariant* temp_meta2_url = g_variant_get_child_value(occur, 1);
						if (temp_meta2_url) {
							meta2_url = g_variant_get_string(temp_meta2_url, NULL);

							g_variant_unref(temp_meta2_url);
						}
                                                /* ------- */
                                        }
                                        else
                                        	source_path = "";

					GRID_DEBUG("Decoded source path from crawler : [%s]", source_path);

					GError* e = NULL;
					GSList* del_chunks_list = NULL;

					/* Sending purge request on the specified Meta2 for a specified container */
					if (FALSE == ending_signal) {
						struct hc_url_s *url = hc_url_empty();
						hc_url_set(url, HCURL_NS, namespace);
						gchar* chexid = g_substr(source_path, strlen(source_path) - 64, strlen(source_path));
        					hc_url_set(url, HCURL_HEXID, chexid);

						GRID_DEBUG("Sending PURGE to container [%s]", hc_url_get(url, HCURL_WHOLE));
						e = m2v2_remote_execute_PURGE(meta2_url, NULL, url, &del_chunks_list);

						/* For each entry of the deleted chunks list, DELETE call is sent to the RAWX */
						guint nb_del = 0;
						_delete_chunks_on_rawx(del_chunks_list, &nb_del);
						if(0 < nb_del)
							GRID_INFO("%"G_GUINT32_FORMAT" chunks deleted from %s", nb_del, hc_url_get(url, HCURL_WHOLE));

						g_free(chexid);
						hc_url_clean(url);
					}
					/* ------- */


					/* ------- */

					if (FALSE == ending_signal) {
						if (!e) {
							char* temp_msg = (char*)g_malloc0((SHORT_BUFFER_SIZE * sizeof(char)) + sizeof(guint64));
                                                	sprintf(temp_msg, "%s on %s for the context %llu and the file %s", ACK_OK, action_name, (long long unsigned)context_id, source_path);
                                                	GRID_DEBUG("%s (%d) : %s", action_name, service_pid, temp_msg);

                                                	GVariant* temp_msg_gv = g_variant_new_string(temp_msg);
                                                	ack_parameters = g_variant_new(gvariant_ack_param_type_string, context_id, temp_msg_gv);
                                                	if (EXIT_FAILURE == send_signal(conn, signal_object_name, signal_ack_interface_name, ACK_OK, ack_parameters))
                                                        	GRID_ERROR("%s (%d) : System D-Bus signal sending failed %s %s", action_name, service_pid, error.name, error.message);
                                               		g_variant_unref(ack_parameters);

                                                	g_free(temp_msg);
						}
						else {
							GRID_WARN("Failed to send PURGE to container [%s] : %s", source_path, e->message);
							
							char* temp_msg = (char*)g_malloc0((SHORT_BUFFER_SIZE * sizeof(char)) + sizeof(guint64));
                                                        sprintf(temp_msg, "%s on %s for the context %llu and the file %s", ACK_KO, action_name, (long long unsigned)context_id, source_path);
                                                        GRID_DEBUG("%s (%d) : %s", action_name, service_pid, temp_msg);

                                                        GVariant* temp_msg_gv = g_variant_new_string(temp_msg);
                                                        ack_parameters = g_variant_new(gvariant_ack_param_type_string, context_id, temp_msg_gv);
                                                        if (EXIT_FAILURE == send_signal(conn, signal_object_name, signal_ack_interface_name, ACK_KO, ack_parameters))
                                                                GRID_ERROR("%s (%d) : System D-Bus signal sending failed %s %s", action_name, service_pid, error.name, error.message);
                                                        g_variant_unref(ack_parameters);

                                                        g_free(temp_msg);
							g_clear_error(&e);
						}
					}

					g_variant_unref(param);
					/*g_free(namespace);*/ /* TODO : Guess should be commented on other services */
					g_free(argv);
				}
			}
		}

		GRID_TRACE("Dbus msg is not for us");

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
	action_name = "action_purge_container";
	namespace_cmd_opt_name = "n";
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
