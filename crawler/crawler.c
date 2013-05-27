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

#include <dbus/dbus.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/types.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>

#include <glib.h>
#include <gmodule.h>

#include "crawler_constants.h"
#include "crawler_common_tools.h"

#include "../metautils/lib/common_main.h"
#include "../metautils/lib/loggers.h"

static pthread_t control_ack_thread; /* The thread listening to the system D-Bus for control and acknowledgement signals */
static pthread_mutex_t mutex_ctx_update = PTHREAD_MUTEX_INITIALIZER; /* Mutex related to action context update */
static pthread_t action_timeout_thread; /* The thread checking for timeout on the contexts */
static gboolean stop_thread; /* Flag to stop the listening threads */

static const char* control_status; /* Current control status (BYPASS, PAUSE, ...) */

static const gchar* service_name;
static gint32 service_pid;
static guint64 service_uid;
static int my_argc;
static char** my_argv;

static struct trip_lib_entry_points* trip_ep; /* Trip library entry points (library and methods) */

static GHashTable* action_ctx_table; /* Association table between unique ID of actions and their related contexts */
static gchar** action_list; /* List of action names to perform (order matters) */
static guint action_list_length;

/* Console parameters utils */
static GString* console_trip_name;
static GString* console_action_names;
static gboolean console_infinite;
static GString* console_triplibpath;
/* ------- */

static void
main_set_defaults(void) {
        stop_thread = FALSE;
        control_status = CTRL_BYPASS;
        service_name = "crawler";
        service_pid = getpid();
        service_uid = g_get_monotonic_time();
        my_argc = -1;
        my_argv = NULL;
        trip_ep = NULL;
        action_ctx_table = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, (GDestroyNotify)g_free);
        action_list = NULL;
        action_list_length = 0;

        console_trip_name = NULL;
        console_action_names = NULL;
	console_triplibpath = NULL;
        console_infinite = FALSE;
}

static void
main_specific_fini(void) {
        (trip_ep->trip_end)();

        if (NULL != action_ctx_table)
                g_hash_table_destroy(action_ctx_table);

        if (NULL != trip_ep)
                free_trip_lib_entry_points(trip_ep);

        if (NULL != action_list)
                g_strfreev(action_list);

        GRID_INFO("%s (%d) : Crawler ended", service_name, service_pid);
}

static struct trip_lib_entry_points*
load_trip_library(gchar* trip_library_name)
{
	gchar* plugin_path = NULL;
	struct trip_lib_entry_points* ret = NULL;

	if (NULL == trip_library_name)
		return NULL;

	if (NULL != console_triplibpath) {
		gchar* temp_triplib = g_string_free(console_triplibpath, FALSE);
		console_triplibpath = g_string_new(temp_triplib);

		plugin_path = g_strconcat(temp_triplib, G_DIR_SEPARATOR_S, "lib", trip_library_name, ".so", NULL);

		g_free(temp_triplib);
	}
	else
		plugin_path = g_strconcat(default_trip_lib_dir, G_DIR_SEPARATOR_S, "lib", trip_library_name, ".so", NULL);

	ret = (struct trip_lib_entry_points*)g_malloc0(sizeof(struct trip_lib_entry_points));

	if (NULL == ret) {
		g_free(plugin_path);

		return NULL;
	}

	if (NULL == (ret->lib_ref = g_module_open(plugin_path, G_MODULE_BIND_LAZY))) {
		g_free(plugin_path);
		g_free(ret);
		return NULL;
	}

	if (!g_module_symbol(ret->lib_ref, "trip_start", &(ret->trip_start))) {
		g_free(plugin_path);
		g_free(ret);
		return NULL;
	}

	if (!g_module_symbol(ret->lib_ref, "trip_next", &(ret->trip_next))) {
		g_free(plugin_path);
		g_free(ret);
		return NULL;
	}

	if (!g_module_symbol(ret->lib_ref, "trip_end", &(ret->trip_end))) {
		g_free(plugin_path);
		g_free(ret);
		return NULL;
	}

	if (!g_module_symbol(ret->lib_ref, "trip_progress", &(ret->trip_progress))) {
		g_free(plugin_path);
		g_free(ret);
		return NULL;
	}

	g_free(plugin_path);
	return ret;
}

static gboolean
main_configure(int argc, char **args) {
        if (NULL == action_ctx_table) {
                GRID_ERROR("%s (%d) : Context table failed to create", service_name, service_pid);

                return FALSE;
        }
        GRID_INFO("%s (%d) : Context table created", service_name, service_pid);

        /* Trip management */
        if (NULL != console_trip_name) {
                gchar* temp_trip_name = g_string_free(console_trip_name, FALSE);
		console_trip_name = g_string_new(temp_trip_name);

                trip_ep = load_trip_library(temp_trip_name);

                g_free(temp_trip_name);
        }
        if (NULL == trip_ep || (EXIT_FAILURE == (int)(trip_ep->trip_start)(argc, args))) {
                GRID_ERROR("%s (%d) : Trip library failed to load", service_name, service_pid);

                return FALSE;
        }
        GRID_INFO("%s (%d) : Trip library loaded", service_name, service_pid);
        /* ------- */

        /* Action management */
        if (NULL != console_action_names) {
        	char* temp_action_names = g_string_free(console_action_names, FALSE);
		console_action_names = g_string_new(temp_action_names);

                action_list = g_strsplit(temp_action_names, opt_value_list_separator, -1);

                g_free(temp_action_names);
        }
        if (NULL == action_list)
                return FALSE;
        while((action_list[action_list_length]))
                action_list_length++;

        if (0 == action_list_length) {
                GRID_ERROR("%s (%d) : No action to list", service_name, service_pid);

                return FALSE;
        }
        GRID_INFO("%s (%d) : Action list feeded", service_name, service_pid);
        /* ------- */

        my_argc = argc;
        my_argv = args;
        GRID_INFO("%s (%d) : Additional parameters stored", service_name, service_pid);

        return TRUE;
}

static gboolean
action_timeout(struct action_context* current_ctx) {
	time_t current_time_stamp;

	time(&current_time_stamp);
	if (MAX_ACTION_TIMEOUT  > difftime(current_time_stamp, current_ctx->time_stamp))
		return FALSE;

	GRID_DEBUG("%s (%d) : Context %llu removed from the context table : Expired context", service_name, service_pid, (unsigned long long)current_ctx->id);

	return TRUE;
}

static void*
action_timeout_check() {
	while ( FALSE == stop_thread ) {
		if (NULL != action_ctx_table) {
			pthread_mutex_lock(&mutex_ctx_update);
			g_hash_table_foreach_remove(action_ctx_table, (GHRFunc)action_timeout, NULL);
			pthread_mutex_unlock(&mutex_ctx_update);
		}

		sleep(1);
	}

	return NULL;	
}

/* 
 * This function tests if all the remaining acknowledgement answers have been received
 **/
static gboolean
end_test() {
	GHashTableIter iter;
	struct action_context* temp_action_ctx = NULL;

	g_hash_table_iter_init(&iter, action_ctx_table);
	while(g_hash_table_iter_next(&iter, NULL, (void**)&temp_action_ctx)) {
		temp_action_ctx = (struct action_context*)temp_action_ctx;

		if (temp_action_ctx->pos < action_list_length)
			return FALSE;
	}

	return TRUE;
}

/*
 * This method updates a given context
 **/
static void
action_ctx_update(guint64 context_id, const char* ack_signal, GVariant* ack_params) {	
	DBusError error;
	DBusConnection* conn = NULL; /* The connection pointer to the system D-Bus */
	struct action_context* action_ctx = NULL;
	gchar* action_name = NULL;
	GVariant* signal_parameters = NULL;
	time_t temp_time_stamp;

	/* TODO : Make something with this ack_params content (its first element is the context_id) */
	ack_params = ack_params;
	/* ------- */

	pthread_mutex_lock(&mutex_ctx_update);
	action_ctx = (struct action_context*)g_hash_table_lookup(action_ctx_table, &context_id);
	pthread_mutex_unlock(&mutex_ctx_update);

	dbus_error_init(&error);

	if (NULL != action_ctx) {
		if (!g_strcmp0(ACK_OK, ack_signal)) {
			pthread_mutex_lock(&mutex_ctx_update);

			(action_ctx->pos)++;

			if (action_ctx->pos < action_list_length) {
				action_name = action_list[action_ctx->pos];
                                GRID_DEBUG("%s (%d) : Context %llu updated to the next action %s", service_name, service_pid, (unsigned long long)action_ctx->id, action_name);

				signal_parameters = assemble_context_occur_argc_argv_uid(action_ctx->id, action_ctx->occur, my_argc, my_argv, service_uid);

				if (NULL != signal_parameters) {
					if (EXIT_FAILURE != init_dbus_connection(&conn)) {
                        			time(&temp_time_stamp);
                        			action_ctx->time_stamp = temp_time_stamp;

						if (EXIT_FAILURE == send_signal(conn, signal_object_name, signal_action_interface_name, action_name, signal_parameters))
							GRID_ERROR("%s (%d) : System D-Bus signal sending failed in crawler %s %s", service_name, service_pid, error.name, error.message);
						else
                                        		GRID_DEBUG("%s (%d) : Signal %s sent on the system D-Bus interface %s for the context %llu", service_name, service_pid, action_name, signal_action_interface_name, (unsigned long long)action_ctx->id);

						if (NULL != conn)
                        				dbus_connection_unref(conn);
					}

					g_variant_unref(signal_parameters);
				}
			}
			else {
				g_hash_table_remove(action_ctx_table, &(action_ctx->id));

                                GRID_DEBUG("%s (%d) : Context %llu removed from the context table : No action left", service_name, service_pid, (unsigned long long)context_id);
			}

			pthread_mutex_unlock(&mutex_ctx_update);
		}
		else {
			pthread_mutex_lock(&mutex_ctx_update);

			action_name = action_list[action_ctx->pos];

			g_hash_table_remove(action_ctx_table, &(action_ctx->id));

			GRID_DEBUG("%s (%d) : Context %llu removed from the context table : Action %s failed", service_name, service_pid, (unsigned long long)context_id, action_name);

			pthread_mutex_unlock(&mutex_ctx_update);
		}	
	}
}

/*
 * This function is listening to the system D-Bus for control and acknowledgement signals (start, stop, pause, ok, ko...) and is launched in a separated thread
 **/
static void*
listening_control_ack() {
	DBusMessage* msg;
	DBusMessageIter iter;
	gchar* match_pattern = NULL;
	DBusError error;
	int pid_param = -1;
	guint64 context_id;
        DBusConnection* conn = NULL; /* The connection pointer to the system D-Bus */
        int ret;
	GVariant* ack_params = NULL;
	char* ack_params_print = NULL;

        dbus_error_init(&error);

        if (EXIT_FAILURE == (ret = init_dbus_connection(&conn))) { /* Opening the system D-Bus connection */
                GRID_ERROR("%s (%d) : System D-Bus connection failed in crawler %s %s", service_name, service_pid, error.name, error.message);

                return NULL;
        }

	/* Applying to the control interface */
 	match_pattern = g_strconcat("type='signal',interface='", signal_control_interface_name, "'", NULL);
	dbus_bus_add_match(conn, match_pattern, &error);
	dbus_connection_flush(conn);
	if (dbus_error_is_set(&error)) {
		GRID_ERROR("%s (%d) : Subscription to the system D-Bus failed in crawler %s %s", service_name, service_pid, error.name, error.message);

		g_free(match_pattern);

		return NULL;
	}
	GRID_DEBUG("%s (%d) : Crawler applied to the system D-Bus %s interface", service_name, service_pid, signal_control_interface_name);

	g_free(match_pattern);
	/* ------- */

	/* Applying to the acknowloedgement interface */
        match_pattern = g_strconcat("type='signal',interface='", signal_ack_interface_name, "'", NULL);
        dbus_bus_add_match(conn, match_pattern, &error);
        dbus_connection_flush(conn);
        if (dbus_error_is_set(&error)) {
                GRID_ERROR("%s (%d) : Subscription to the system D-Bus failed in crawler %s %s", service_name, service_pid, error.name, error.message);

                g_free(match_pattern);

                return NULL;
        }
	GRID_DEBUG("%s (%d) : Crawler applied to the system D-Bus %s interface", service_name, service_pid, signal_ack_interface_name);

	g_free(match_pattern);
	/* ------- */

	while ( FALSE == stop_thread ) {
		dbus_connection_read_write(conn, 0);
		msg = dbus_connection_pop_message(conn);

		if (NULL == msg)
			continue;

		if (dbus_message_is_signal(msg, signal_control_interface_name, CTRL_STOP)) { /* CTRL_STOP control signal */
			/* Signal arguments */
			if (!dbus_message_iter_init(msg, &iter)) {
				dbus_message_unref(msg);

				continue;
			}
			else {
				if (DBUS_TYPE_INT32 != dbus_message_iter_get_arg_type(&iter)) {
					dbus_message_unref(msg);

					continue;
				}
				else {
					dbus_message_iter_get_basic(&iter, &pid_param);

					if (pid_param != service_pid) { /* Not this crawler PID */
						dbus_message_unref(msg);

						continue;
					}

					control_status = CTRL_STOP;

					GRID_DEBUG("%s (%d) : Signal %s received on the system D-Bus control interface %s", service_name, service_pid, CTRL_STOP, signal_control_interface_name);
				}
			}
			/* ------- */
		}
		else if (dbus_message_is_signal(msg, signal_control_interface_name, CTRL_PROGRESS)) { /* CTRL_PROGRESS control signal */
			/* Signal arguments */
                        if (!dbus_message_iter_init(msg, &iter)) {
				dbus_message_unref(msg);

                                continue;
			}
                        else {
                                if (DBUS_TYPE_INT32 != dbus_message_iter_get_arg_type(&iter)) {
					dbus_message_unref(msg);

                                        continue;
				}
                                else {
                                        dbus_message_iter_get_basic(&iter, &pid_param);

                                        if (pid_param != service_pid) { /* Not this crawler PID */
						dbus_message_unref(msg);

                                                continue;
					}

					if (!dbus_message_iter_next(&iter)) {
						dbus_message_unref(msg);

						continue;
					}
					else {
						if (DBUS_TYPE_INT32 != dbus_message_iter_get_arg_type(&iter)) {
							dbus_message_unref(msg);

                                        		continue;
						}
						else {
							int caller_pid = -1;
							dbus_message_iter_get_basic(&iter, &caller_pid);

                                        		GRID_DEBUG("%s (%d) : Signal %s received on the system D-Bus control interface %s", service_name, service_pid, CTRL_PROGRESS, signal_control_interface_name);

							if (EXIT_FAILURE == send_signal_int32_int32_string(conn, signal_object_name, signal_control_interface_name, CTRL_PROGRESS_RET, caller_pid, (int)(trip_ep->trip_progress)(), control_status))
                                                		GRID_ERROR("%s (%d) : System D-Bus signal sending failed in crawler %s %s", service_name, service_pid, error.name, error.message);
                                        		else
                                                		GRID_DEBUG("%s (%d) : Signal %s sent on the system D-Bus interface %s", service_name, service_pid, CTRL_PROGRESS_RET, signal_control_interface_name);
						}
					}
                                }
                        }
                        /* ------- */
		}
		else if (dbus_message_is_signal(msg, signal_control_interface_name, CTRL_SLOW)) { /* CTRL_SLOW control signal */
			/* Signal arguments */
                        if (!dbus_message_iter_init(msg, &iter)) {
				dbus_message_unref(msg);

                                continue;
			}
                        else {
                                if (DBUS_TYPE_INT32 != dbus_message_iter_get_arg_type(&iter)) {
					dbus_message_unref(msg);

                                        continue;
				}
                                else {
                                        dbus_message_iter_get_basic(&iter, &pid_param);

                                        if (pid_param != service_pid) { /* Not this crawler PID */
						dbus_message_unref(msg);

                                                continue;
					}

                                        control_status = CTRL_SLOW;

                                	GRID_DEBUG("%s (%d) : Signal %s received on the system D-Bus control interface %s", service_name, service_pid, CTRL_SLOW, signal_control_interface_name);
                                }
                        }
                        /* ------- */
		}
                else if (dbus_message_is_signal(msg, signal_control_interface_name, CTRL_PAUSE)) { /* CTRL_PAUSE control signal */
                        /* Signal arguments */
                        if (!dbus_message_iter_init(msg, &iter)) {
				dbus_message_unref(msg);

                                continue;
			}
                        else {
                                if (DBUS_TYPE_INT32 != dbus_message_iter_get_arg_type(&iter)) {
					dbus_message_unref(msg);

                                        continue;
				}
                                else {
                                        dbus_message_iter_get_basic(&iter, &pid_param);

                                        if (pid_param != service_pid) { /* Not this crawler PID */
						dbus_message_unref(msg);

                                                continue;
					}

                                        control_status = CTRL_PAUSE;

                                	GRID_DEBUG("%s (%d) : Signal %s received on the system D-Bus control interface %s", service_name, service_pid, CTRL_PAUSE, signal_control_interface_name);
                                }
                        }
                        /* ------- */
                }
                else if (dbus_message_is_signal(msg, signal_control_interface_name, CTRL_RESUME)) { /* CTRL_RESUME control signal */
                        /* Signal arguments */
                        if (!dbus_message_iter_init(msg, &iter)) {
				dbus_message_unref(msg);

                                continue;
			}
                        else {
                                if (DBUS_TYPE_INT32 != dbus_message_iter_get_arg_type(&iter)) {
					dbus_message_unref(msg);

                                        continue;
				}
                                else {
                                        dbus_message_iter_get_basic(&iter, &pid_param);

                                        if (pid_param != service_pid) { /* Not this crawler PID */
						dbus_message_unref(msg);

                                                continue;
					}

                                        control_status = CTRL_BYPASS;

                                	GRID_DEBUG("%s (%d) : Signal %s received on the system D-Bus control interface %s", service_name, service_pid, CTRL_RESUME, signal_control_interface_name);
                                }
                        }
                        /* ------- */
                }
		else if (dbus_message_is_signal(msg, signal_ack_interface_name, ACK_OK)) { /* ACK_OK control signal */
			/* Signal arguments */
                        if (!dbus_message_iter_init(msg, &iter)) {
				dbus_message_unref(msg);

				continue;
			}
                        else {
                                if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&iter)) {
					dbus_message_unref(msg);

                                        continue;
				}
                                else {
					GRID_DEBUG("%s (%d) : Signal %s received on the system D-Bus acknowledgement interface %s", service_name, service_pid, ACK_OK, signal_ack_interface_name);

					dbus_message_iter_get_basic(&iter, &ack_params_print);
					GVariantType* ack_param_type = g_variant_type_new(gvariant_ack_param_type_string);
					ack_params = g_variant_parse(ack_param_type, ack_params_print, NULL, NULL, NULL);
					g_variant_type_free(ack_param_type);

					if (NULL != ack_params) {
						GVariant* temp_context_id = g_variant_get_child_value(ack_params, 0);
						context_id = g_variant_get_uint64(temp_context_id);
						action_ctx_update(context_id, ACK_OK, ack_params);
						g_variant_unref(temp_context_id);
						g_variant_unref(ack_params);
					}
                                }
                        }
                        /* ------- */
                }
		else if (dbus_message_is_signal(msg, signal_ack_interface_name, ACK_KO)) { /* ACK_KO control signal */
			/* Signal arguments */
                        if (!dbus_message_iter_init(msg, &iter)) {
				dbus_message_unref(msg);

                                continue;
			}
                        else {
                                if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&iter)) {
					dbus_message_unref(msg);

                                        continue;
				}
                                else {
					GRID_DEBUG("%s (%d) : Signal %s received on the system D-Bus acknowledgement interface %s", service_name, service_pid, ACK_KO, signal_ack_interface_name);

					dbus_message_iter_get_basic(&iter, &ack_params_print);
                                        GVariantType* ack_param_type = g_variant_type_new(gvariant_ack_param_type_string);
                                        ack_params = g_variant_parse(ack_param_type, ack_params_print, NULL, NULL, NULL);
                                        g_variant_type_free(ack_param_type);

                                        if (NULL != ack_params) {
						GVariant* temp_context_id = g_variant_get_child_value(ack_params, 0);
                                                context_id = g_variant_get_uint64(temp_context_id);
                                                action_ctx_update(context_id, ACK_KO, ack_params);
                                                g_variant_unref(temp_context_id);
                                                g_variant_unref(ack_params);
					}
                                }
                        }
                        /* ------- */
                }

		dbus_message_unref(msg);
	}

	return NULL;
}

/* GRID COMMON MAIN */
static struct grid_main_option_s *
main_get_options(void) {
        static struct grid_main_option_s options[] = {
                { "trip", OT_STRING, {.str = &console_trip_name},
                        "The name of the trip" },
                { "action", OT_STRING,  {.str = &console_action_names},
                        "The names of the actions" },
		{ "infinite", OT_BOOL, {.b = &console_infinite},
			"In order to make the crawler looping on and on" },
		{ "triplibpath", OT_STRING, {.str = &console_triplibpath},
                        "In order to explicitely specify where to find the trip libraries" }
        };

        return options;
}

static void
main_action(void) {
	DBusError error;
	int ret;
	GVariant* occur = NULL;
	GVariant* signal_parameters = NULL;
	struct action_context* temp_action_ctx = NULL;
	DBusConnection* conn = NULL; /* The connection pointer to the system D-Bus */
	time_t temp_time_stamp;

	dbus_error_init(&error);

	GRID_INFO("%s (%d) : Crawler started", service_name, service_pid);

	if (EXIT_FAILURE == (ret = init_dbus_connection(&conn))) { /* Opening the system D-Bus connection */
		GRID_ERROR("%s (%d) : System D-Bus connection failed %s %s", service_name, service_pid, error.name, error.message);

                return;
        }

	/* Running the control and acknowledgement listener */
	ret = pthread_create(&control_ack_thread, NULL, listening_control_ack, NULL);
 	if (EAGAIN == ret || EINVAL == ret || EPERM == ret)
		GRID_INFO("%s (%d) : System D-Bus control and acknowledgement thread failed to start...", service_name, service_pid);
        else
		GRID_INFO("%s (%d) : System D-Bus control and acknowledgement thread started...", service_name, service_pid);
	/* ------- */

	/* Running the action timeout check */
	ret = pthread_create(&action_timeout_thread, NULL, action_timeout_check, NULL);
        if (EAGAIN == ret || EINVAL == ret || EPERM == ret)
		GRID_INFO("%s (%d) : Action timeout check thread failed to start...", service_name, service_pid);
        else
		GRID_INFO("%s (%d) : Action timeout check thread started...", service_name, service_pid);
	/* ------- */

	sleep(1);

infinite_loop:
	/* And the trip goes on... */
	occur = (GVariant*)(trip_ep->trip_next)();
	while (NULL != occur) {
		while (!g_strcmp0(CTRL_PAUSE, control_status))
			sleep(1);

		if (!g_strcmp0(CTRL_STOP, control_status))
			break;
		else if (!g_strcmp0(CTRL_SLOW, control_status))
			sleep(SLOW_VALUE);

                /* Action context creation and storage */
                temp_action_ctx = new_action_context();
		if (NULL == temp_action_ctx) {
                	if (NULL != conn)
				dbus_connection_unref(conn);

			if (NULL != occur)
				g_variant_unref(occur);

			return;
		}
                /* ------- */

		/* Sending message */
		signal_parameters = assemble_context_occur_argc_argv_uid(temp_action_ctx->id, occur, my_argc, my_argv, service_uid);

                if (NULL == signal_parameters) {
			if (NULL != conn)
				dbus_connection_unref(conn);

			if (NULL != occur)
                        	g_variant_unref(occur);

			if (NULL != temp_action_ctx)
				free(temp_action_ctx);

			return;
		}

		time(&temp_time_stamp);
		temp_action_ctx->time_stamp = temp_time_stamp;
		temp_action_ctx->occur = occur;

		g_hash_table_insert(action_ctx_table, &(temp_action_ctx->id), temp_action_ctx);
		GRID_DEBUG("%s (%d) : Context %llu added to the context table", service_name, service_pid, (unsigned long long)temp_action_ctx->id);

                if (EXIT_FAILURE == send_signal(conn, signal_object_name, signal_action_interface_name, action_list[0], signal_parameters))
                        GRID_ERROR("%s (%d) : System D-Bus signal sending failed in crawler %s %s", service_name, service_pid, error.name, error.message);
		else
			GRID_DEBUG("%s (%d) : Signal %s sent on the system D-Bus interface %s for the context %llu", service_name, service_pid, action_list[0], signal_action_interface_name, (unsigned long long)temp_action_ctx->id);
		/* ------- */

                occur = (GVariant*)(trip_ep->trip_next)();
	}
	/* ------- */

	while(FALSE == end_test())
		sleep(1);

	/* Sending NULL occurences message */
	signal_parameters = assemble_context_occur_argc_argv_uid(0, g_variant_new_string(end_signal_tile), my_argc, my_argv, service_uid);

	if (NULL == signal_parameters) {
		if (NULL != conn)
			dbus_connection_unref(conn);

		return;
	}

	guint i;
	for (i = 0; i < action_list_length; i++) {
		if (EXIT_FAILURE == send_signal(conn, signal_object_name, signal_action_interface_name, action_list[i], signal_parameters))
                	GRID_ERROR("%s (%d) : System D-Bus final signal sending failed in crawler %s %s", service_name, service_pid, error.name, error.message);
		else
			GRID_DEBUG("%s (%d) : Final signal %s sent on the system D-Bus interface %s", service_name, service_pid, action_list[i], signal_action_interface_name);
	}
	/* ------- */

	/* Infinite loop management */
	if (g_strcmp0(CTRL_STOP, control_status) && TRUE == console_infinite) {
		main_specific_fini();
		action_ctx_table = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, (GDestroyNotify)g_free);
		main_configure(my_argc, my_argv);

		goto infinite_loop;
	}
	else {
		if (NULL != conn)
                	dbus_connection_unref(conn);
	}
	/* ------- */

	return;
}

static const gchar*
main_usage(void) {
	return "-Otrip=<trip_name> -Oaction=<action_name><:...:...> [-Oinfinite=<true|false>] [-Otriplib=<specific_trip_library_dir_path>] -- -trip_name.param_name=<value> -action_name.param_name=<value> [...]\n";
}

static void
main_specific_stop(void) {
        stop_thread = TRUE;

	g_string_free(console_trip_name, TRUE);
	g_string_free(console_action_names, TRUE);
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
	if (!g_module_supported()) {
		g_error("GLib MODULES are not supported on this platform!");
		return 1;
	}
	return grid_main(argc, argv, &cb);
}
/* ------- */
