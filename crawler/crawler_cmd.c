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
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <errno.h>

#include "crawler_constants.h"
#include "crawler_common_tools.h"

#include "../metautils/lib/common_main.h"
#include "../metautils/lib/loggers.h"

#define MAX_PIPE_LENGTH 512

static pthread_t progress_thread; /* The thread listening to the system D-Bus for returned progress signals */
static gboolean stop_thread; /* Flag to stop the listening threads */
static gboolean pending_progress;
static time_t pending_progress_ts;

static gchar* service_name;
static gint32 service_pid;

static GString* console_pid;
static GString* console_command;
static GString* console_option;

static void*
listening_progress_ret() {
	DBusError error;
	DBusConnection* conn = NULL;

	dbus_error_init(&error);

	if (EXIT_FAILURE == init_dbus_connection(&conn)) {
                GRID_ERROR("%s (%d) : System D-Bus connection failed in crawler %s %s", service_name, service_pid, error.name, error.message);

                return NULL;
        }

	/* Applying to the control interface */
        gchar* match_pattern = g_strconcat("type='signal',interface='", signal_control_interface_name, "'", NULL);
        dbus_bus_add_match(conn, match_pattern, &error);
        dbus_connection_flush(conn);
        if (dbus_error_is_set(&error)) {
                GRID_ERROR("%s (%d) : Subscription to the system D-Bus failed in crawler %s %s", service_name, service_pid, error.name, error.message);

                g_free(match_pattern);

                return NULL;
        }
        g_free(match_pattern);
        /* ------- */

	DBusMessage* msg;
        DBusMessageIter iter;
	while (FALSE == stop_thread) {
		dbus_connection_read_write(conn, 0);
                msg = dbus_connection_pop_message(conn);

                if (NULL == msg)
                        continue;

		if (dbus_message_is_signal(msg, signal_control_interface_name, CTRL_PROGRESS_RET)) {
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
					gint32 pid_param = -1;
                                        dbus_message_iter_get_basic(&iter, &pid_param);

                                        if (pid_param != service_pid) {
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
							int percentage;
                                                        dbus_message_iter_get_basic(&iter, &percentage);
							
							if (!dbus_message_iter_next(&iter)) {
								dbus_message_unref(msg);

                                                		continue;
							}
							else {
								if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&iter)) {
									dbus_message_unref(msg);

                                         		        	continue;
								}
                                                		else {
									gchar* status;
									dbus_message_iter_get_basic(&iter, &status);

									g_printerr("%d%% achieved\nstatus = %s\n", percentage, status);
								}
							}
						}
					}

					pending_progress = FALSE;
                                }
                        }
                        /* ------- */
                }

		dbus_message_unref(msg);
	}

	return NULL;
}

static GSList*
get_crawler_pid_list() {
	GSList* result = NULL;
	FILE* fp = popen("ps afx | grep crawler", "r");
	
	if (NULL == fp)
		return NULL;

	gchar buff[MAX_PIPE_LENGTH];
	while (NULL != fgets(buff, MAX_PIPE_LENGTH, fp)) {
		gchar** tokens = NULL;
		/* Checking with the '--' */
		/*
		if (NULL == (tokens = g_strsplit(buff, "--", -1)))
			continue;
		if (2 != g_strv_length(tokens)) {
			g_strfreev(tokens);
			continue;
		}
		g_strfreev(tokens);
		*/
		/* ------- */
		/* Checking with the '-Otrip' */
		if (NULL == (tokens = g_strsplit(buff, "-Otrip=", -1)))
                        continue;
                if (2 != g_strv_length(tokens)) {
			g_strfreev(tokens);
                        continue;
		}
                g_strfreev(tokens);
		/* ------- */
		/* PID extraction */
		if (NULL == (tokens = g_strsplit(buff, " ", -1)))
                        continue;

		guint i = 0;
		while (i < g_strv_length(tokens) && NULL != tokens[i] && !g_strcmp0("", tokens[i]))
			i++;
		if (i == g_strv_length(tokens) || NULL == tokens[i]) {
			g_strfreev(tokens);
                        continue;
		}
		gchar* temp_buff = g_strdup(tokens[i]);
		/* ------- */
		
		result = g_slist_prepend(result, temp_buff);
		g_strfreev(tokens);
	}
 
 	pclose(fp);

	return result;
}

static const gchar*
main_usage(void) {
        return "./crawler_cmd [-Opid=<crawler_pid_value> -Ocommand=<command>|-Ooption=<help|list>]";
}

static void
main_action(void) {
	DBusError error;
	int ret;

	dbus_error_init(&error);

	if (NULL != console_option) {
		gchar* option = g_string_free(console_option, FALSE);

		if (!g_strcmp0("help", option)) {
			g_print("Available commands list :\n");
			g_print("------------------------\n");

			g_print("\tstop\t\t:\tStops the crawler\n");
			g_print("\tpause\t\t:\tPauses the crawler\n");
			g_print("\tslow\t\t:\tSlows the crawler\n");
			g_print("\tresume\t\t:\tResume a previously paused or slowed crawler\n");
			g_print("\tprogress\t:\tShows the progress percentage and the status of the crawler\n");
		}
		else if (!g_strcmp0("list", option)) {
			g_print("PIDs of the currently running crawlers :\n");
			g_print("----------------------------------------\n");

			GSList* result = get_crawler_pid_list();
			while (NULL != result) {
				gchar* current_pid = g_slist_last(result)->data;

				g_print("\t%s\n", current_pid);

				g_free(g_slist_last(result)->data);
				result = g_slist_remove(result, g_slist_last(result)->data);
			}
		}
		else
			GRID_INFO("%s (%d) : Unknown option '%s'\n", service_name, service_pid, option);

		g_free(option);
		console_option = NULL;
	}
	else {
		if (NULL != console_command) {
			gchar* pid = g_string_free(console_pid, FALSE);
			gchar* command = g_string_free(console_command, FALSE);
			gchar* ctrl_command = NULL;

			if (!g_strcmp0("stop", command))
				ctrl_command = CTRL_STOP;
			else if (!g_strcmp0("pause", command))
				ctrl_command = CTRL_PAUSE;
			else if (!g_strcmp0("slow", command))
                                ctrl_command = CTRL_SLOW;
			else if (!g_strcmp0("resume", command))
                                ctrl_command = CTRL_RESUME;
			else if (!g_strcmp0("progress", command))
				ctrl_command = CTRL_PROGRESS;
			else {
				GRID_INFO("%s (%d) : Unknown command '%s'\n", service_name, service_pid, command);

				g_free(pid);
                        	g_free(command);
                        	console_pid = NULL;
                        	console_command = NULL;

				return;
			}

			ret = pthread_create(&progress_thread, NULL, listening_progress_ret, NULL);
        		if (EAGAIN == ret || EINVAL == ret || EPERM == ret)
                		GRID_ERROR("%s (%d) : System D-Bus returned progress thread failed to start...", service_name, service_pid);

        		sleep(1);

			DBusConnection* conn = NULL;
			if (EXIT_FAILURE == init_dbus_connection(&conn))
                		GRID_ERROR("%s (%d) : System D-Bus connection failed %s %s", service_name, service_pid, error.name, error.message);
			else {
				if (!g_strcmp0(CTRL_PROGRESS, ctrl_command)) {
                                	time(&pending_progress_ts);
                                	pending_progress = TRUE;
                                }
				if (EXIT_FAILURE == send_signal_int32_int32(conn, signal_object_name, signal_control_interface_name, ctrl_command, (gint32)g_ascii_strtoll(pid, NULL, 10), service_pid)) {
					pending_progress = FALSE;

					GRID_ERROR("%s (%d) : System D-Bus signal sending failed %s %s", service_name, service_pid, error.name, error.message);
				}

				if (NULL != conn)
					dbus_connection_unref(conn);
			}

			while(TRUE == pending_progress) {
				time_t current_time_stamp;
				time(&current_time_stamp);

				if (MAX_ACTION_TIMEOUT  < difftime(current_time_stamp, pending_progress_ts)) {
					g_print("Getting informations from this crawler takes too much time...\n");

					break;
				}
			}

			g_free(pid);
			g_free(command);
			console_pid = NULL;
			console_command = NULL;
		}
	}
}

static gboolean
main_configure(int argc, char **args) {
	if ((NULL != console_pid && NULL != console_option) || (NULL == console_pid && NULL == console_option))
		return FALSE;

	argc = argc;
	args = args;

	return TRUE;
}

static struct grid_main_option_s *
main_get_options(void) {
        static struct grid_main_option_s options[] = {
                { "pid", OT_STRING, {.str = &console_pid},
			"The PID value of the crawler" },
		{ "command", OT_STRING, {.str = &console_command},
                        "The command to send to the crawler" },
		{ "option", OT_STRING, {.str = &console_option},
			"The specified option"}
        };

        return options;
}

static void
main_set_defaults(void) {
	stop_thread = FALSE;
	pending_progress = FALSE;
	service_name = "crawler_cmd";
	service_pid = getpid();	
	console_pid = NULL;
	console_command = NULL;
	console_option = NULL;
}

static void
main_specific_fini(void) {
	if (NULL != console_pid)
		g_string_free(console_pid, TRUE);

	if (NULL != console_command)
                g_string_free(console_command, TRUE);

	if (NULL != console_option)
		g_string_free(console_option, TRUE);
}

static void
main_specific_stop(void) {
	stop_thread = TRUE;
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
