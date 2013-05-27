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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <glib.h>
#include <gmodule.h>

#include "crawler_constants.h"
#include "crawler_common_tools.h"

#include "../metautils/lib/loggers.h"

static const char* service_name = "crawler_common_tools";

struct action_context*
new_action_context(void) {
	struct action_context* new_action_ctx = (struct action_context*)g_malloc0(sizeof(struct action_context));

	if (NULL == new_action_ctx)
		return NULL;

	new_action_ctx->id = g_get_monotonic_time();
	new_action_ctx->pos = 0;

	if (NULL != new_action_ctx->occur)
		g_variant_unref(new_action_ctx->occur);

	return new_action_ctx;
}

void
free_trip_lib_entry_points(struct trip_lib_entry_points* trip_ep) {
        if (NULL != trip_ep) {
                if (NULL != trip_ep->lib_ref)
                        g_module_close(trip_ep->lib_ref);
                g_free(trip_ep);
        }
}

gchar*
g_substr(const gchar* string, guint32 start_pos, guint32 end_pos) {
	gsize len;
	gchar* output = NULL;

	if (start_pos >= strlen(string))
		return NULL;

	if (end_pos > strlen(string))
		len = strlen(string) - start_pos;
	else
		len = end_pos - start_pos;

	output = g_malloc0(len + 1);
	if (NULL == output)
		return NULL;

	return g_utf8_strncpy(output, &string[start_pos], len);
}

int
init_dbus_connection(DBusConnection** conn) {
	if (!*conn) { /* Nothing is done if the connection is active */
		*conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
		if (!*conn)
			return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

/* Returned argv value must be freed with g_free() */
int
disassemble_context_occur_argc_argv_uid(GVariant* gv_glued, guint64* context_id, GVariant** gv_src, int* argc, char*** argv, guint64* service_uid) {
	GVariantType* gvt = g_variant_type_new(gvariant_action_param_type_string);
	if (NULL == gv_glued || FALSE == g_variant_is_of_type(gv_glued, gvt)) {
		g_variant_type_free(gvt);

		return EXIT_FAILURE;
	}
	g_variant_type_free(gvt);

	*context_id = g_variant_get_uint64(g_variant_get_child_value(gv_glued, 0));
	*gv_src = g_variant_get_variant(g_variant_get_child_value(gv_glued, 1));
	*argc = g_variant_get_int32(g_variant_get_child_value(gv_glued, 2));
	*argv = (char**)g_variant_get_strv(g_variant_get_child_value(gv_glued, 3), NULL);
	*service_uid = g_variant_get_uint64(g_variant_get_child_value(gv_glued, 4));

	return EXIT_SUCCESS;
}

GVariant*
assemble_context_occur_argc_argv_uid(guint64 context_id, GVariant* gv, int argc, char** argv, guint64 service_uid) {
	GVariantBuilder* argv_builder = NULL;
	GVariant* ret = NULL;
	int i;

	if (NULL == gv || NULL == argv)
		return NULL;

	argv_builder = g_variant_builder_new(G_VARIANT_TYPE("as"));
	for (i = 0; (argv[i]); i++)
		g_variant_builder_add(argv_builder, "s", argv[i]);

	ret = g_variant_new(gvariant_action_param_type_string, context_id, gv, argc, argv_builder, service_uid);

	g_variant_builder_unref(argv_builder);

	return ret;
}

int
send_signal(DBusConnection* conn, const gchar* dbus_object, const gchar* dbus_interface, const gchar* dbus_signal, GVariant* params) {
	DBusError error;
	DBusMessage* msg;
        DBusMessageIter iter;
	int service_pid;
	gchar* gv_print;

	if (NULL == conn || NULL == dbus_object || NULL == dbus_interface || NULL == dbus_signal || NULL == params)
		return EXIT_FAILURE;

	dbus_error_init(&error);
	service_pid = getpid();

        msg = dbus_message_new_signal(dbus_object, dbus_interface, dbus_signal);
        if (NULL == msg) {
                GRID_ERROR("%s (%d) : System D-Bus signal creation failed %s %s", service_name, service_pid, error.name, error.message);

                return EXIT_FAILURE;
        }

	gv_print = g_variant_print(params, FALSE);

	dbus_message_iter_init_append(msg, &iter);
	if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &gv_print)) {
		GRID_ERROR("%s (%d) : System D-Bus signal appending failed %s %s", service_name, service_pid, error.name, error.message);
		dbus_message_unref(msg);
		g_free(gv_print);

		return EXIT_FAILURE;
	}

	if (!dbus_connection_send(conn, msg, NULL)) {
		GRID_ERROR("%s (%d) : Failed to send signal on the system D-Bus %s %s", service_name, service_pid, error.name, error.message);
        	dbus_message_unref(msg);
		g_free(gv_print);

        	return EXIT_FAILURE;
        }

        dbus_connection_flush(conn);
        dbus_message_unref(msg);
	g_free(gv_print);

	return EXIT_SUCCESS;
}

int
send_signal_int32_int32(DBusConnection* conn, const gchar* dbus_object, const gchar* dbus_interface, const gchar* dbus_signal, gint32 iparam1, gint32 iparam2) {
        DBusError error;
        DBusMessage* msg;
        DBusMessageIter iter;
	int service_pid;

        if (NULL == conn || NULL == dbus_object || NULL == dbus_interface || NULL == dbus_signal)
                return EXIT_FAILURE;

        dbus_error_init(&error);
	service_pid = getpid();

        msg = dbus_message_new_signal(dbus_object, dbus_interface, dbus_signal);
        if (NULL == msg) {
                GRID_ERROR("%s (%d) : System D-Bus signal creation failed %s %s", service_name, service_pid, error.name, error.message);

                return EXIT_FAILURE;
        }

	dbus_message_iter_init_append(msg, &iter);
        if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &iparam1)) {
                GRID_ERROR("%s (%d) : System D-Bus signal appending failed %s %s", service_name, service_pid, error.name, error.message);
                dbus_message_unref(msg);

                return EXIT_FAILURE;
        }

        dbus_message_iter_init_append(msg, &iter);
        if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &iparam2)) {
                GRID_ERROR("%s (%d) : System D-Bus signal appending failed %s %s", service_name, service_pid, error.name, error.message);
                dbus_message_unref(msg);

                return EXIT_FAILURE;
        }

        if (!dbus_connection_send(conn, msg, NULL)) {
                GRID_ERROR("%s (%d) : Failed to send signal on the system D-Bus %s %s", service_name, service_pid, error.name, error.message);
                dbus_message_unref(msg);

                return EXIT_FAILURE;
        }

        dbus_connection_flush(conn);
        dbus_message_unref(msg);

        return EXIT_SUCCESS;
}

int
send_signal_int32_int32_string(DBusConnection* conn, const gchar* dbus_object, const gchar* dbus_interface, const gchar* dbus_signal, gint32 iparam1, gint32 iparam2, const char* sparam) {
        DBusError error;
        DBusMessage* msg;
        DBusMessageIter iter;
        int service_pid;

        if (NULL == conn || NULL == dbus_object || NULL == dbus_interface || NULL == dbus_signal)
                return EXIT_FAILURE;

        dbus_error_init(&error);
        service_pid = getpid();

        msg = dbus_message_new_signal(dbus_object, dbus_interface, dbus_signal);
        if (NULL == msg) {
                GRID_ERROR("%s (%d) : System D-Bus signal creation failed %s %s", service_name, service_pid, error.name, error.message);

                return EXIT_FAILURE;
        }

        dbus_message_iter_init_append(msg, &iter);
        if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &iparam1)) {
                GRID_ERROR("%s (%d) : System D-Bus signal appending failed %s %s", service_name, service_pid, error.name, error.message);
                dbus_message_unref(msg);

                return EXIT_FAILURE;
        }

        dbus_message_iter_init_append(msg, &iter);
        if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &iparam2)) {
                GRID_ERROR("%s (%d) : System D-Bus signal appending failed %s %s", service_name, service_pid, error.name, error.message);
                dbus_message_unref(msg);

                return EXIT_FAILURE;
        }

        dbus_message_iter_init_append(msg, &iter);
        if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &sparam)) {
                GRID_ERROR("%s (%d) : System D-Bus signal appending failed %s %s", service_name, service_pid, error.name, error.message);
                dbus_message_unref(msg);

                return EXIT_FAILURE;
        }

        if (!dbus_connection_send(conn, msg, NULL)) {
                GRID_ERROR("%s (%d) : Failed to send signal on the system D-Bus %s %s", service_name, service_pid, error.name, error.message);
                dbus_message_unref(msg);

                return EXIT_FAILURE;
        }

        dbus_connection_flush(conn);
        dbus_message_unref(msg);

        return EXIT_SUCCESS;
}

gchar*
get_argv_value(int argc, char** argv, gchar* module_name, gchar* variable_name) {
	int i;
        gchar* temp = NULL;
	gchar* temp2 = NULL;
        gchar* ret = NULL;

        for (i = 0;(NULL == ret) && (i < argc); i++) {
		temp = g_strconcat(opt_indicator, module_name, opt_separator, variable_name, opt_affectation, NULL);
		
		/* Testing the minimal length of the option */
		if (strlen(temp) + 1 > strlen(argv[i])) {
			g_free(temp);
			
			continue;
		}
		/* ------- */

		temp2 = g_substr(argv[i], 0, strlen(temp));
		if (!g_strcmp0(temp, temp2))
			ret = g_substr(argv[i], strlen(temp), strlen(argv[i]));
		else {
			g_free(temp2);
			g_free(temp);

			continue;
		}

		g_free(temp2);
		g_free(temp);
	}

	return ret;
}

gboolean
chunk_path_is_valid(const gchar* file_path) {
        guint count = 0;
        const gchar *s;
        register gchar c;
	gchar* basename = g_path_get_basename(file_path);

        for (s=basename; (c = *s) ;s++) {
                if (FALSE == g_ascii_isxdigit(c)) {
			g_free(basename);

                        return FALSE;
		}
                
		if (++count > 64) {
			g_free(basename);

			return FALSE;
		}
        }

	g_free(basename);

        return count == 64U;
}

gboolean
container_path_is_valid(const gchar* file_path) {
        if (FALSE == chunk_path_is_valid(file_path))
                return FALSE;

        FILE* file_pointer = NULL;
        int str_cmp = -1;
        gchar my_header[16] = "";

        file_pointer = fopen(file_path, "r");
        if (NULL != file_pointer) {
                if (NULL != fgets(my_header, 16, file_pointer))
                        str_cmp = g_strcmp0(my_header, "SQLite format 3");

                fclose (file_pointer);
        }

        return (!str_cmp);
}

int
move_file(const char* source_file_path, const char* destination_file_path, gboolean delete_after) {
	FILE* source_file_pointer;
	FILE* destination_file_pointer;
	char buffer[SHORT_BUFFER_SIZE];
	int read_bytes_number;

	if (NULL == (source_file_pointer = fopen(source_file_path, "rb")))
		return EXIT_FAILURE;

	if (NULL == (destination_file_pointer = fopen(destination_file_path, "wb"))) {
		fclose(source_file_pointer);

		return EXIT_FAILURE;
	}

	while ((read_bytes_number = fread(buffer, 1, SHORT_BUFFER_SIZE, source_file_pointer)))
		fwrite(buffer, 1, read_bytes_number, destination_file_pointer);

	fclose(destination_file_pointer);
	fclose(source_file_pointer);

	if (TRUE == delete_after)
		remove(source_file_path);

	return EXIT_SUCCESS;
}
