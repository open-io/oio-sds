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

#ifndef CRAWLER_COMMON_TOOLS_H
#define CRAWLER_COMMON_TOOLS_H

#include <glib.h>
#include <gmodule.h>

#include <dbus/dbus.h>
#include <time.h>

typedef int func1(int, char**);
typedef GVariant* func2();
typedef void func3();
typedef int func4();

struct trip_lib_entry_points {
	GModule* lib_ref;
	func1* trip_start;
	func2* trip_next;
	func3* trip_end;
	func4* trip_progress;
};

struct action_context {
	guint64 id; /* Unique context ID (local) */
	guint pos; /* Index of currently running action for this context (starts with 0) */
	GVariant* occur; /* Context related occurence */
	time_t time_stamp; /* Beginning of the current signal send */
};

/*
 * This function initializes a new action context
 **/
struct action_context*
new_action_context(void);

/*
 * This method frees a given trip entry points structure
 **/
void
free_trip_lib_entry_points(struct trip_lib_entry_points*);

/*
 * This function returns a substring of a string (must free the returned value). Returns NULL on bad starting position, and returns the end of the string from the given starting position value if the length value is too large
 **/
gchar*
g_substr(const gchar*, guint32, guint32);

/*
 * This function initializes a new connection to the system D-Bus
 **/
int
init_dbus_connection(DBusConnection**);

/*
 * This function is separating a GVariant and the command line optionss from a GVariant
 **/
int
disassemble_context_occur_argc_argv_uid(GVariant*, guint64*, GVariant**, int*, char***, guint64*);

/*
 * This function is gluing a GVariant and the command line options in a new GVariant
 **/
GVariant*
assemble_context_occur_argc_argv_uid(guint64, GVariant*, int, char**, guint64);

/*
 * This function sends a signal to a particular interface on the bus, with parameters contained in a GVariant
 **/
int
send_signal(DBusConnection*, const gchar*, const gchar*, const gchar*, GVariant*);

/*
 * This function sends a signal to a particular interface on the bus, with two int32 parameter
 **/
int
send_signal_int32_int32(DBusConnection*, const gchar*, const gchar*, const gchar*, gint32, gint32);

/*
 * This function sends a signal to a particular interface on the bus, with two int32 parameter and a string
 **/
int
send_signal_int32_int32_string(DBusConnection*, const gchar*, const gchar*, const gchar*, gint32, gint32, const char*);

/*
 * This function gets the specific value of argv
 **/
gchar*
get_argv_value(int, char**, gchar*, gchar*);

/*
 * This function tests if a chunk path is valid or not
 **/
gboolean
chunk_path_is_valid(const gchar*);

/*
 * This function tests if a container path is valid or not
 **/
gboolean
container_path_is_valid(const gchar*);

/*
 * This function moves a file on the disk, and eventualy deletes it in the end
 **/
int
move_file(const char*, const char*, gboolean);

#endif
