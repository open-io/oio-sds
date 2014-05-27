#ifndef CRAWLER_TOOLS_H
#define CRAWLER_TOOLS_H

#include <glib.h>
#include <gmodule.h>

#include <dbus/dbus.h>
#include <time.h>


/**
 * build the name of service on dbus bus
 */
void buildServiceName(char* svc_name, int max_size_svc_name,
		char* prefix_name, char* action_name, int pid, gboolean bPrefixOnly);

/**
 * search and determine, and return the adresse bud-daemon to used dbus bus
 */
char* getBusAddress(char* userdata);


/**
 * This function returns a substring of a string (must free the returned value).
 * Returns NULL on bad starting position, and returns the end of the string
 * from the given starting position value if the length value is too large
 */
gchar* g_substr(const gchar*, guint32, guint32);

/**
 * This function initializes a new connection to the system D-Bus
 */
int init_dbus_connection(DBusConnection**);

/**
 * Separate a GVariant and the command line options from a GVariant.
 */
int disassemble_context_occur_argc_argv_uid(GVariant*, guint64*, GVariant**, int*, char***, guint64*);

/**
 * Glue a GVariant and the command line options in a new GVariant.
 */
GVariant* assemble_context_occur_argc_argv_uid(GVariant** b, guint64, GVariant*, int, char**, guint64);


/*
 * This function gets the specific value of argv
 **/
gchar* get_argv_value(int, char**, gchar*, gchar*);

/*
 * This function tests if a chunk path is valid or not
 **/
gboolean chunk_path_is_valid(const gchar*);

/*
 * This function tests if a container path is valid or not
 **/
gboolean container_path_is_valid(const gchar*);

/*
 * This function moves a file on the disk, and eventualy deletes it in the end
 **/
int move_file(const char*, const char*, gboolean);


guint64   get_child_value_uint64(GVariant* gv, int order);
GVariant* get_child_value_variant(GVariant* gv, int order);
int       get_child_value_int(GVariant* gv, int order);
const     gchar* get_child_value_string( GVariant* gv, int order);
void      get_child_value_strv(GVariant* gv, int order, gchar*** value);

/******************************************************************************/
/******************************************************************************/

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

/**
 *  * This method frees a given trip entry points structure
 *   */
void free_trip_lib_entry_points(struct trip_lib_entry_points*);


struct trip_lib_entry_points* load_trip_library(char* path, char* trip_library_name);


#endif
