#ifndef LIB_TRIP_H
#define LIB_TRIP_H

#include <glib.h>

gboolean bVerbose = FALSE;

#define TRIP_ERROR(...) { char triptmp[1024]; g_snprintf(triptmp, 1023, __VA_ARGS__);\
	GRID_ERROR("%s: %s", trip_name, triptmp); if (bVerbose) g_print("%s: %s\n", trip_name, triptmp); }
#define TRIP_WARN(...)  { char triptmp[1024]; g_snprintf(triptmp, 1023, __VA_ARGS__);\
	GRID_WARN( "%s: %s", trip_name, triptmp); if (bVerbose) g_print("%s: %s\n", trip_name, triptmp); }
#define TRIP_INFO(...)  { char triptmp[1024]; g_snprintf(triptmp, 1023, __VA_ARGS__);\
	GRID_INFO( "%s: %s", trip_name, triptmp); if (bVerbose) g_print("%s: %s\n", trip_name, triptmp); }
#define TRIP_TRACE(...) { char triptmp[1024]; g_snprintf(triptmp, 1023, __VA_ARGS__);\
	GRID_TRACE("%s: %s", trip_name, triptmp); if (bVerbose) g_print("%s: %s\n", trip_name, triptmp); }
#define TRIP_DEBUG(...) { char triptmp[1024]; g_snprintf(triptmp, 1023, __VA_ARGS__);\
	GRID_DEBUG("%s: %s", trip_name, triptmp); if (bVerbose) g_print("%s: %s\n", trip_name, triptmp); }


/*
 * This function returns the percentage of trip achievement
 **/
int
trip_progress(void);

/*
 * This function must be called before any trip action to prepare later iterations
 **/
int
trip_start(int, char**);

/*
 * This function returns the next element of the next iteration trip in a GVariant object
 **/
GVariant*
trip_next(void);

/*
 * This function ends the trip and runs appropriate actions (i.e. free memory allocations)
 **/
void
trip_end(void);

#endif
