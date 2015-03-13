/*
OpenIO SDS crawler
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef OIO_SDS__crawler__lib__lib_trip_h
# define OIO_SDS__crawler__lib__lib_trip_h 1

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

#endif /*OIO_SDS__crawler__lib__lib_trip_h*/