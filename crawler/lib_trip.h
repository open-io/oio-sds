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

#ifndef LIB_TRIP_H
#define LIB_TRIP_H

#include <glib.h>

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
