/*
OpenIO SDS server
Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#ifndef OIO_SDS__metautils__lib__stats_h
#define OIO_SDS__metautils__lib__stats_h 1

#include <glib.h>

/**
 * Our experience shows that we do a lot of increments of stats by set of 4.
 * Instead of a complicated and/or sphisticated interface, here is a small but
 * simple API.
 */

/** @private */
struct stat_record_s
{
	guint64 value;
	GQuark  which;
};

/**
 * Increment 4 values at once, in the same critical section
 * Any key to 0 is ignored.
 */
void oio_stats_set(
		GQuark k1, guint64 v1, GQuark k2, guint64 v2,
		GQuark k3, guint64 v3, GQuark k4, guint64 v4);

/**
 * Set 4 values at once, in the same critical section
 * Any key to 0 is ignored.
 */
void oio_stats_add(
		GQuark k1, guint64 v1, GQuark k2, guint64 v2,
		GQuark k3, guint64 v3, GQuark k4, guint64 v4);

/**
 * Dump all the stats at once.
 * @return a GArray of <struct stat_record_s>
 */
GArray* network_server_stat_getall (void);

#endif  /* OIO_SDS__metautils__lib__stats_h */
