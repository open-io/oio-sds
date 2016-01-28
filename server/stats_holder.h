/*
OpenIO SDS server
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#ifndef OIO_SDS__server__stats_holder_h
# define OIO_SDS__server__stats_holder_h 1

# include <glib/gtypes.h>

struct grid_single_rrd_s;

/*! Allocates a round-robin set of metrics, working on <period> slots. */
struct grid_single_rrd_s* grid_single_rrd_create(time_t now, time_t period);

/*! Cleans all the resources used by the rrd. */
void grid_single_rrd_destroy(struct grid_single_rrd_s *gsr);

/*! Save a default value to be used for the slots where there is no
 * activity. */
void grid_single_rrd_set_default(struct grid_single_rrd_s *gsr,
		guint64 def);

/*! forces an absolute value for the current position */
void grid_single_rrd_push(struct grid_single_rrd_s *gsr,
		time_t at, guint64 v);

/*! forces an absolute value for the current position */
void grid_single_rrd_pushifmax(struct grid_single_rrd_s *gsr,
		time_t at, guint64 v);

/*! Get the value in the current slot of the rrd. */
guint64 grid_single_rrd_get(struct grid_single_rrd_s *gsr, time_t at);

/*! Compute the difference between the current value and the value that
 * is <period> seconds old. */
guint64 grid_single_rrd_get_delta(struct grid_single_rrd_s *gsr,
		time_t at, time_t period);

/*! Computes the maximal value among the set not older than <period> seconds. */
guint64 grid_single_rrd_get_max(struct grid_single_rrd_s *gsr,
		time_t at, time_t period);

/*! Cumulates all the maximum values, for all the periods between
 * 1 and the given <period>. Single run! */
void grid_single_rrd_get_allmax(struct grid_single_rrd_s *gsr,
		time_t at, time_t period, guint64 *out);

#endif /*OIO_SDS__server__stats_holder_h*/
