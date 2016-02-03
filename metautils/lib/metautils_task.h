/*
OpenIO SDS metautils
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

#ifndef OIO_SDS__metautils__lib__metautils_task_h
# define OIO_SDS__metautils__lib__metautils_task_h 1

# include <glib.h>

typedef guint task_period_t;

struct grid_task_queue_s;

struct grid_task_queue_s* grid_task_queue_create(const gchar *name);

void grid_task_queue_stop(struct grid_task_queue_s *gtq);

void grid_task_queue_destroy(struct grid_task_queue_s *gtq);

void grid_task_queue_fire(struct grid_task_queue_s *gtq);

void grid_task_queue_register(struct grid_task_queue_s *gtq,
		task_period_t period, GDestroyNotify run, GDestroyNotify cleanup,
		gpointer udata);

/** When the thread is joined, 'gtq' is returned. */
GThread* grid_task_queue_run(struct grid_task_queue_s *gtq, GError **err);

#endif /*OIO_SDS__metautils__lib__metautils_task_h*/
