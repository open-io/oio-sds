/*
OpenIO SDS cluster
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

#ifndef OIO_SDS__cluster__agent__task_h
# define OIO_SDS__cluster__agent__task_h 1

# include <glib.h>
# include <cluster/agent/worker.h>

typedef int (*task_handler_f) (gpointer udata, GError **err);

typedef struct {
	char *id;
	gint64 period; /* time in seconds */
	gint64 next_schedule; /* monotonic time in seconds */
	task_handler_f task_handler;
	GDestroyNotify clean_udata;
	gpointer udata;
	guint8 flag_destroy;
	guint8 busy;
} task_t;

#endif /*OIO_SDS__cluster__agent__task_h*/
