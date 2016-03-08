/*
OpenIO SDS event queue
Copyright (C) 2016 OpenIO, original work as part of OpenIO Software Defined Storage

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

struct oio_events_queue_s;

void oio_events_queue__destroy (struct oio_events_queue_s *self);

/* msg's ownership is given to the queue. msg has to be valid JSON */
void oio_events_queue__send (struct oio_events_queue_s *self, gchar *msg);

/* should emitters stop sending events */
gboolean oio_events_queue__is_stalled (struct oio_events_queue_s *self);

/* Event-agent based implementation ----------------------------------------- */

/* Creates an agent-based event queue, with a maximum number of events "not yet
   acknowledged" events set to <max_pending>. When ZERO, there is no limit
   with all the (possible) consequences of memory outage */
struct oio_events_queue_s * oio_events_queue_factory__create_agent (
		const char *zurl, guint max_pending);

/* Changes the window's width of events in flight. <max_pending> has the same
   meaning as in oio_events_queue_factory__create_agent() */
void oio_events_queue__set_max_pending (struct oio_events_queue_s *self,
		guint max_pending);

/* <self> must have been created by oio_events_queue_factory__create_agent().
   It internally loops until <running> returns FALSE */
GError * oio_events_queue__run_agent (struct oio_events_queue_s *self,
	gboolean (*running) (void));

