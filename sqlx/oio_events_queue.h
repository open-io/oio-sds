/*
OpenIO SDS sqlx
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

struct oio_events_queue_s;

void oio_events_queue__destroy (struct oio_events_queue_s *self);

/* msg's ownership is given to the queue. msg has to be valid JSON */
void oio_events_queue__send (struct oio_events_queue_s *self, gchar *msg);

/* should emitters stop sending events */
gboolean oio_events_queue__is_stalled (struct oio_events_queue_s *self);

/* Event-agent based implementation ----------------------------------------- */

struct oio_events_queue_s * oio_events_queue_factory__create_agent (
		const char *zurl, guint max_pending);

/* <self> must have been created by oio_events_queue_factory__create_agent().
   It internally loops until <running> returns FALSE */
GError * oio_events_queue__run_agent (struct oio_events_queue_s *self,
	gboolean (*running) (void));

