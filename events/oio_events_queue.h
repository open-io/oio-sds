/*
OpenIO SDS event queue
Copyright (C) 2016-2017 OpenIO SAS, as part of OpenIO SDS

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
#ifndef OIO_SDS__sqlx__oio_events_queue_h
# define OIO_SDS__sqlx__oio_events_queue_h 1

struct oio_events_queue_s;

void oio_events_queue__destroy (struct oio_events_queue_s *self);

/* msg's ownership is given to the queue. msg has to be valid JSON */
void oio_events_queue__send (struct oio_events_queue_s *self, gchar *msg);

/* Send an overwritable event, which may itself overwrite any previous event
 * sent with the same key. The actual event sending will be delayed
 * a little. */
void oio_events_queue__send_overwritable(struct oio_events_queue_s *self,
		gchar *key, gchar *msg);

/* should emitters stop sending events? whatever, even if it returns TRUE,
 * the queue won't deny events. */
gboolean oio_events_queue__is_stalled (struct oio_events_queue_s *self);

GError * oio_events_queue__run (struct oio_events_queue_s *self,
		gboolean (*running) (gboolean pending));

/* -------------------------------------------------------------------------- */

struct oio_url_s;

void oio_event__init (GString *out, const char *type, struct oio_url_s *url);

GString* oio_event__create (const char *type, struct oio_url_s *url);

/* -------------------------------------------------------------------------- */

/* find the appropriate implementation of event queue for the configuration
 * given in 'cfg' */
GError * oio_events_queue_factory__create (const char *cfg,
		struct oio_events_queue_s **out);

GError * oio_events_queue_factory__check_config (const char *cfg);

#endif /*OIO_SDS__sqlx__oio_events_queue_h*/
