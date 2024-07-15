/*
OpenIO SDS event queue
Copyright (C) 2016-2020 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021-2024 OVH SAS

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
#ifndef OIO_SDS__sqlx__oio_events_queue_h
# define OIO_SDS__sqlx__oio_events_queue_h 1

#define  OIO_EVENT_DOMAIN "EVENTS"

struct oio_events_queue_s;

void oio_events_queue__destroy (struct oio_events_queue_s *self);

/* msg's ownership is given to the queue. msg has to be valid JSON */
gboolean oio_events_queue__send (struct oio_events_queue_s *self, gchar *msg);

/* Flush any overwritable event with the specified key, disregarding
 * the buffer delay. `key` will be freed. */
void oio_events_queue__flush_overwritable(struct oio_events_queue_s *self,
		gchar *key);

/* Send an overwritable event, which may itself overwrite any previous event
 * sent with the same key. The actual event sending will be delayed
 * a little. */
gboolean oio_events_queue__send_overwritable(struct oio_events_queue_s *self,
		gchar *key, gchar *msg);

/* Should emitters stop sending events?
 * (based on queue reaching maximum pending events) */
gboolean oio_events_queue__is_stalled (struct oio_events_queue_s *self);

/** Get the total time spent sending events. */
guint64 oio_events_queue__get_total_send_time(struct oio_events_queue_s *self);

/** Get the total number of events sent through this queue. */
guint64 oio_events_queue__get_total_sent_events(struct oio_events_queue_s *self);

/* Get a health metric for the events queue, from 0 (bad) to 100 (good). */
gint64 oio_events_queue__get_health(struct oio_events_queue_s *self);

void oio_events_queue__set_buffering (struct oio_events_queue_s *self,
		gint64 delay);

GError * oio_events_queue__start (struct oio_events_queue_s *self);

/* -------------------------------------------------------------------------- */

struct oio_url_s;

void oio_event__init (GString *out, const char *type, struct oio_url_s *url);

GString* oio_event__create (const char *type, struct oio_url_s *url);

/* Create the base of a JSON formatted event, with the specified request ID. */
GString* oio_event__create_with_id(const char *type, struct oio_url_s *url,
		const char *request_id);

/* -------------------------------------------------------------------------- */

/* find the appropriate implementation of event queue for the configuration
 * given in 'cfg'.
 * As of today, only configuration URL prefixed with 'beanstalk://'
 * and 'kafka://' are accepted.
 * 'tube' can be NULL if one is specified in the URL's query string.
 * sync option is only available for kafka endpoint (will be ignored otherwise).
 */
GError * oio_events_queue_factory__create (const char *cfg, const char *tube,
		const gboolean sync, struct oio_events_queue_s **out);

/* -------------------------------------------------------------------------- */

#define OIO_EVENTS_STATS_HISTORY_SECONDS 60

/** Register a queue whose metrics must be reported by
 * oio_events_stats_to_prometheus(). */
void oio_events_stats_register(const gchar *key,
		struct oio_events_queue_s *queue);

/** Unregister a queue whose metrics are reported by
 * oio_events_stats_to_prometheus(). */
void oio_events_stats_unregister(const gchar *key);

/** Get a report of registered queue metric, in Prometheus format. */
void oio_events_stats_to_prometheus(const gchar *service_id,
		const gchar *namespace, GString *out);

#endif /*OIO_SDS__sqlx__oio_events_queue_h*/
