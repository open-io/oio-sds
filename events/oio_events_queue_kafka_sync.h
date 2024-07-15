/*
OpenIO SDS event queue
Copyright (C) 2024 OVH SAS

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

#ifndef OIO_SDS__sqlx__oio_events_queue_kafka_sync_h
# define OIO_SDS__sqlx__oio_events_queue_kafka_sync_h 1

/* Holds data necessary to connect to a Kafka endpoint. */
struct _queue_with_endpoint_sync_s
{
	struct oio_events_queue_vtable_s *vtable;

	gchar *endpoint;
	gchar *username;
	gchar *password;
	gchar *queue_name;  // topic for Kafka

	volatile gboolean healthy;  // used to know if a queue is explicitly unhealthy

	struct grid_single_rrd_s *event_send_count;
	struct grid_single_rrd_s *event_send_time;
	struct kafka_s *kafka;
};

/* Creates an event queue based on Kafka, with the default maximum number
 * of events "not yet acknowledged".
 * In this implementation, "_q_send" is synchronous, therefore blocking.
 * Also, there is no "internal" queue and events are directly sent to kafka. */
GError * oio_events_queue_factory__create_kafka_sync(
		const char *endpoint, const char *topic,
		struct oio_events_queue_s **out);

#endif /*OIO_SDS__sqlx__oio_events_queue_kafka_h*/
