/*
OpenIO SDS event queue
Copyright (C) 2023 OVH SAS

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

#ifndef OIO_SDS__event__kafka_h
#define OIO_SDS__event__kafka_h

#include <glib.h>
#include <librdkafka/rdkafka.h>


#define KAFKA_PREFIX "kafka://"


struct kafka_s
{
	rd_kafka_t *producer;
	const gchar* topic;
};

/** Create a Kafka connector, tied to the specified exchange. */
GError* kafka_create(const gchar *endpoint, const gchar *exchange,
		struct kafka_s **out);

/** Connect the specified kafka connector.
 * Won't try to connect if the socket seems already connected. */
GError* kafka_connect(struct kafka_s *kafka);

/** Send a message to the previously configured queue. */
GError* kafka_publish_message(struct kafka_s *kafka,
		void* msg, size_t msglen, const gchar* topic);

/** Destroy the specified kafka connector. */
GError* kafka_destroy(struct kafka_s *kafka);


#endif /*OIO_SDS__event__kafka_h*/