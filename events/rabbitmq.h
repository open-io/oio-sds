/*
OpenIO SDS event queue
Copyright (C) 2022-2023 OVH SAS

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

#ifndef OIO_SDS__event__rabbitmq_h
# define OIO_SDS__event__rabbitmq_h 1

#include <glib.h>
#include <amqp.h>

/* We use RabbitMQ, but we can theoretically talk to any AMQP broker. */
#define AMQP_DEFAULT_CHANNEL 1
#define AMQP_DEFAULT_PORT 5672
#define AMQP_PREFIX "amqp://"

struct rabbitmq_s
{
	gchar *hostname;
	int port;
	gchar *vhost;
	amqp_channel_t channel;
	amqp_bytes_t exchange;
	gchar *username;
	gchar *password;

	amqp_connection_state_t conn;
};

/** Holds statistics about the usage of a specific queue. */
struct rabbitmq_queue_stats_s
{
	guint32 message_count;   // Provided by the broker
	guint32 consumer_count;  // Provided by the broker
};

/** Create a RabbitMQ connector, tied to the specified exchange. */
GError *rabbitmq_create(const gchar *endpoint, const gchar *exchange,
		const gchar *username, const gchar *password,
		struct rabbitmq_s **out);

/** Connect the specified RabbitMQ connector.
 * Won't try to connect if the socket seems already connected. */
GError *rabbitmq_connect(struct rabbitmq_s *rabbitmq);

/** Declare the exchange passed to rabbitmq_create, with the specified
 * parameters. Will connect to the broker if not connected already. */
GError *rabbitmq_declare_exchange(struct rabbitmq_s *rabbitmq,
		const gchar *exchange_type, gboolean passive, gboolean durable,
		gboolean auto_delete);

/** Declare the specified queue.
 * Will connect to the broker if not connected already. */
GError *rabbitmq_declare_queue(struct rabbitmq_s *rabbitmq,
		const gchar *queue_name, gboolean passive, gboolean durable,
		gboolean exclusive, gboolean auto_delete);

/** Bind the specified queue to the exchange passed to rabbitmq_create,
 * with the specified routing key.
 * Will connect to the broker if not connected already. */
GError *rabbitmq_bind_queue(struct rabbitmq_s *rabbitmq,
		const gchar *queue_name, const gchar *routing_key);

/** Send a message to the previously configured exchange,
 * with an empty routing key. */
GError *rabbitmq_send_msg(struct rabbitmq_s *rabbitmq,
		void *msg, size_t msglen, const gchar *routing_key);

/** Get statistics about a connected RabbitMQ connector. */
GError *rabbitmq_get_stats(struct rabbitmq_s *rabbitmq, const char *queue_name,
	struct rabbitmq_queue_stats_s *out);

/** Destroy the specified RabbitMQ connector. */
void rabbitmq_destroy(struct rabbitmq_s *rabbitmq);

#endif /*OIO_SDS__event__rabbitmq_h*/
