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

#include <glib.h>

#include <amqp.h>
#include <amqp_tcp_socket.h>

#include <core/oiolog.h>
#include <core/oiostr.h>
#include <core/internals.h>
#include <events/events_variables.h>

#include "rabbitmq.h"


static amqp_table_t *
_parse_args(const gchar *args_str)
{
	amqp_table_t *args_table = g_malloc0(sizeof(amqp_table_t));
	GArray *entries = g_array_new(FALSE, TRUE, sizeof(amqp_table_entry_t));
	gchar **tokens = g_strsplit(args_str, ",", -1);
	for (gchar **entry = tokens; entry && *entry; entry++) {
		gchar **kv_toks = g_strsplit(*entry, "=", 2);
		// Notice the use of strdup(), NOT g_strdup().
		amqp_table_entry_t aentry =  {
				.key = amqp_cstring_bytes(strdup(kv_toks[0])),
				.value.kind = AMQP_FIELD_KIND_UTF8,
				.value.value.bytes = amqp_cstring_bytes(strdup(kv_toks[1]))
		};
		g_array_append_vals(entries, &aentry, 1);
		g_strfreev(kv_toks);
	}
	g_strfreev(tokens);
	args_table->num_entries = entries->len;
	args_table->entries = (amqp_table_entry_t*) g_array_free(entries, FALSE);
	return args_table;
}

static void
_free_extra_args(amqp_table_t *args_table)
{
	for (int i = args_table->num_entries; i > 0; i--) {
		amqp_table_entry_t entry = args_table->entries[i - 1];
		amqp_bytes_free(entry.key);
		amqp_bytes_free(entry.value.value.bytes);
	}
	g_free(args_table->entries);
	args_table->num_entries = 0;
	args_table->entries = NULL;
	g_free(args_table);
}

GError*
rabbitmq_create(const gchar *endpoint, const gchar *exchange,
		const gchar *username, const gchar *password,
		const gchar **extra_args UNUSED,
		struct rabbitmq_s **out)
{
	g_assert_nonnull(out);

	GError *err = NULL;
	struct rabbitmq_s out1 = {0};
	gchar **netloc_and_vhost = g_strsplit(endpoint, "/", 2);
	gchar **host_and_port = g_strsplit(netloc_and_vhost[0], ":", 2);
	if (!oio_str_is_set(host_and_port[0])) {
		err = BADREQ("RabbitMQ endpoint is empty");
	} else if (!oio_str_is_set(exchange)) {
		err = BADREQ("RabbitMQ exchange is empty");
	} else {
		out1.hostname = g_strdup(host_and_port[0]);
		if (host_and_port[1] != NULL) {
			out1.port = (int)g_ascii_strtoll(host_and_port[1], NULL, 10);
		} else {
			out1.port = AMQP_DEFAULT_PORT;
		}
		if (netloc_and_vhost[1] != NULL) {
			out1.vhost = g_uri_unescape_string(netloc_and_vhost[1], NULL);
		}
		/* If we want to allow multiple threads to talk to the same connection,
		 * we have to make them talk to separate channels. Here we make the
		 * supposition that each thread will create its own connection. */
		out1.channel = AMQP_DEFAULT_CHANNEL;
		/* XXX: amqp_cstring_bytes() does not copy the string, whereas
		 * amqp_bytes_free() will free() the internal buffer... */
		out1.exchange = amqp_cstring_bytes(strdup(exchange));
		out1.username = g_strdup(username);
		out1.password = g_strdup(password);

		out1.exchange_args = _parse_args(oio_events_amqp_exchange_args);
		out1.queue_args = _parse_args(oio_events_amqp_queue_args);
		out1.bind_args = _parse_args(oio_events_amqp_bind_args);
	}
	g_strfreev(host_and_port);
	g_strfreev(netloc_and_vhost);

	if (!err) {
		*out = g_memdup(&out1, sizeof(struct rabbitmq_s));
	}

	return err;
}

static GError*
rabbitmq_reply_to_error(amqp_rpc_reply_t rep, const char *context)
{
	GError *err = NULL;
	switch (rep.reply_type) {
	case AMQP_RESPONSE_NORMAL:
		break;

	case AMQP_RESPONSE_NONE:
		err = SYSERR("%s: missing RPC reply type!", context);
		break;

	case AMQP_RESPONSE_LIBRARY_EXCEPTION:
		err = SYSERR("%s: %s", context, amqp_error_string2(rep.library_error));
		break;

	case AMQP_RESPONSE_SERVER_EXCEPTION:
		switch (rep.reply.id) {
		case AMQP_CONNECTION_CLOSE_METHOD: {
			amqp_connection_close_t *m =
					(amqp_connection_close_t *) rep.reply.decoded;
			err = SYSERR(
					"%s: server connection error %uh, message: %.*s\n",
					context,
					m->reply_code,
					(int) m->reply_text.len, (char *) m->reply_text.bytes);
		  break;
		}
		case AMQP_CHANNEL_CLOSE_METHOD: {
			amqp_channel_close_t *m =
					(amqp_channel_close_t *) rep.reply.decoded;
			err = SYSERR(
					"%s: server channel error %uh, message: %.*s\n",
					context, m->reply_code,
					(int) m->reply_text.len, (char *) m->reply_text.bytes);
		  break;
		}
		default:
			err = SYSERR("%s: unknown server error, method id 0x%08X\n",
					context, rep.reply.id);
		  break;
		}
		break;
	}

	return err;
}

GError*
rabbitmq_declare_exchange(struct rabbitmq_s *rabbitmq,
		const gchar *exchange_type, gboolean passive, gboolean durable,
		gboolean auto_delete)
{
	GError *err = NULL;
	if (!(err = rabbitmq_connect(rabbitmq))) {
		amqp_exchange_declare(rabbitmq->conn, rabbitmq->channel,
				rabbitmq->exchange, amqp_cstring_bytes(exchange_type),
				passive, durable, auto_delete,
				FALSE,  // internal
				*rabbitmq->exchange_args  // extra arguments
		);
		amqp_rpc_reply_t rep = amqp_get_rpc_reply(rabbitmq->conn);
		if (rep.reply_type != AMQP_RESPONSE_NORMAL) {
			err = rabbitmq_reply_to_error(rep,
					"RabbitMQ: failed to declare exchange");
		}
	}
	return err;
}

GError*
rabbitmq_declare_queue(struct rabbitmq_s *rabbitmq,
		const gchar *queue_name, gboolean passive, gboolean durable,
		gboolean exclusive, gboolean auto_delete)
{
	GError *err = NULL;
	if (!(err = rabbitmq_connect(rabbitmq))) {
		GRID_INFO("RabbitMQ declaring queue %s (durable=%d)",
				queue_name, durable);
		amqp_queue_declare(rabbitmq->conn, rabbitmq->channel,
				amqp_cstring_bytes(queue_name),
				passive, durable, exclusive, auto_delete,
				*rabbitmq->queue_args  // extra arguments
		);
		amqp_rpc_reply_t rep = amqp_get_rpc_reply(rabbitmq->conn);
		if (rep.reply_type != AMQP_RESPONSE_NORMAL) {
			err = rabbitmq_reply_to_error(rep,
					"RabbitMQ: failed to declare queue");
		}
	}
	return err;
}

GError*
rabbitmq_bind_queue(struct rabbitmq_s *rabbitmq,
		const gchar *queue_name, const gchar *routing_key)
{
	GError *err = NULL;
	if (!(err = rabbitmq_connect(rabbitmq))) {
		GRID_INFO(
				"RabbitMQ binding queue %s to exchange %s with routing key %s",
				queue_name, (char*)rabbitmq->exchange.bytes, routing_key
		);
		amqp_queue_bind(rabbitmq->conn, rabbitmq->channel,
				amqp_cstring_bytes(queue_name), rabbitmq->exchange,
				amqp_cstring_bytes(routing_key),
				*rabbitmq->bind_args  // extra arguments
		);
		amqp_rpc_reply_t rep = amqp_get_rpc_reply(rabbitmq->conn);
		if (rep.reply_type != AMQP_RESPONSE_NORMAL) {
			err = rabbitmq_reply_to_error(rep,
					"RabbitMQ: failed to bind queue to exchange");
		}
	}
	return err;
}

GError*
rabbitmq_connect(struct rabbitmq_s *rabbitmq)
{
	if (rabbitmq->conn) {
		GRID_DEBUG("RabbitMQ already connected to %s:%d",
				rabbitmq->hostname, rabbitmq->port);
		return NULL;
	}
	GRID_DEBUG("Connecting to RabbitMQ at %s:%d (%p)",
			rabbitmq->hostname, rabbitmq->port, rabbitmq);
	GError *err = NULL;

	// TODO(FVE): check return values
	rabbitmq->conn = amqp_new_connection();
	amqp_socket_t *socket = amqp_tcp_socket_new(rabbitmq->conn);

	int status = amqp_socket_open(socket,
			rabbitmq->hostname, rabbitmq->port);
	if (status != AMQP_STATUS_OK) {
		err = SYSERR("RabbitMQ: failed to reconnect to %s:%d: %s",
				rabbitmq->hostname, rabbitmq->port,
				amqp_error_string2(status));
	} else {
		amqp_rpc_reply_t rep = amqp_login(
				rabbitmq->conn,
				rabbitmq->vhost?:"/",
				0,                        // channel_max -> no limit
				AMQP_DEFAULT_FRAME_SIZE,  // frame_max
				AMQP_DEFAULT_HEARTBEAT,   // heartbeat (seconds)
				AMQP_SASL_METHOD_PLAIN,
				rabbitmq->username?: "guest", // login
				rabbitmq->password?: "guest"  // password
		);
		if (rep.reply_type != AMQP_RESPONSE_NORMAL) {
			err = rabbitmq_reply_to_error(rep, "RabbitMQ: failed to login");
		} else {
			amqp_channel_open(rabbitmq->conn, rabbitmq->channel);
			rep = amqp_get_rpc_reply(rabbitmq->conn);
			if (rep.reply_type != AMQP_RESPONSE_NORMAL) {
				err = rabbitmq_reply_to_error(rep,
						"RabbitMQ: failed to open channel");
			}
			if (err) {
				amqp_connection_close(rabbitmq->conn, AMQP_REPLY_SUCCESS);
			}
		}
	}
	if (err) {
		// Will also close the socket.
		amqp_destroy_connection(rabbitmq->conn);
		rabbitmq->conn = NULL;
	} else {
		GRID_INFO("RabbitMQ connected to [%s:%d] vhost=%s",
				rabbitmq->hostname, rabbitmq->port, rabbitmq->vhost?:"/");
	}
	return err;
}

GError*
rabbitmq_send_msg(struct rabbitmq_s *rabbitmq, void *msg, size_t msglen UNUSED,
		const gchar *routing_key)
{
	GError *err = NULL;
	amqp_bytes_t routing_key_bytes = amqp_cstring_bytes(routing_key);
	// FIXME(FVE): I'm not sure how to configure these options
	amqp_boolean_t mandatory = FALSE;
	amqp_boolean_t immediate = FALSE;
	struct amqp_basic_properties_t_ const *properties = NULL;
	// FIXME(FVE): amqp_cstring_bytes expects a nul-terminated string
	int res = amqp_basic_publish(rabbitmq->conn, rabbitmq->channel,
			rabbitmq->exchange, routing_key_bytes,
			mandatory, immediate, properties, amqp_cstring_bytes(msg));
	if (res != AMQP_STATUS_OK) {
		if (res == AMQP_STATUS_CONNECTION_CLOSED) {
			err = BUSY("RabbitMQ: failed to send message: %s",
				amqp_error_string2(res));
		} else {
			err = SYSERR("RabbitMQ: failed to send message: %s",
				amqp_error_string2(res));
		}
		amqp_destroy_connection(rabbitmq->conn);
		rabbitmq->conn = NULL;
	}
	return err;
}

GError*
rabbitmq_get_stats(struct rabbitmq_s *rabbitmq, const char *queue_name,
		struct rabbitmq_queue_stats_s *out)
{
	GError *err = NULL;
	amqp_queue_declare_ok_t *aqdo;
	if (!(err = rabbitmq_connect(rabbitmq))) {
		aqdo = amqp_queue_declare(rabbitmq->conn, rabbitmq->channel,
				amqp_cstring_bytes(queue_name),
				TRUE, FALSE, FALSE, FALSE,
				amqp_empty_table  // extra arguments
		);
		amqp_rpc_reply_t rep = amqp_get_rpc_reply(rabbitmq->conn);
		if (rep.reply_type != AMQP_RESPONSE_NORMAL) {
			err = rabbitmq_reply_to_error(rep,
					"RabbitMQ: failed to get queue stats");
		} else {
			out->message_count = aqdo->message_count;
			out->consumer_count = aqdo->consumer_count;
		}
	}
	return err;
}

void
rabbitmq_destroy(struct rabbitmq_s *rabbitmq)
{
	if (!rabbitmq)
		return;

	amqp_destroy_connection(rabbitmq->conn);
	g_free(rabbitmq->hostname);
	g_free(rabbitmq->vhost);
	amqp_bytes_free(rabbitmq->exchange);
	g_free(rabbitmq->username);
	g_free(rabbitmq->password);

	_free_extra_args(rabbitmq->exchange_args);
	_free_extra_args(rabbitmq->queue_args);
	_free_extra_args(rabbitmq->bind_args);

	memset(rabbitmq, 0, sizeof(struct rabbitmq_s));
	g_free(rabbitmq);
}
