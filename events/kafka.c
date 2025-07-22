/*
OpenIO SDS event queue
Copyright (C) 2023-2025 OVH SAS

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

#include "kafka.h"


#include <core/oiolog.h>
#include <core/oiostr.h>
#include <core/internals.h>
#include <events/oio_events_queue.h>
#include <events/events_variables.h>

/* Used for sync message, the value means nothing but should not exist in
 * "rd_kafka_resp_err_t" enum. */
#define MAGICAL_SYNC -12345


GLogLevelFlags log_level_mapping[] = {
	GRID_LOGLVL_ERROR, // 0
	GRID_LOGLVL_ERROR, // 1
	GRID_LOGLVL_ERROR, // 2
	GRID_LOGLVL_ERROR, // 3
	GRID_LOGLVL_WARN,  // 4
	GRID_LOGLVL_INFO,  // 5
	GRID_LOGLVL_INFO,  // 6
	GRID_LOGLVL_DEBUG, // 7
};

static void kafka_log_forward(
	const rd_kafka_t* rk,
	int level, const char* fac,
	const char* buf)
{
	// Log level conversion
	GLogLevelFlags log_level = log_level_mapping[level];

	g_log(G_LOG_DOMAIN, log_level, "%s - %s: %s", fac, rd_kafka_name(rk), buf);
}

static gboolean message_should_be_dropped(rd_kafka_resp_err_t err) {
	return (
		err == RD_KAFKA_RESP_ERR__PURGE_QUEUE
		|| err == RD_KAFKA_RESP_ERR__PURGE_INFLIGHT
		|| err == RD_KAFKA_RESP_ERR__KEY_SERIALIZATION
		|| err == RD_KAFKA_RESP_ERR__VALUE_SERIALIZATION
		|| err == RD_KAFKA_RESP_ERR_INVALID_MSG_SIZE
		|| err == RD_KAFKA_RESP_ERR_INVALID_MSG
	);
}

static
void on_kafka_delivery_report(rd_kafka_t* rk UNUSED,
		const rd_kafka_message_t *rkmessage, void *opaque) {
	// Retrieve context
	struct kafka_callback_ctx *ctx = (struct kafka_callback_ctx*)opaque;

	rd_kafka_resp_err_t err = rkmessage->err;
	if (err == RD_KAFKA_RESP_ERR_NO_ERROR) {
		return;
	}
	const rd_kafka_topic_t* _topic = rkmessage->rkt;
	const char* topic_name = rd_kafka_topic_name(_topic);
	gchar *msg = g_strndup(rkmessage->payload, rkmessage->len);
	gchar *key = NULL;
	if (rkmessage->key) {
		key =g_strndup(rkmessage->key, rkmessage->key_len);
	}
	if (message_should_be_dropped(err)) {
		// drop_func take ownership of key and msg
		ctx->drop_func(topic_name, key, msg);
	} else {
		// requeue_func takes ownership of key and msg
		ctx->requeue_func(key, msg);
	}
}

static void msg_sync_delivered (
       rd_kafka_t *rk UNUSED,
       const rd_kafka_message_t *rkmessage,
       void *opaque UNUSED)
{
       /* Update the magical value polled by the emitter of the message. */
       if (rkmessage->_private) {
			rd_kafka_resp_err_t *err = (rd_kafka_resp_err_t *)rkmessage->_private;
			*err = rkmessage->err;
       }
}

GError*
kafka_create(const gchar *endpoint,
		const gchar *topic,
		void (*requeue_fn)(gchar*, gchar*),
		void (*drop_fn)(const gchar*, gchar*, gchar*),
		struct kafka_s **out,
		const gboolean sync)
{
	g_assert_nonnull(out);
	g_assert_nonnull(topic);

	GError *err = NULL;

	struct kafka_s out1 = {0};
	out1.conf = rd_kafka_conf_new();
	out1.producer = NULL;
	out1.topic = g_strdup(topic);
	if (!sync) {
		out1.callback_ctx = g_malloc(sizeof(struct kafka_callback_ctx));
		out1.callback_ctx->drop_func = drop_fn;
		out1.callback_ctx->requeue_func = requeue_fn;
	} else {
		out1.callback_ctx = NULL;
	}

	char errstr[512];
	rd_kafka_resp_err_t kafka_err;
	gchar** options = NULL;

	// Endpoints
	GRID_INFO("Setting option bootstrap.server=%s", endpoint);
	kafka_err = rd_kafka_conf_set(
		out1.conf, "bootstrap.servers", endpoint, errstr, sizeof(errstr));
	if (kafka_err) {
		err = BADREQ("Invalid endpoint: %s", errstr);
	}

	if (!err) {
		// Acks
		GRID_INFO("Setting option acks=%s", oio_events_kafka_acks);
		kafka_err = rd_kafka_conf_set(
			out1.conf, "acks", oio_events_kafka_acks, errstr, sizeof(errstr));
		if (kafka_err) {
			err = BADREQ("Invalid acknowledgement: %s", errstr);
		}
	}

	if (!err) {
		// Extra options
		options = g_strsplit(oio_events_kafka_options, ";", -1);
		for (gchar** option = options; options && *option; option++) {
			gchar** key_value = g_strsplit(*option, "=", 2);
			if (key_value[0] == NULL) {
				err = BADREQ("Missing key in kafka options");
				g_strfreev(key_value);
				break;
			}
			if (key_value[1] == NULL) {
				err = BADREQ(
					"Missing value in kafka options for key '%s'", key_value[0]);
				g_strfreev(key_value);
				break;
			}
			GRID_INFO("Setting option %s=%s", key_value[0], key_value[1]);
			kafka_err = rd_kafka_conf_set(
				out1.conf, key_value[0], key_value[1], errstr, sizeof(errstr));
			g_strfreev(key_value);
			if (kafka_err) {
				err = BADREQ("Invalid option: %s", errstr);
				break;
			}
		}
	}

	// Install callbacks for async mode
	if (!err && !sync) {
		// Logger redirection
		rd_kafka_conf_set_log_cb(out1.conf, kafka_log_forward);
		// Delivery report
		rd_kafka_conf_set_opaque(out1.conf, out1.callback_ctx);
		rd_kafka_conf_set_dr_msg_cb(out1.conf, on_kafka_delivery_report);
	}

	// Install callbacks for sync mode
	if (!err && sync) {
		/* To be able to send synchronous messages (with the async kafka api),
		 * a little hack is necessary. A callback is added to the kafka context
		 * and will update a value. As long as the value is not updated, we will
		 * have to wait (by calling the "poll" function as callback are triggered
		 * by it).
		 * In this very special case, some tuning is made for optimization as
		 * messages will always be sent one by one. */
		rd_kafka_conf_set_dr_msg_cb(out1.conf, msg_sync_delivered);

		/* Minimize wait-for-larger-batch delay (since there will be no batching) */
		kafka_err = rd_kafka_conf_set(
			out1.conf, "queue.buffering.max.ms", "1", errstr, sizeof(errstr));
		if (kafka_err) {
			err = BADREQ("Invalid option: %s", errstr);
		}

		if (!err) {
			/* Minimize wait-for-socket delay (otherwise we will lose 100ms per
			* message instead just the RTT) */
			kafka_err = rd_kafka_conf_set(
				out1.conf, "socket.blocking.max.ms", "1", errstr, sizeof(errstr));
			if (kafka_err) {
				err = BADREQ("Invalid option: %s", errstr);
			}
		}

		if (!err) {
			/* Prevent event to remain in the internal kafka queue */
			gchar timeout_str[16];
			g_snprintf(timeout_str, sizeof(timeout_str), "%ld", \
				(OIO_EVENTS_KAFKA_SYNC_POLL_DELAY * OIO_EVENTS_KAFKA_SYNC_MAX_POLLS) / 1000);
			kafka_err = rd_kafka_conf_set(
				out1.conf, "message.timeout.ms", timeout_str, errstr, sizeof(errstr));
			if (kafka_err) {
				err = BADREQ("Invalid option: %s", errstr);
			}
		}
	}

	if (!err) {
		*out = oio_memdup(&out1, sizeof(struct kafka_s));
	} else {
		kafka_destroy(&out1);
	}
	g_strfreev(options);
	return err;
}

GError*
kafka_connect(struct kafka_s *kafka)
{
	if (kafka->producer) {
		GRID_DEBUG("Kafka producer already initialized");
		return NULL;
	}

	GError *err = NULL;
	char errstr[512];
	rd_kafka_conf_t *conf = rd_kafka_conf_dup(kafka->conf);
	kafka->producer = rd_kafka_new(
		RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));

	if (!kafka->producer) {
		rd_kafka_conf_destroy(conf);
		err = BADREQ("Unable to instantiate Kafka producer: %s", errstr);
	}

	return err;
}

GError*
kafka_check_fatal_error(struct kafka_s *kafka)
{
	if (!kafka->producer) {
		return NULL;
	}
	rd_kafka_poll(kafka->producer, 0);
	char errstr[512];
	rd_kafka_resp_err_t  err = rd_kafka_fatal_error(kafka->producer, errstr, sizeof(errstr));

	if (err == RD_KAFKA_RESP_ERR_NO_ERROR) {
		return NULL;
	}

	return SYSERR("Kafka producer encountered a fatal error: %s", rd_kafka_err2str(err));
}

GError*
kafka_poll(struct kafka_s *kafka)
{
	if (kafka->producer) {
		rd_kafka_poll(kafka->producer, 0);
	}
	return NULL;
}

GError*
kafka_publish_message(struct kafka_s *kafka,
		void* key, size_t keylen,
		void* msg, size_t msglen,
		const gchar* topic, const gboolean sync)
{
	GError *err = NULL;
	rd_kafka_resp_err_t err_sync = MAGICAL_SYNC;
	rd_kafka_resp_err_t rc = RD_KAFKA_RESP_ERR_UNKNOWN;

	if (!kafka || !kafka->producer) {
		// One should call "kafka_connect" before publishing a message
		return BADREQ("Try to publish message without producer");
	}
	void* opaque =(sync)? &err_sync : NULL;

	// Add a special opaque only on sync mode.
	rc = rd_kafka_producev(kafka->producer,
		RD_KAFKA_V_TOPIC(topic),
		RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
		RD_KAFKA_V_KEY(key, keylen),
		RD_KAFKA_V_VALUE(msg, msglen),
		RD_KAFKA_V_OPAQUE(opaque),
		RD_KAFKA_V_END);

	if (rc != RD_KAFKA_RESP_ERR_NO_ERROR) {
		if (rc == RD_KAFKA_RESP_ERR_MSG_SIZE_TOO_LARGE) {
			err = BADREQ("Failed to produce to topic %s: %s, dropped", topic,
				rd_kafka_err2str(rc));
		} else {
			err = BUSY("Failed to produce to topic %s: %s, retry later", topic,
				rd_kafka_err2str(rc));
		}
	} else {
		rd_kafka_flush(kafka->producer,
			oio_events_kafka_timeout_flush / G_TIME_SPAN_MILLISECOND);
	}

	if (!err && sync) {
		int i = 0;
		while (err_sync == MAGICAL_SYNC) {
			// Timeout converted in ms
			rd_kafka_poll(kafka->producer, OIO_EVENTS_KAFKA_SYNC_POLL_DELAY / 1000);
			i += 1;
			if (i >= OIO_EVENTS_KAFKA_SYNC_MAX_POLLS) {
				return TIMEOUT("Sync message still not received, aborting...");
			}
		}
		if (err_sync != RD_KAFKA_RESP_ERR_NO_ERROR) {
			return BUSY("Unable to send the sync message: err=%d", err_sync);
		}
	}

	return err;
}

GError*
kafka_flush(struct kafka_s *kafka)
{
	GError* err = NULL;

	if (!kafka || !kafka->producer) {
		return err;
	}

	// Flush
	rd_kafka_flush(kafka->producer,
		oio_events_kafka_timeouts_flush_shutdown / G_TIME_SPAN_MILLISECOND);

	int queue_len = rd_kafka_outq_len(kafka->producer);
	if (queue_len > 0) {
		err = TIMEOUT("%d message(s) were not delivered. Purging", queue_len);
		// Purge remaining messages
		rd_kafka_purge(kafka->producer, RD_KAFKA_PURGE_F_QUEUE);
		rd_kafka_poll(kafka->producer, 0);
	}

	return err;
}

GError*
kafka_close(struct kafka_s *kafka)
{
	GError *err = NULL;

	if (kafka && kafka->producer) {
		err = kafka_flush(kafka);
		rd_kafka_destroy(kafka->producer);
		kafka->producer = NULL;
	}

	return err;
}

GError*
kafka_destroy(struct kafka_s *kafka)
{
	GError* err = NULL;

	if (kafka) {
		kafka_close(kafka);
		rd_kafka_conf_destroy(kafka->conf);
		g_free((gchar*)kafka->topic);
		if (kafka->callback_ctx) {
			g_free(kafka->callback_ctx);
		}
	}

	return err;
}
