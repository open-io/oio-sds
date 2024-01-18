/*
OpenIO SDS event queue
Copyright (C) 2023-2024 OVH SAS

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
#include <events/events_variables.h>

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

static void kafka_log_forward(const rd_kafka_t* rk, int level, const char* fac, const char* buf) {
	// Log level conversion
	GLogLevelFlags log_level = log_level_mapping[level];

	g_log(G_LOG_DOMAIN, log_level, "%s - %s: %s", fac, rd_kafka_name(rk), buf);
}

GError*
kafka_create(const gchar *endpoint, const gchar *topic,
		struct kafka_s **out)
{
	g_assert_nonnull(out);
	g_assert_nonnull(topic);

	GError *err = NULL;

	struct kafka_s out1 = {0};
	out1.topic = g_strdup(topic);

	rd_kafka_conf_t* kafka_conf = rd_kafka_conf_new();
	char errstr[512];
	rd_kafka_resp_err_t kafka_err;
	gchar** options = NULL;


	// Endpoints
	GRID_INFO("Setting option bootstap.server=%s", endpoint);
	kafka_err = rd_kafka_conf_set(kafka_conf, "bootstrap.servers", endpoint, errstr, sizeof(errstr));
	if (kafka_err) {
		err = BADREQ("Invalid endpoint: %s", errstr);
	}

	if (!err) {
		// Acks
		GRID_INFO("Setting option acks=%s", oio_events_kafka_acks);
		kafka_err = rd_kafka_conf_set(kafka_conf, "acks", oio_events_kafka_acks, errstr, sizeof(errstr));
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
				err = BADREQ("Missing value in kafka options for key '%s'", key_value[0]);
				g_strfreev(key_value);
				break;
			}
			GRID_INFO("Setting option %s=%s", key_value[0], key_value[1]);
			kafka_err = rd_kafka_conf_set(kafka_conf, key_value[0], key_value[1], errstr, sizeof(errstr));
			g_strfreev(key_value);
			if (kafka_err) {
				err = BADREQ("Invalid option: %s", errstr);
				break;
			}
		}
	}

	// Configure logger redirection
	if (!err) {
		rd_kafka_conf_set_log_cb(kafka_conf, kafka_log_forward);
	}

	if (!err) {
		out1.producer = rd_kafka_new(RD_KAFKA_PRODUCER, kafka_conf, errstr, sizeof(errstr));
		if (!out1.producer) {
			err = BADREQ("Unable to instantiate Kafka producer: %s", errstr);
		}
	}

	if (!err) {
		*out = g_memdup(&out1, sizeof(struct kafka_s));
	} else {
		rd_kafka_conf_destroy(kafka_conf);
	}

	g_strfreev(options);

	return err;
}

GError*
kafka_connect(const struct kafka_s *kafka UNUSED)
{
	return NULL;
}

GError*
kafka_publish_message(struct kafka_s *kafka,
		void* msg, size_t msglen, const gchar* topic)
{
	GError *err = NULL;

	rd_kafka_resp_err_t rc = rd_kafka_producev(kafka->producer,
				RD_KAFKA_V_TOPIC(topic),
				RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
				RD_KAFKA_V_VALUE(msg, msglen),
				RD_KAFKA_V_END);
	if (rc != RD_KAFKA_RESP_ERR_NO_ERROR) {
		rd_kafka_resp_err_t rd_err = rd_kafka_last_error();
		if (rd_err == RD_KAFKA_RESP_ERR__QUEUE_FULL) {
			// Queue is full retry later
			err = BUSY("Failed to produce to topic %s: %s", topic,
				rd_kafka_err2str(rd_err));
		} else {
			err = BADREQ("Failed to produce to topic %s: %s", topic,
				rd_kafka_err2str(rd_err));
		}
	} else {
		rd_kafka_flush(kafka->producer, oio_events_kafka_timeouts_flush);
	}

	return err;
}


GError*
kafka_destroy(struct kafka_s *kafka)
{
	GError* err = NULL;

	if (!kafka) {
		return err;
	}

	// Flush
	rd_kafka_flush(kafka->producer, 10 * 1000);

	int queue_len = rd_kafka_outq_len(kafka->producer);
	if (queue_len > 0) {
        err = TIMEOUT("%d message(s) were not delivered", queue_len);
    }

	rd_kafka_destroy(kafka->producer);
	g_free((gchar*)kafka->topic);

	return err;
}
