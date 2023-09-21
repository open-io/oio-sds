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

#include "kafka.h"

#include <core/oiolog.h>
#include <core/oiostr.h>
#include <core/internals.h>
#include <events/events_variables.h>



static void dr_msg_cb (rd_kafka_t *kafka_handle UNUSED,
                       const rd_kafka_message_t *rkmessage,
                       void *opaque UNUSED) {
    if (rkmessage->err) {
        g_error("Message delivery failed: %s", rd_kafka_err2str(rkmessage->err));
    }
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

	rd_kafka_conf_set(kafka_conf, "bootstrap.servers", endpoint, errstr, sizeof(errstr));

	rd_kafka_conf_set_dr_msg_cb(kafka_conf, dr_msg_cb);

	out1.producer = rd_kafka_new(RD_KAFKA_PRODUCER, kafka_conf, errstr, sizeof(errstr));
	if (!out1.producer) {
		err = BADREQ("Unable to instantiate Kafka producer: %s", errstr);
	}

	if (!err) {
		*out = g_memdup(&out1, sizeof(struct kafka_s));
	}

	return err;
}

GError*
kafka_connect(struct kafka_s *kafka UNUSED)
{
	return NULL;
}

GError*
kafka_publish_message(struct kafka_s *kafka,
		void* msg, size_t msglen, const gchar* topic)
{
	GError *err = NULL;

	rd_kafka_resp_err_t rd_err;

	rd_err = rd_kafka_producev(kafka->producer,
				RD_KAFKA_V_TOPIC(topic),
				RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
				RD_KAFKA_V_VALUE(msg, msglen),
				RD_KAFKA_V_END);

	if (rd_err) {
		err = BUSY("Failed to produce to topic %s: %s", topic,
			rd_kafka_err2str(rd_err));
	}

	rd_kafka_poll(kafka->producer, 0);

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

	if (rd_kafka_outq_len(kafka->producer) > 0) {
        err = TIMEOUT("%d message(s) were not delivered", rd_kafka_outq_len(kafka->producer));
    }

	rd_kafka_destroy(kafka->producer);

	return err;
}
