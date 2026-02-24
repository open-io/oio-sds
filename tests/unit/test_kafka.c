/*
Copyright (C) 2026 OVH SAS

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
#include <core/oio_core.h>
#include <events/kafka.h>

/* Override sync timeouts before including kafka.c so that tests exercising
 * the timeout path complete in milliseconds rather than seconds. */
#define OIO_EVENTS_KAFKA_SYNC_MAX_POLLS  3
#define OIO_EVENTS_KAFKA_SYNC_POLL_DELAY (10 * G_TIME_SPAN_MILLISECOND)

#include "../../events/kafka.c"

/* Unreachable endpoint: no real broker needed for any of these tests. */
#define FAKE_ENDPOINT "127.0.0.1:10000"
#define FAKE_TOPIC    "test-topic"

static void _noop_requeue(gchar *key, gchar *msg) { g_free(key); g_free(msg); }
static void _noop_drop(const gchar *topic UNUSED, gchar *key, gchar *msg) {
	(void)topic; g_free(key); g_free(msg);
}

static void
test_kafka_create_destroy_async(void)
{
	struct kafka_s *kafka = NULL;
	GError *err = kafka_create(
		FAKE_ENDPOINT, FAKE_TOPIC,
		_noop_requeue, _noop_drop,
		&kafka, FALSE);
	g_assert_no_error(err);
	g_assert_nonnull(kafka);
	g_assert_cmpstr(kafka->topic, ==, FAKE_TOPIC);
	g_assert_nonnull(kafka->callback_ctx);

	err = kafka_destroy(kafka, TRUE);
	g_assert_no_error(err);
}

static void
test_kafka_create_destroy_sync(void)
{
	struct kafka_s *kafka = NULL;
	GError *err = kafka_create(
		FAKE_ENDPOINT, FAKE_TOPIC,
		NULL, NULL,
		&kafka, TRUE);
	g_assert_no_error(err);
	g_assert_nonnull(kafka);
	g_assert_null(kafka->callback_ctx);

	err = kafka_destroy(kafka, TRUE);
	g_assert_no_error(err);
}

static void
test_kafka_publish_without_connect(void)
{
	struct kafka_s *kafka = NULL;
	GError *err = kafka_create(
		FAKE_ENDPOINT, FAKE_TOPIC,
		NULL, NULL,
		&kafka, TRUE);
	g_assert_no_error(err);

	/* producer is NULL here -> must return a BADREQ error */
	gchar *msg = g_strdup("test_kafka_publish_without_connect");
	err = kafka_publish_message(
		kafka, NULL, 0, msg, strlen(msg), FAKE_TOPIC, TRUE);
	g_free(msg);

	g_assert_nonnull(err);
	g_assert_cmpint(err->code, ==, CODE_BAD_REQUEST);
	g_error_free(err);

	kafka_destroy(kafka, TRUE);
}

static void
test_kafka_sync_timeout(void)
{
	struct kafka_s *kafka = NULL;
	GError *err = kafka_create(
		FAKE_ENDPOINT, FAKE_TOPIC,
		NULL, NULL,
		&kafka, TRUE);
	g_assert_no_error(err);

	/* kafka_connect creates the producer object; it does not actually reach
	 * the broker. */
	err = kafka_connect(kafka);
	g_assert_no_error(err);
	g_assert_nonnull(kafka->producer);

	gchar *msg = g_strdup("test_kafka_sync_timeout");
	/* With no broker this call times out and must return TIMEOUT (or BUSY),
	 * but it must NOT leave any pending delivery callback pointing at freed
	 * memory. */
	err = kafka_publish_message(
		kafka, NULL, 0, msg, strlen(msg), FAKE_TOPIC, TRUE);
	g_free(msg);

	g_assert_nonnull(err);
	g_error_free(err);

	/* Check polling is still possible after the timeout */
	err = kafka_poll(kafka);
    g_assert_null(err);

	kafka_destroy(kafka, TRUE);
}

static void
test_kafka_flush_null(void)
{
	/* Neither NULL nor an unconnected kafka must crash. */
	GError *err = kafka_flush(NULL);
	g_assert_no_error(err);

	struct kafka_s *kafka = NULL;
	err = kafka_create(
		FAKE_ENDPOINT, FAKE_TOPIC,
		NULL, NULL,
		&kafka, TRUE);
	g_assert_no_error(err);

    /* producer is NULL, must be a no-op */
	err = kafka_flush(kafka);
	g_assert_no_error(err);

	kafka_destroy(kafka, TRUE);
}

static void
test_kafka_close_unconnected(void)
{
	struct kafka_s *kafka = NULL;
	GError *err = kafka_create(
		FAKE_ENDPOINT, FAKE_TOPIC,
		NULL, NULL,
		&kafka, TRUE);
	g_assert_no_error(err);

	/* Closing before connecting must be safe. */
	err = kafka_close(kafka);
	g_assert_no_error(err);

	kafka_destroy(kafka, TRUE);
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc, argv);

	g_test_add_func("/events/kafka/create_destroy_async",
		test_kafka_create_destroy_async);
	g_test_add_func("/events/kafka/create_destroy_sync",
		test_kafka_create_destroy_sync);
	g_test_add_func("/events/kafka/publish_without_connect",
		test_kafka_publish_without_connect);
	g_test_add_func("/events/kafka/sync_timeout",
		test_kafka_sync_timeout);
	g_test_add_func("/events/kafka/flush_null",
		test_kafka_flush_null);
	g_test_add_func("/events/kafka/close_unconnected",
		test_kafka_close_unconnected);

	return g_test_run();
}
