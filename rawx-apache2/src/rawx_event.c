#include <stdlib.h>
#include <assert.h>
#include <zmq.h>
#include <glib.h>

#include "rawx_event.h"

static void *g_zmq_ctx = NULL;
static char g_event_addr[RAWX_EVENT_ADDR_SIZE];

int
rawx_event_init(const char *addr)
{
	if (addr[0] == '\0')
		return 1;

	g_strlcpy(g_event_addr, addr, sizeof(g_event_addr));
	g_zmq_ctx = zmq_ctx_new();
	return g_zmq_ctx != NULL;
}

void
rawx_event_destroy(void)
{
	if (g_zmq_ctx != NULL)
		zmq_ctx_destroy (g_zmq_ctx);
	g_zmq_ctx = NULL;
}

static void callback_g_free(void *data, void *hint) {
	(void) hint;
	g_free(data);
}

int
rawx_event_send(const char *event_type, GString *data_json) {
	if (g_zmq_ctx == NULL)
		return 1;

	GString *json = g_string_sized_new(256);

	g_string_append_printf(json,
			"{"
			"\"event\":\"%s\","
			"\"when\":%"G_GINT64_FORMAT","
			"\"data\":%s"
			"}",
			event_type,
			g_get_real_time(),
			data_json->str);

	g_string_free(data_json, TRUE);

	return rawx_event_send_raw(json);
}

struct msg_header_s {
	guint32 random;
};
typedef struct msg_header_s msg_header_t;

static int
_init_header_part(zmq_msg_t *message) {
	msg_header_t *data = g_malloc(sizeof(msg_header_t));
	data->random = g_random_int();
	return zmq_msg_init_data(message, data, sizeof(msg_header_t),
			callback_g_free, NULL);
}

static int
_init_data_part(zmq_msg_t *message, GString *json) {
	int data_len = json->len;
	gchar *data = g_string_free(json, FALSE);
	return zmq_msg_init_data(message, data, data_len,
			callback_g_free, NULL);
}

int
rawx_event_send_raw(GString *json){
	int rc;

	if (g_zmq_ctx == NULL)
		return 1;

	void *sock = zmq_socket(g_zmq_ctx, ZMQ_REQ);
	if (sock == NULL) {
		return 0;
	}

	int opt = 1000;
	zmq_setsockopt(sock, ZMQ_LINGER, &opt, sizeof(opt));

	rc = zmq_connect(sock, g_event_addr);
	if (rc < 0) {
		zmq_close(sock);
		return 0;
	}

	zmq_msg_t header_part;
	rc = _init_header_part(&header_part);
	if (rc < 0) {
		zmq_close(sock);
		return 0;
	}

	rc = zmq_msg_send(&header_part, sock, ZMQ_SNDMORE);
	if (rc < 0) {
		zmq_msg_close(&header_part);
		zmq_close(sock);
		return 0;
	}

	zmq_msg_t data_part;
	rc = _init_data_part(&data_part, json);
	if (rc < 0) {
		zmq_msg_close(&header_part);
		zmq_close(sock);
		return 0;
	}

	rc = zmq_msg_send(&data_part, sock, 0);
	if (rc < 0) {
		zmq_msg_close(&data_part);
		zmq_msg_close(&header_part);
		zmq_close(sock);
		return 0;
	}

	/* We don't need the response */
	zmq_close(sock);

	return 1;
}
