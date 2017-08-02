/*
OpenIO SDS oio-event-benchmark
Copyright (C) 2017 OpenIO, as part of OpenIO SDS

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <glib.h>

#include <metautils/lib/metautils.h>

#include "event_benchmark.h"
#include "event_worker.h"
#include "event_sender.h"
#include "fake_service.h"

#define STORAGE_CHUNK_NEW "storage.chunk.new"
#define STORAGE_CHUNK_DELETED "storage.chunk.deleted"
#define STORAGE_CONTAINER_NEW "storage.container.new"
#define STORAGE_CONTAINER_STATE "storage.container.state"
#define STORAGE_CONTAINER_DELETED "storage.container.deleted"
#define STORAGE_CONTENT_DELETED "storage.content.deleted"

#define CONTENT_VERSION "1498665033873808"
#define MIN_SENT_EVENTS 100

#define _PAIR_AND_COMMA(KEY,VAL) if (VAL) { \
	g_string_append_c(data_json, ','); \
	oio_str_gstring_append_json_pair(data_json, KEY, VAL); \
}

#define _PAIR_AND_COMMA_INT(KEY,VAL) if (VAL) { \
	g_string_append_c(data_json, ','); \
	oio_str_gstring_append_json_pair_int(data_json, KEY, VAL); \
}

#define _PAIR_AND_COMMA_BOOLEAN(KEY,VAL) if (VAL) { \
	g_string_append_c(data_json, ','); \
	oio_str_gstring_append_json_pair_boolean(data_json, KEY, VAL); \
}

extern gboolean fake_service_ready;
extern gchar namespace[LIMIT_LENGTH_NSNAME];

gint sent_events = MIN_SENT_EVENTS;
gint64 reception_time = 0;
gint errors = 0;
gdouble speed = 0.0;
gint64 max_waiting = 10000000;

enum event_type_e event_type = CHUNK_NEW;
static const char *type = STORAGE_CHUNK_NEW;

static gboolean
event_sender_init()
{
	gchar *event_agent_addr = oio_cfg_get_eventagent(namespace);
	GError *err = event_worker_init(event_agent_addr);
	g_free(event_agent_addr);
	if (err) {
		GRID_ERROR("Failed to initialize event context: (%d) %s", err->code,
				err->message);
		g_clear_error(&err);

		return FALSE;
	}

	return TRUE;
}

/* The returned value must be free after use */
static GString *
_random_hex(guint32 n_bits)
{
	guint32 n_bytes = n_bits / 8;
	if (n_bits % 8 != 0) {
		n_bytes++;
	}
	guint8 buff[n_bytes];
	oio_buf_randomize(buff, n_bytes);

	guint32 l_str = n_bits / 4;
	if (n_bits % 4 != 0) {
		l_str++;
	}
	GString *hex = g_string_sized_new(l_str);
	oio_str_bin2hex(buff, n_bytes, hex->str, l_str);

	return hex;
}

static void
send_event()
{
	struct oio_url_s *url = NULL;
	GString *data_json = NULL;

	if (event_type == CHUNK_NEW || event_type == CHUNK_DELETED) {
		data_json = g_string_sized_new(512);
		g_string_append_c(data_json, '{');

		oio_str_gstring_append_json_pair(data_json, "volume_id", RAWX_ADDRESS);
		GString *container_id = _random_hex(256);
		_PAIR_AND_COMMA("container_id", container_id->str);
		g_string_free(container_id, TRUE);
		GString *content_id = _random_hex(128);
		_PAIR_AND_COMMA("content_id", content_id->str);
		g_string_free(content_id, TRUE);
		_PAIR_AND_COMMA("content_path", "test.txt");
		_PAIR_AND_COMMA("content_version", CONTENT_VERSION);
		_PAIR_AND_COMMA("content_storage_policy", "THREECOPIES");
		_PAIR_AND_COMMA("content_chunk_method", "plain/nb_copy=3");
		GString *chunk_id = _random_hex(256);
		_PAIR_AND_COMMA("chunk_id", chunk_id->str);
		g_string_free(chunk_id, TRUE);
		_PAIR_AND_COMMA("chunk_position", "0");

		if (event_type == CHUNK_DELETED) {
			GString *chunk_hash = _random_hex(128);
			_PAIR_AND_COMMA("chunk_hash", chunk_hash->str);
			g_string_free(chunk_hash, TRUE);
			_PAIR_AND_COMMA("chunk_size", "111");
		}

		g_string_append_c(data_json, '}');
	} else if (event_type == CONTAINER_NEW || event_type == CONTAINER_STATE
			|| event_type == CONTAINER_DELETED) {
		url = oio_url_empty();

		oio_url_set(url, OIOURL_ACCOUNT, "account");
		oio_url_set(url, OIOURL_NS, namespace);
		oio_url_set(url, OIOURL_USER, "container");

		if (event_type == CONTAINER_NEW) {
			oio_url_set(url, OIOURL_PATH, "test.txt");
			size_t id_size = oio_url_get_id_size(url);
			guint8 id[id_size];
			oio_buf_randomize(id, id_size);
			oio_url_set_id(url, id);
		} else if (event_type == CONTAINER_STATE) {
			data_json = g_string_sized_new(512);
			g_string_append_c(data_json, '{');

			oio_str_gstring_append_json_pair(data_json, "policy", NULL);
			_PAIR_AND_COMMA_INT("bytes-count", 111);
			_PAIR_AND_COMMA_INT("object-count", 1);
			_PAIR_AND_COMMA_INT("ctime", oio_ext_real_time());

			g_string_append_c(data_json, '}');
		} else {
			size_t id_size = oio_url_get_id_size(url);
			guint8 id[id_size];
			oio_buf_randomize(id, id_size);
			oio_url_set_id(url, id);
		}
	} else if (event_type == CONTENT_DELETED) {
		url = oio_url_empty();
		oio_url_set(url, OIOURL_ACCOUNT, "account");
		oio_url_set(url, OIOURL_NS, namespace);
		oio_url_set(url, OIOURL_USER, "container");
		oio_url_set(url, OIOURL_PATH, "test.txt");
		size_t id_size = oio_url_get_id_size(url);
		guint8 id[id_size];
		oio_buf_randomize(id, id_size);
		oio_url_set_id(url, id);

		data_json = g_string_sized_new(512);
		g_string_append_static(data_json, "[{");

		GString *hash = _random_hex(128);
		oio_str_gstring_append_json_pair(data_json, "hash", hash->str);
		_PAIR_AND_COMMA_INT("size", 111);
		_PAIR_AND_COMMA("type", "chunks");
		_PAIR_AND_COMMA("id", "http://" FAKE_SERVICE_ADDRESS "/rawx");
		_PAIR_AND_COMMA("pos", "0");

		g_string_append_static(data_json, "},{");

		oio_str_gstring_append_json_pair(data_json, "hash", hash->str);
		g_string_free(hash, TRUE);
		_PAIR_AND_COMMA("mime-type", OIO_DEFAULT_MIMETYPE);
		_PAIR_AND_COMMA("chunk-method", "plain/nb_copy=3");
		_PAIR_AND_COMMA("policy", "THREECOPIES");
		_PAIR_AND_COMMA("type", "contents_headers");
		GString *data_id = _random_hex(128);
		_PAIR_AND_COMMA("id", data_id->str);
		g_string_free(data_id, TRUE);
		_PAIR_AND_COMMA_INT("size", 111);
		g_string_append_static(data_json, "},{");
		oio_str_gstring_append_json_pair(data_json, "name", "test.txt");
		_PAIR_AND_COMMA_BOOLEAN("deleted", FALSE);
		GString *header = _random_hex(128);
		_PAIR_AND_COMMA("header", header->str);
		g_string_free(header, TRUE);
		_PAIR_AND_COMMA_INT("version", g_ascii_strtoll(CONTENT_VERSION, NULL, 10));
		gint64 ctime = oio_ext_real_time();
		_PAIR_AND_COMMA_INT("mtime", ctime);
		_PAIR_AND_COMMA("type", "aliases");
		_PAIR_AND_COMMA_INT("ctime", ctime);

		g_string_append_static(data_json, "}]");
	}

	GError *err = event_worker_send(type, url, data_json);
	if (err) {
		GRID_ERROR("Event KO %s: (%d) %s\n", type, err->code, err->message);
		g_clear_error(&err);
		errors++;
	}
}

static void
send_events()
{
	errors = 0;
	fake_service_ready = FALSE;

	reception_time = g_get_monotonic_time();

	for (gint i = 0; i < sent_events; i++) {
		if (!grid_main_is_running()) {
			return;
		}

		send_event();
	}
}

// Main callbacks

gboolean
event_sender_configure(char *event_type_str)
{
	if (g_strcmp0(event_type_str, "CHUNK_NEW") == 0) {
		event_type = CHUNK_NEW;
		type = STORAGE_CHUNK_NEW;
	} else if (g_strcmp0(event_type_str, "CHUNK_DELETED") == 0) {
		event_type = CHUNK_DELETED;
		type = STORAGE_CHUNK_DELETED;
	} else if (g_strcmp0(event_type_str, "CONTAINER_NEW") == 0) {
		event_type = CONTAINER_NEW;
		type = STORAGE_CONTAINER_NEW;
	} else if (g_strcmp0(event_type_str, "CONTAINER_STATE") == 0) {
		event_type = CONTAINER_STATE;
		type = STORAGE_CONTAINER_STATE;
	} else if (g_strcmp0(event_type_str, "CONTAINER_DELETED") == 0) {
		event_type = CONTAINER_DELETED;
		type = STORAGE_CONTAINER_DELETED;
	} else if (g_strcmp0(event_type_str, "CONTENT_DELETED") == 0) {
		event_type = CONTENT_DELETED;
		type = STORAGE_CONTENT_DELETED;
	} else {
		return FALSE;
	}

	return TRUE;
}

gboolean
event_sender_run(void)
{
	if (!event_sender_init()) {
		return FALSE;
	}

	while (TRUE) {
		if (!grid_main_is_running()) {
			return TRUE;
		}

		while (!fake_service_ready) {
			if (reception_time != 0 &&
					(g_get_monotonic_time() - reception_time) > max_waiting) {
				fake_service_too_long();
				speed = 0.0;
				break;
			}

			if (!grid_main_is_running()) {
				return TRUE;
			}

			g_usleep(G_TIME_SPAN_MILLISECOND);
		}

		if (speed >= 1.0) {
			sent_events = (gint) speed;
		} else {
			sent_events = MIN_SENT_EVENTS;
		}
		printf("Sending %d fake events\n", sent_events);
		send_events();
	}
}

void
event_sender_fini(void)
{
	event_worker_destroy();
}
