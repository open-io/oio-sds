#include <stdio.h>
#include <glib.h>

#include <metautils/lib/metautils.h>

#include "bench_conf.h"
#include "manage_events_queue.h"
#include "send_events.h"

#define STORAGE_CHUNK_NEW "storage.chunk.new"
#define STORAGE_CHUNK_DELETED "storage.chunk.deleted"
#define STORAGE_CONTAINER_NEW "storage.container.new"
#define STORAGE_CONTAINER_STATE "storage.container.state"
#define STORAGE_CONTENT_DELETED "storage.content.deleted"

#define CONTENT_VERSION "1498665033873808"

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

gint n_events_per_round = 10;
gint rounds = 1;
gint increment = 10;

gint64 reception_time = 0;
gint n_errors = 0;
gdouble speed = 0.0;

static gint total_errors = 0;
static gdouble total_speed = 0.0;

enum event_type_e event_type = CHUNK_NEW;
static const char *type = STORAGE_CHUNK_NEW;

static gboolean
init_send_event()
{
	gchar *event_agent_addr = oio_cfg_get_eventagent(NAME_SPACE);
	GError *err = manage_events_queue_init(event_agent_addr);
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

	guint32 l_str = (n_bits / 4);
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

		// _PAIR_AND_COMMA("content_size", resource->info->chunk.content_size);
		// _PAIR_AND_COMMA("content_nbchunks", resource->info->chunk.content_chunk_nb);
		// _PAIR_AND_COMMA("content_mime_type", resource->info->chunk.content_mime_type);
		// _PAIR_AND_COMMA("metachunk_size", resource->info->chunk.metachunk_size);
		// _PAIR_AND_COMMA("metachunk_hash", resource->info->chunk.metachunk_hash);

		if (event_type == CHUNK_DELETED) {
			GString *chunk_hash = _random_hex(128);
			_PAIR_AND_COMMA("chunk_hash", chunk_hash->str);
			g_string_free(chunk_hash, TRUE);

			_PAIR_AND_COMMA("chunk_size", "111");
		}
		
		g_string_append_c(data_json, '}');
	} else if (event_type == CONTAINER_NEW || event_type == CONTAINER_STATE) {
		url = oio_url_empty();
		
		oio_url_set(url, OIOURL_ACCOUNT, "account");
		
		oio_url_set(url, OIOURL_NS, NAME_SPACE);
		
		oio_url_set(url, OIOURL_USER, "container");
		
		if (event_type == CONTAINER_NEW) {
			oio_url_set(url, OIOURL_PATH, "test.txt");
			
			size_t id_size = oio_url_get_id_size(url);
			guint8 id[id_size];
			oio_buf_randomize(id, id_size);
			oio_url_set_id(url, id);
		} else {
			data_json = g_string_sized_new(512);

			g_string_append_c(data_json, '{');
			
			_PAIR_AND_COMMA("policy", NULL);
			
			_PAIR_AND_COMMA_INT("bytes-count", 111);
			
			_PAIR_AND_COMMA_INT("object-count", 1);
			
			_PAIR_AND_COMMA_INT("ctime", oio_ext_real_time());
			
			g_string_append_c(data_json, '}');
		}
	} else if (event_type == CONTENT_DELETED) {
		url = oio_url_empty();
		
		oio_url_set(url, OIOURL_ACCOUNT, "account");
		
		oio_url_set(url, OIOURL_NS, NAME_SPACE);
		
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

	GError *err = manage_events_queue_send(type, url, data_json);
	if (err) {
		GRID_ERROR("Event KO %s: (%d) %s\n", type, err->code, err->message);
		g_clear_error(&err);

		n_errors++;
	}
	
	oio_url_clean(url);
}

static void
send_events()
{
	n_errors = 0;
	fake_service_ready = FALSE;
	
	// Wait the stabilization of the fake_service
	g_usleep(G_TIME_SPAN_SECOND);
	
	reception_time = g_get_monotonic_time();
	
	for (gint i = 0; i < n_events_per_round; i++) {
		if (!grid_main_is_running()) {
			return;
		}
		
		send_event();
	}
	
	// Wait the reception of events
	while (!fake_service_ready) {
		if (!grid_main_is_running()) {
			return;
		}
		
        g_usleep(G_TIME_SPAN_SECOND);
	}
}

// Main callbacks

void
send_events_defaults(void)
{
	n_events_per_round = 10;
	rounds = 1;
	increment = 10;
}

gboolean
send_events_configure(char *event_type_str)
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
	} else if (g_strcmp0(event_type_str, "CONTENT_DELETED") == 0) {
		event_type = CONTENT_DELETED;
		type = STORAGE_CONTENT_DELETED;
	} else {
		return FALSE;
	}

	return TRUE;
}

void
send_events_run(void)
{
	if (!init_send_event()) {
		grid_main_set_status(2);
		return;
	}
	
	// Wait the start of the fake_service
	while (!fake_service_ready) {
		if (!grid_main_is_running()) {
			return;
		}
		
        g_usleep(G_TIME_SPAN_SECOND);
	}
	
	while (TRUE) {
		total_errors = 0;
		total_speed = 0.0;
		
		for (gint i = 0; i < rounds; i++) {
			if (!grid_main_is_running()) {
				return;
			}
			
			send_events();
			
			total_errors += n_errors;
			total_speed += speed;
		}
		
		if (!grid_main_is_running()) {
			return;
		}
		
		printf("Events: %d, Errors: %d, Events/sec: %f\n", n_events_per_round,
			   total_errors, total_speed / rounds);
		
		n_events_per_round += increment;
	}
}

void
send_events_fini(void)
{
	manage_events_queue_destroy();
}
