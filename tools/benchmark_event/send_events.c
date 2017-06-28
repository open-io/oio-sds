#include <stdio.h>
#include <glib.h>

#include <metautils/lib/metautils.h>
#include <rawx-apache2/src/rawx_event.h>

#include "bench_conf.h"
#include "send_events.h"

#define STORAGE_CHUNK_NEW "storage.chunk.new"
#define STORAGE_CHUNK_DELETE "storage.chunk.deleted"

enum event_type_e {
	CHUNK_NEW,
	CHUNK_DELETE
};

#define _PAIR_AND_COMMA(KEY,VAL) if (VAL) { \
	g_string_append_c(json, ','); \
	oio_str_gstring_append_json_pair(json, KEY, VAL); \
}

extern gboolean fake_service_ready;

gint n_events_per_exp = 10;
gint n_experiences = 1;

gint64 reception_time = 0;
gint n_errors = 0;
gdouble speed = 0.0;

static gint total_errors = 0;
static gdouble total_speed = 0.0;

static enum event_type_e event_type = CHUNK_NEW;
static const char *type = STORAGE_CHUNK_NEW;

static gboolean
init_send_event()
{
	gchar *event_agent_addr = oio_cfg_get_eventagent(NAME_SPACE);
	GError *err = rawx_event_init(event_agent_addr);
	g_free(event_agent_addr);
	if (err) {
		GRID_INFO("Failed to initialize event context: (%d) %s", err->code,
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
	GString *json = g_string_sized_new(512);

	g_string_append_c(json, '{');

	oio_str_gstring_append_json_pair(json, "volume_id", RAWX_ADDRESS);

	GString *container_id = _random_hex(256);
	_PAIR_AND_COMMA("container_id", container_id->str);
	g_string_free(container_id, TRUE);

	GString *content_id = _random_hex(128);
	_PAIR_AND_COMMA("content_id", content_id->str);
	g_string_free(content_id, TRUE);

	_PAIR_AND_COMMA("content_path", "test.txt");

	GString *content_version = _random_hex(64);
	_PAIR_AND_COMMA("content_version",content_version->str);
	g_string_free(content_version, TRUE);

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

	if (event_type == CHUNK_DELETE) {
		GString *chunk_hash = _random_hex(128);
		_PAIR_AND_COMMA("chunk_hash", chunk_hash->str);
		g_string_free(chunk_hash, TRUE);

		_PAIR_AND_COMMA("chunk_size", "111");
	}

	g_string_append_c(json, '}');

	GError *err = rawx_event_send(type, json);
	if (err) {
		GRID_INFO("Event KO %s: (%d) %s\n", type, err->code, err->message);
		g_clear_error(&err);

		n_errors++;
	}
}

static void
send_events()
{
	n_errors = 0;
	fake_service_ready = FALSE;
	
	// Wait the stabilization of the fake_service
	g_usleep(G_TIME_SPAN_SECOND);
	
	reception_time = g_get_monotonic_time();
	
	for (gint i = 0; i < n_events_per_exp; i++) {
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
	n_events_per_exp = 10;
	n_experiences = 1;
}

gboolean
send_events_configure(int argc, char **argv)
{
	if (argc < 1) {
		g_printerr("Invalid arguments number\n");
		return FALSE;
	}

	if (g_strcmp0(argv[0], "CHUNK_NEW") == 0) {
		event_type = CHUNK_NEW;
		type = STORAGE_CHUNK_NEW;
	} else if (g_strcmp0(argv[0], "CHUNK_DELETE") == 0) {
		event_type = CHUNK_DELETE;
		type = STORAGE_CHUNK_DELETE;
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
		
		for (gint i = 0; i < n_experiences; i++) {
			if (!grid_main_is_running()) {
				return;
			}
			
			send_events();
			
			total_errors += n_errors;
			total_speed += speed;
		}
		
		printf("Events: %d, Errors: %d, Events/sec: %f\n", n_events_per_exp, total_errors, total_speed / n_experiences);
		
		n_events_per_exp += 10;
	}
}

void
send_events_fini(void)
{
	rawx_event_destroy();
}
