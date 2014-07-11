#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "rawx.client.stats"
#endif

#include <metautils/lib/metautils.h>

#include "rawx_client_internals.h"

static void
_convert_string_to_double(gpointer key, gpointer value, gpointer data)
{
	gint64 value_i64;
	gdouble value_d;
	gchar* str_value;
	GHashTable *hash;

	str_value = value;
	hash = data;

	value_i64 = g_ascii_strtoll(str_value, NULL, 10);
	value_d = value_i64;
	g_hash_table_insert(hash, g_strdup(key), g_memdup(&value_d, sizeof(value_d)));
}

GHashTable *
rawx_client_get_statistics(rawx_session_t * session, GError ** err)
{
	int rc;
	gchar str_addr[64];
	gsize str_addr_size;
	GHashTable *parsed = NULL;
	GHashTable *result = NULL;
	GByteArray *buffer = NULL;
	ne_request *request = NULL;

	if (!session) {
		GSETERROR(err, "Invalid parameter");
		return NULL;
	}

	ne_set_connect_timeout(session->neon_session, session->timeout.cnx / 1000);
	ne_set_read_timeout(session->neon_session, session->timeout.req / 1000);
	request = ne_request_create(session->neon_session, "GET", "/stat");
	if (!request) {
		GSETERROR(err, "neon request creation error");
		return NULL;
	}

	buffer = g_byte_array_new();
	ne_add_response_body_reader(request, ne_accept_2xx, body_reader, buffer);

	switch (rc = ne_request_dispatch(request)) {
	case NE_OK:
		if (ne_get_status(request)->klass != 2) {
			GSETERROR(err, "RAWX returned an error");
		}
		else if (!(parsed = body_parser(buffer, err))) {
			GSETERROR(err, "No statistics from the RAWX server");
		}
		break;
	case NE_ERROR:
	case NE_TIMEOUT:
	case NE_CONNECT:
	case NE_AUTH:
		str_addr_size = addr_info_to_string(&(session->addr), str_addr, sizeof(str_addr));
		GSETERROR(err, "cannot download the stats from [%.*s]' (%s)",
		    str_addr_size, str_addr, ne_get_error(session->neon_session));
		break;
	default:
		GSETERROR(err, "Unexpected return code from the neon library : %d", rc);
		break;
	}

	g_byte_array_free(buffer, TRUE);
	ne_request_destroy(request);

	result = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	g_hash_table_foreach(parsed, _convert_string_to_double, result);
	g_hash_table_destroy(parsed);

	return result;
}
