#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "grid.snmp.session"
#endif

#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <neon/ne_basic.h>
#include <neon/ne_request.h>
#include <neon/ne_session.h>

#include <metautils/lib/metautils.h>

#include "session.h"

struct rawx_session_s
{
        GByteArray *request_id;
        addr_info_t addr;
        struct {
                gint cnx;
                gint req;
        } timeout;
        ne_session *neon_session;
};

static int
body_reader(void *userdata, const char *buf, size_t len)
{
	GByteArray *gba = userdata;
	if (buf && len)
		g_byte_array_append(gba, (const guint8*)buf, len);
	return 0;
}

static GHashTable *
body_parser(GByteArray * buffer, GError ** err)
{
	GHashTable *result = NULL;
	GRegex *stat_regex = NULL;
	GMatchInfo *match_info = NULL;

	g_byte_array_append(buffer, (const guint8*)"", 1);

	stat_regex = g_regex_new("^(\\S+)[ \\t]+(\\S+).*$",
			G_REGEX_MULTILINE | G_REGEX_RAW, G_REGEX_MATCH_NOTEMPTY, err);

	if (!stat_regex) {
		GSETERROR(err, "Regex compilation error");
		return NULL;
	}

	if (!g_regex_match(stat_regex, (const gchar*)buffer->data, G_REGEX_MATCH_NOTEMPTY, &match_info)) {
		GSETERROR(err, "Invalid stat from the RAWX");
		goto error_label;
	}

	result = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	if (!result) {
		GSETERROR(err, "Memory allocation failure");
		goto error_label;
	}

	do {
		if (!g_match_info_matches(match_info)) {
			GSETERROR(err, "Invalid matching");
			goto error_label;
		}
		else if (g_match_info_get_match_count(match_info) != 3) {
			GSETERROR(err, "Invalid matching, %d groups found", g_match_info_get_match_count(match_info));
			goto error_label;
		}
		else {
			gchar *str_key, *str_value;

			str_key = g_match_info_fetch(match_info, 1);
			str_value = g_match_info_fetch(match_info, 2);

			if (!str_key || !str_value) {
				GSETERROR(err, "Matching capture failure");
				if (str_value)
					g_free(str_value);
				if (str_key)
					g_free(str_key);
				if (result)
					g_hash_table_destroy(result);
				goto error_label;
			}

			g_hash_table_insert(result, str_key, str_value);
		}
	} while (g_match_info_next(match_info, NULL));

	g_match_info_free(match_info);
	g_regex_unref(stat_regex);

	return result;

error_label:
	if (match_info)
		g_match_info_free(match_info);
	if (result)
		g_hash_table_destroy(result);
	g_regex_unref(stat_regex);

	return NULL;
}

rawx_session_t* rawx_client_create_session( addr_info_t *ai, GError **err )
{
	struct sockaddr_storage ss;
	gsize ss_size = sizeof(ss);
	gchar host[256], port[16];
	rawx_session_t *session;

	session = g_try_malloc0( sizeof(rawx_session_t) );
	if (!session) {
		GSETERROR(err,"Memory allocation failure");
		goto error_session;
	}

	memcpy( &(session->addr), ai, sizeof(addr_info_t) );

	if (!addrinfo_to_sockaddr( ai, (struct sockaddr*)&ss, &ss_size )) {
		GSETERROR(err,"addr_info_t conversion error");
		goto error_addr;
	}

	memset( host, 0x00, sizeof(host) );
	memset( port, 0x00, sizeof(port) );

	if (getnameinfo ( (struct sockaddr* )&ss, ss_size, host, sizeof(host), port, sizeof(port), NI_NUMERICHOST|NI_NUMERICSERV)) {
		GSETERROR(err,"addr_info_t resolution error : %s", strerror(errno));
		goto error_addr;
	}

	session->neon_session = ne_session_create ("http", host, atoi(port));
	if (!session->neon_session) {
		GSETERROR(err,"neon session creation error");
		goto error_neon;
	}

	session->timeout.cnx = 60000;
	session->timeout.req = 60000;

	ne_set_connect_timeout (session->neon_session, session->timeout.cnx/1000);
	ne_set_read_timeout (session->neon_session, session->timeout.req/1000);

	return session;

error_neon:
error_addr:
	g_free(session);
error_session:
	return NULL;
}

void rawx_client_free_session( rawx_session_t *session )
{
	if (!session)
		return;
	ne_session_destroy( session->neon_session );
	memset( session, 0x00, sizeof(rawx_session_t) );
	g_free( session );
}

void rawx_client_session_set_timeout( rawx_session_t *session, gint cnx, gint req )
{
	if (!session)
		return;
	if (req>0) session->timeout.req = req;
	if (cnx>0) session->timeout.cnx = cnx;
}

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
rawx_client_get_statistics(rawx_session_t * session, const gchar *url, GError ** err)
{
	int rc;
	gchar str_addr[64];
	gsize str_addr_size;
	GHashTable *parsed = NULL;
	GHashTable *result = NULL;
	GByteArray *buffer = NULL;
	ne_request *request = NULL;

	if (!session || !url) {
		GSETERROR(err, "Invalid parameter");
		return NULL;
	}

	ne_set_connect_timeout(session->neon_session, session->timeout.cnx / 1000);
	ne_set_read_timeout(session->neon_session, session->timeout.req / 1000);
	request = ne_request_create(session->neon_session, "GET", url);
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
			goto exit;
		}
		else if (!(parsed = body_parser(buffer, err))) {
			GSETERROR(err, "No statistics from the RAWX server");
			goto exit;
		}
		break;
	case NE_ERROR:
	case NE_TIMEOUT:
	case NE_CONNECT:
	case NE_AUTH:
		str_addr_size = addr_info_to_string(&(session->addr), str_addr, sizeof(str_addr));
		GSETERROR(err, "cannot download the stats from [%.*s]' (%s)",
		    str_addr_size, str_addr, ne_get_error(session->neon_session));
		goto exit;
	default:
		GSETERROR(err, "Unexpected return code from the neon library : %d", rc);
		goto exit;
	}

	result = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	g_hash_table_foreach(parsed, _convert_string_to_double, result);

exit:
	if (buffer != NULL)
		g_byte_array_free(buffer, TRUE);
	if (request != NULL)
		ne_request_destroy(request);
	if (parsed != NULL)
		g_hash_table_destroy(parsed);

	return result;
}

