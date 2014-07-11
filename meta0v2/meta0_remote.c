#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "meta0.remote"
#endif

#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include "./meta0_remote.h"

GSList *
meta0_remote_get_meta1_all(addr_info_t * meta0, gint ms, GError ** err)
{
	GSList *result = NULL;
	GError *e = NULL;

	gboolean on_reply(gpointer c1, MESSAGE reply) {
		void *body = NULL;
		gsize bsize = 0;
		(void) c1;
		if (0 < message_get_BODY(reply, &body, &bsize, NULL)) {
			if (0 >= meta0_info_unmarshall(&result, body, &bsize, &e)) {
				GSETERROR(err, "Decoder error (meta0_info_t)");
				return FALSE;
			}
		}
		return TRUE;
	}

	GByteArray *gba = message_marshall_gba_and_clean(message_create_request(
				NULL, NULL, NAME_MSGNAME_M0_GETALL, NULL, NULL));

	struct client_s *client = gridd_client_create_empty();
	e = gridd_client_request(client, gba, NULL, on_reply);
	g_byte_array_unref(gba);
	gba = NULL;

	if (!e) {
		if (!(e = gridd_client_connect_addr(client, meta0))) {
			gridd_client_set_timeout(client, ms, ms);
			gridd_client_start(client);
			if (!(e = gridd_client_loop(client)))
				e = gridd_client_error(client);
		}
	}

	if (e) {
		if (result) {
			g_slist_foreach(result, meta0_info_gclean, NULL);
			g_slist_free(result);
			result = NULL;
		}
		g_error_transmit(err, e);
	}

	gridd_client_free(client);
	return result;
}

GSList*
meta0_remote_get_meta1_one(addr_info_t *m0a, gint ms, const guint8 *prefix,
		GError ** err)
{
	GSList *result = NULL;
	GError *e = NULL;

	gboolean on_reply(gpointer c1, MESSAGE reply) {
		void *body = NULL;
		gsize bsize = 0;
		(void) c1;
		if (0 < message_get_BODY(reply, &body, &bsize, NULL)) {
			if (0 >= meta0_info_unmarshall(&result, body, &bsize, err)) {
				GSETERROR(err, "Decoder error (meta0_info_t)");
				return FALSE;
			}
		}
		return TRUE;
	}

	GByteArray *hdr = g_byte_array_append(g_byte_array_new(), prefix, 2);
	GByteArray *req = message_marshall_gba_and_clean(message_create_request(
			NULL, NULL, NAME_MSGNAME_M0_GETONE, NULL,
			"PREFIX", hdr,
			NULL));
	g_byte_array_unref(hdr);

	struct client_s *client = gridd_client_create_empty();
	e = gridd_client_request(client, req, NULL, on_reply);
	g_byte_array_unref(req);
	req = NULL;

	gscstat_tags_start(GSCSTAT_SERVICE_META0, GSCSTAT_TAGS_REQPROCTIME);

	if (!e) {
		if (!(e = gridd_client_connect_addr(client, m0a))) {
			gridd_client_set_timeout(client, ms, ms);
			gridd_client_start(client);
			if (!(e = gridd_client_loop(client)))
				e = gridd_client_error(client);
		}
	}

	gscstat_tags_end(GSCSTAT_SERVICE_META0, GSCSTAT_TAGS_REQPROCTIME);

	if (e) {
		if (result) {
			g_slist_foreach(result, meta0_info_gclean, NULL);
			g_slist_free(result);
			result = NULL;
		}
		g_error_transmit(err, e);
	}

	gridd_client_free(client);
	return result;
}

gint
meta0_remote_cache_refresh(addr_info_t *m0a, gint ms, GError ** err)
{
	GError *e = NULL;

	struct client_s *client = gridd_client_create_empty();

	GByteArray *gba = message_marshall_gba_and_clean(message_create_request(
				NULL, NULL, NAME_MSGNAME_M0_RELOAD, NULL, NULL));
	e = gridd_client_request(client, gba, NULL, NULL);
	g_byte_array_unref(gba);
	gba = NULL;

	gscstat_tags_start(GSCSTAT_SERVICE_META0, GSCSTAT_TAGS_REQPROCTIME);

	if (!e) {
		if (!(e = gridd_client_connect_addr(client, m0a))) {
			gridd_client_set_timeout(client, ms, ms);
			gridd_client_start(client);
			if (!(e = gridd_client_loop(client)))
				e = gridd_client_error(client);
		}
	}

	gscstat_tags_end(GSCSTAT_SERVICE_META0, GSCSTAT_TAGS_REQPROCTIME);

	if (e) {
		g_error_transmit(err, e);
		return FALSE;
	}

	return TRUE;
}

gint
meta0_remote_fill(addr_info_t *m0a, gint ms, gchar **urls,
		guint nbreplicas, GError **err)
{
	MESSAGE request = NULL;
	GError *local_err = NULL;
	struct client_s *client = NULL;
	gchar target[64];
	GByteArray *packed = NULL;

	if (nbreplicas < 1) {
		GSETERROR(err, "Too few replicas");
		return FALSE;
	}
	if (!urls || !*urls) {
		GSETERROR(err, "Too few URL's");
		return FALSE;
	}
	if (nbreplicas > g_strv_length(urls)) {
		GSETERROR(err, "Too many replicas for the URL's set");
		return FALSE;
	}
	gscstat_tags_start(GSCSTAT_SERVICE_META0, GSCSTAT_TAGS_REQPROCTIME);

	message_create(&request, NULL);
	message_set_NAME(request, NAME_MSGNAME_M0_FILL, sizeof(NAME_MSGNAME_M0_FILL)-1, NULL);
	do {
		gchar str[32];
		g_snprintf(str, sizeof(str), "%u", nbreplicas);
		message_add_field(request, "REPLICAS", sizeof("REPLICAS"), str, strlen(str), NULL);
	} while (0);
	do {
		gchar *body = g_strjoinv("\n", urls);
		message_set_BODY(request, body, strlen(body), NULL);
		g_free(body);
	} while (0);

	addr_info_to_string(m0a, target, sizeof(target));
	packed = message_marshall_gba(request, NULL);
	client = gridd_client_create(target, packed, NULL, NULL);
	if ( ms > 0 ) {
		gridd_client_set_timeout(client, ms, ms);
	}

	gridd_client_start(client);

	if((local_err = gridd_client_loop(client)) != NULL)
		goto end_label;
	if((local_err = gridd_client_error(client)) != NULL)
		goto end_label;

end_label:
	if (request)
		message_destroy(request, NULL);
	if (packed) 
		g_byte_array_free(packed, TRUE);

	gscstat_tags_end(GSCSTAT_SERVICE_META0, GSCSTAT_TAGS_REQPROCTIME);

	if (!local_err)
		return TRUE;

	*err = local_err;
	return FALSE;
}

gint
meta0_remote_fill_v2(addr_info_t *m0a, gint ms,
                guint nbreplicas, gboolean nodist, GError **err)
{
        MESSAGE request = NULL;
        GError *local_err = NULL;
	struct client_s *client = NULL;
	gchar target[64];
	GByteArray *packed = NULL;

        if (nbreplicas < 1) {
                GSETERROR(err, "Too few replicas");
                return FALSE;
        }

	gscstat_tags_start(GSCSTAT_SERVICE_META0, GSCSTAT_TAGS_REQPROCTIME);

        message_create(&request, NULL);
        message_set_NAME(request, NAME_MSGNAME_M0_V2_FILL, sizeof(NAME_MSGNAME_M0_V2_FILL)-1, NULL);
        do {
                gchar str[32];
                g_snprintf(str, sizeof(str), "%u", nbreplicas);
                message_add_field(request, "REPLICAS", sizeof("REPLICAS"), str, strlen(str), NULL);
        } while (0);
        do {
                gchar str[32];
                g_snprintf(str, sizeof(str), "%u", nodist);
                message_add_field(request, "NODIST", sizeof("NODIST"), str, strlen(str), NULL);
        } while (0);

	addr_info_to_string(m0a, target, sizeof(target));
	packed = message_marshall_gba(request, NULL);
	client = gridd_client_create(target, packed, NULL, NULL);
	if ( ms > 0 ) {
		gridd_client_set_timeout(client, ms, ms);
	}

	gridd_client_start(client);

	if((local_err = gridd_client_loop(client)) != NULL)
		goto end_label;
	if((local_err = gridd_client_error(client)) != NULL)
		goto end_label;

end_label:
	if (request)
		message_destroy(request, NULL);
	if (packed) 
		g_byte_array_free(packed, TRUE);

	gscstat_tags_end(GSCSTAT_SERVICE_META0, GSCSTAT_TAGS_REQPROCTIME);

	if (!local_err)
		return TRUE;

	*err = local_err;
	return FALSE;
}


gint
meta0_remote_assign(addr_info_t *m0a, gint ms, gboolean nocheck, GError **err)
{
        MESSAGE request = NULL;
        GError *local_err = NULL;
	struct client_s *client = NULL;
	gchar target[64];
	GByteArray *packed = NULL;

	gscstat_tags_start(GSCSTAT_SERVICE_META0, GSCSTAT_TAGS_REQPROCTIME);

	message_create(&request, NULL);
        message_set_NAME(request,NAME_MSGNAME_M0_ASSIGN,sizeof(NAME_MSGNAME_M0_ASSIGN)-1, NULL);
	if (nocheck) {
		gchar *str ="yes";
		message_add_field(request, "NOCHECK", sizeof("NOCHECK")-1, str, strlen(str), NULL);
	}
	
	addr_info_to_string(m0a, target, sizeof(target));
	packed = message_marshall_gba(request, NULL);
	client = gridd_client_create(target, packed, NULL, NULL);
	if ( ms > 0 ) {
		gridd_client_set_timeout(client, ms, ms);
	}

	gridd_client_start(client);

	if((local_err = gridd_client_loop(client)) != NULL) {
		goto end_label;
	}
	if((local_err = gridd_client_error(client)) != NULL)
		goto end_label;

end_label:
	if (request)
		message_destroy(request, NULL);
	if (packed) 
		g_byte_array_free(packed, TRUE);

	gscstat_tags_end(GSCSTAT_SERVICE_META0, GSCSTAT_TAGS_REQPROCTIME);
	if (!local_err)
		return TRUE;

	*err = local_err;
	return FALSE;
}	

gint
meta0_remote_disable_meta1(addr_info_t *m0a, gint ms, gchar **urls, gboolean nocheck, GError **err)
{
	MESSAGE request = NULL;
	GError *local_err = NULL;
	struct client_s *client = NULL;
	gchar target[64];
	GByteArray *packed = NULL;

	if (!urls || !*urls) {
		GSETERROR(err, "Too few URL's");
		return FALSE;
	}

	gscstat_tags_start(GSCSTAT_SERVICE_META0, GSCSTAT_TAGS_REQPROCTIME);

	message_create(&request, NULL);
	message_set_NAME(request, NAME_MSGNAME_M0_DISABLE_META1, sizeof(NAME_MSGNAME_M0_DISABLE_META1)-1, NULL);
	if (nocheck) {
		gchar *str ="yes";
		message_add_field(request, "NOCHECK", sizeof("NOCHECK")-1, str, strlen(str), NULL);
	}
	do {
		gchar *body = g_strjoinv("\n", urls);
		message_set_BODY(request, body, strlen(body), NULL);
		g_free(body);
	} while (0);
	addr_info_to_string(m0a, target, sizeof(target));
	packed = message_marshall_gba(request, NULL);
	client = gridd_client_create(target, packed, NULL, NULL);
	if ( ms > 0 ) {
		gridd_client_set_timeout(client, ms, ms);
	}

	gridd_client_start(client);

	if ((local_err = gridd_client_loop(client)) != NULL)
		goto end_label;
	if ((local_err = gridd_client_error(client)) != NULL)
		goto end_label;

end_label:
	if (request)
		message_destroy(request, NULL);
	if (packed)
		g_byte_array_free(packed, TRUE);

	gscstat_tags_end(GSCSTAT_SERVICE_META0, GSCSTAT_TAGS_REQPROCTIME);

	if (!local_err)
		return TRUE;

	*err = local_err;
	return FALSE;

}

gchar **
meta0_remote_get_meta1_info(addr_info_t *m0a, gint ms, GError **err)
{
	GError *local_err = NULL;
	gchar **result = NULL;
	MESSAGE request = NULL;
	struct client_s *client = NULL;
	gchar target[64];
	GByteArray *packed = NULL;

	gboolean on_reply(gpointer c1, MESSAGE reply) {
		void *body = NULL;
		gsize bsize = 0;
		(void) c1;

		if (0 < message_get_BODY(reply, &body, &bsize, NULL)) {
			gchar **tmpResult = NULL;
			tmpResult=metautils_decode_lines((gchar *)body , ((gchar *)body) + bsize);

			if (tmpResult) {
				guint len,resultlen,i;
				gchar **v0;
				if ( result != NULL )
					resultlen=g_strv_length(result);
				else
					resultlen=0;
				len = g_strv_length(tmpResult);
				v0 = g_realloc(result, sizeof(gchar*) * (len + resultlen+1));
				for ( i=0; i<len ; i++) {
					v0[resultlen+i] = g_strdup(tmpResult[i]);
				}
				v0[len+resultlen]=NULL;
				result = g_strdupv(v0);
				g_strfreev(v0);
				g_strfreev(tmpResult);
			}
		}
		return TRUE;
	}

	gscstat_tags_start(GSCSTAT_SERVICE_META0, GSCSTAT_TAGS_REQPROCTIME);

	request = message_create_request(NULL, NULL, NAME_MSGNAME_M0_GET_META1_INFO, NULL, NULL);
	addr_info_to_string(m0a, target, sizeof(target));
	packed = message_marshall_gba(request, NULL);
	client = gridd_client_create(target, packed, NULL, on_reply);
	if ( ms > 0 ) {
		gridd_client_set_timeout(client, ms, ms);
	}

	gridd_client_start(client);

	if((local_err = gridd_client_loop(client)) != NULL)
		goto end_label;
	if((local_err = gridd_client_error(client)) != NULL)
		goto end_label;

end_label:
	if (request)
		message_destroy(request, NULL);
	if (packed)
		g_byte_array_free(packed, TRUE);

	gscstat_tags_end(GSCSTAT_SERVICE_META0, GSCSTAT_TAGS_REQPROCTIME);

	if (local_err) {
		*err = local_err;
		if (result) {
			g_strfreev(result);
			result = NULL;
		}
	}
	return result;
}


gint
meta0_remote_destroy_meta1ref(addr_info_t *m0a, gint ms, gchar *urls, GError **err)
{
	MESSAGE request = NULL;
	GError *local_err = NULL;
	struct client_s *client = NULL;
	gchar target[64];
	GByteArray *packed = NULL;

	if (!urls || !*urls) {
		GSETERROR(err, "Too few URL's");
		return FALSE;
	}

	message_create(&request, NULL);
	message_set_NAME(request, NAME_MSGNAME_M0_DESTROY_META1REF, sizeof(NAME_MSGNAME_M0_DESTROY_META1REF)-1, NULL);

	message_add_field(request, "METAURL", sizeof("METAURL"), urls, strlen(urls), NULL);

	addr_info_to_string(m0a, target, sizeof(target));
	packed = message_marshall_gba(request, NULL);
	client = gridd_client_create(target, packed, NULL, NULL);
	if ( ms > 0 ) {
		gridd_client_set_timeout(client, ms, ms);
	}

	gridd_client_start(client);

	if((local_err = gridd_client_loop(client)) != NULL) {
		goto end_label;
	}
	if((local_err = gridd_client_error(client)) != NULL)
		goto end_label;

end_label:
	if (request)
		message_destroy(request, NULL);
	if (packed) 
		g_byte_array_free(packed, TRUE);

	if (local_err) {
		*err = local_err;
		return FALSE;
	}
	return TRUE;
}

gint
meta0_remote_destroy_meta0zknode(addr_info_t *m0a, gint ms, gchar *urls, GError **err)
{
	MESSAGE request = NULL;
	GError *local_err = NULL;
	struct client_s *client = NULL;
	gchar target[64];
	GByteArray *packed = NULL;

	if (!urls || !*urls) {
		GSETERROR(err, "Too few URL's");
		return FALSE;
	}

	message_create(&request, NULL);
	message_set_NAME(request, NAME_MSGNAME_M0_DESTROY_META0ZKNODE, sizeof(NAME_MSGNAME_M0_DESTROY_META0ZKNODE)-1, NULL);

	message_add_field(request, "METAURL", sizeof("METAURL"), urls, strlen(urls), NULL);

	addr_info_to_string(m0a, target, sizeof(target));
	packed = message_marshall_gba(request, NULL);
	client = gridd_client_create(target, packed, NULL, NULL);
	if ( ms > 0 ) {
		gridd_client_set_timeout(client, ms, ms);
	}

	gridd_client_start(client);

	if((local_err = gridd_client_loop(client)) != NULL) {
		goto end_label;
	}
	if((local_err = gridd_client_error(client)) != NULL)
		goto end_label;

end_label:
	if (request)
		message_destroy(request, NULL);
	if (packed) 
		g_byte_array_free(packed, TRUE);

	if (local_err) {
		*err = local_err;
		return FALSE;
	}
	return TRUE;
}

