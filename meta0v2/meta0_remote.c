/*
OpenIO SDS meta0v2
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#include "meta0_remote.h"
#include "internals.h"

static gboolean
_m0_remote_no_return (addr_info_t *m0a, gint ms, GByteArray *req, GError **err)
{
	EXTRA_ASSERT (m0a != NULL);
	gchar addr[STRLEN_ADDRINFO];
	addr_info_to_string (m0a, addr, STRLEN_ADDRINFO);

	GError *e = gridd_client_exec (addr, ms>0 ? ms/1000.0 : 60.0, req);
	if (!e)
		return TRUE;
	g_error_transmit(err, e);
	return FALSE;
}

static GSList *
_m0_remote_m0info (addr_info_t *m0a, gint ms, GByteArray *req, GError **err)
{
	EXTRA_ASSERT (m0a != NULL);
	gchar addr[STRLEN_ADDRINFO];
	addr_info_to_string (m0a, addr, STRLEN_ADDRINFO);

	GSList *result = NULL;
	GError *e = gridd_client_exec_and_decode (addr, ms>0 ? ms/1000.0 : 60.0, req,
			&result, meta0_info_unmarshall);

	if (!e)
		return result;
	g_slist_free_full (result, (GDestroyNotify)meta0_info_clean);
	g_error_transmit(err, e);
	return NULL;
}

/* ------------------------------------------------------------------------- */

GSList *
meta0_remote_get_meta1_all(addr_info_t *m0a, gint ms, GError ** err)
{
	GByteArray *req = message_marshall_gba_and_clean (
			metautils_message_create_named (NAME_MSGNAME_M0_GETALL));
	return _m0_remote_m0info (m0a, ms, req, err);
}

GSList*
meta0_remote_get_meta1_one(addr_info_t *m0a, gint ms, const guint8 *prefix,
		GError ** err)
{
	GByteArray *hdr = g_byte_array_append(g_byte_array_new(), prefix, 2);
	MESSAGE request = metautils_message_create_named (NAME_MSGNAME_M0_GETONE);
	metautils_message_add_fields_gba (request, NAME_MSGKEY_PREFIX, hdr, NULL);
	GByteArray *req = message_marshall_gba_and_clean (request);
	g_byte_array_unref(hdr);
	return _m0_remote_m0info (m0a, ms, req, err);
}

gint
meta0_remote_cache_refresh(addr_info_t *m0a, gint ms, GError ** err)
{
	GByteArray *gba = message_marshall_gba_and_clean (
			metautils_message_create_named (NAME_MSGNAME_M0_RELOAD));
	return _m0_remote_no_return (m0a, ms, gba, err);
}

gint
meta0_remote_fill(addr_info_t *m0a, gint ms, gchar **urls,
		guint nbreplicas, GError **err)
{
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

	MESSAGE request = metautils_message_create_named(NAME_MSGNAME_M0_FILL);
	metautils_message_add_field_strint64(request, NAME_MSGKEY_REPLICAS, nbreplicas);
	gchar *body = g_strjoinv("\n", urls);
	metautils_message_set_BODY(request, body, strlen(body));
	g_free(body);
	return _m0_remote_no_return (m0a, ms, message_marshall_gba_and_clean(request), err);
}

gint
meta0_remote_fill_v2(addr_info_t *m0a, gint ms,
                guint nbreplicas, gboolean nodist, GError **err)
{
	if (nbreplicas < 1) {
		GSETERROR(err, "Too few replicas");
		return FALSE;
	}

	MESSAGE request = metautils_message_create_named(NAME_MSGNAME_M0_V2_FILL);
	metautils_message_add_field_strint64(request, NAME_MSGKEY_REPLICAS, nbreplicas);
	metautils_message_add_field_strint(request, NAME_MSGKEY_NODIST, nodist);
	return _m0_remote_no_return (m0a, ms, message_marshall_gba_and_clean(request), err);
}

gint
meta0_remote_assign(addr_info_t *m0a, gint ms, gboolean nocheck, GError **err)
{
	MESSAGE request = metautils_message_create_named(NAME_MSGNAME_M0_ASSIGN);
	if (nocheck)
		metautils_message_add_field_str (request, NAME_MSGKEY_NOCHECK, "yes");
	return _m0_remote_no_return (m0a, ms, message_marshall_gba_and_clean(request), err);
}

gint
meta0_remote_disable_meta1(addr_info_t *m0a, gint ms, gchar **urls, gboolean nocheck, GError **err)
{
	if (!urls || !*urls) {
		GSETERROR(err, "Too few URL's");
		return FALSE;
	}

	MESSAGE request = metautils_message_create_named(NAME_MSGNAME_M0_DISABLE_META1);
	if (nocheck)
		metautils_message_add_field_str(request, NAME_MSGKEY_NOCHECK, "yes");
	gchar *body = g_strjoinv("\n", urls);
	metautils_message_set_BODY(request, body, strlen(body));
	g_free(body);
	return _m0_remote_no_return (m0a, ms, message_marshall_gba_and_clean(request), err);
}

gint
meta0_remote_destroy_meta1ref(addr_info_t *m0a, gint ms, gchar *urls, GError **err)
{
	if (!urls || !*urls) {
		GSETERROR(err, "Too few URL's");
		return FALSE;
	}

	MESSAGE request = metautils_message_create_named(NAME_MSGNAME_M0_DESTROY_META1REF);
	metautils_message_add_field_str (request, NAME_MSGKEY_METAURL, urls);
	return _m0_remote_no_return (m0a, ms, message_marshall_gba_and_clean(request), err);
}

gint
meta0_remote_destroy_meta0zknode(addr_info_t *m0a, gint ms, gchar *urls, GError **err)
{
	if (!urls || !*urls) {
		GSETERROR(err, "Too few URL's");
		return FALSE;
	}

	MESSAGE request = metautils_message_create_named(NAME_MSGNAME_M0_DESTROY_META0ZKNODE);
	metautils_message_add_field_str (request, NAME_MSGKEY_METAURL, urls);
	return _m0_remote_no_return (m0a, ms, message_marshall_gba_and_clean(request), err);
}

gchar **
meta0_remote_get_meta1_info(addr_info_t *m0a, gint ms, GError **err)
{
	GError *e = NULL;
	gchar **result = NULL;
	struct gridd_client_s *client = NULL;
	gchar target[64];

	gboolean on_reply(gpointer c1, MESSAGE reply) {
		(void) c1;

		gchar **tmpResult = NULL;
		if (NULL != (e = metautils_message_extract_body_strv (reply, &tmpResult))) {
			GRID_WARN("GetMeta1Info : invalid reply");
			g_clear_error (&e);
			return FALSE;
		}
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
		return TRUE;
	}

	MESSAGE request = metautils_message_create_named(NAME_MSGNAME_M0_GET_META1_INFO);
	GByteArray *packed = message_marshall_gba_and_clean(request);

	addr_info_to_string(m0a, target, sizeof(target));

	client = gridd_client_create(target, packed, NULL, on_reply);
	if ( ms > 0 )
		gridd_client_set_timeout(client, ms, ms);
	e = gridd_client_run (client);
	g_byte_array_free(packed, TRUE);

	if (e) {
		*err = e;
		if (result) {
			g_strfreev(result);
			result = NULL;
		}
	}
	return result;
}

