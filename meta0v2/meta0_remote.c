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

#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <metautils/lib/metautils.h>

#include "meta0_remote.h"
#include "internals.h"

static GError *
_m0_remote_no_return (const char *m0, GByteArray *req)
{
	EXTRA_ASSERT (m0 != NULL);
	return gridd_client_exec (m0, M0V2_CLIENT_TIMEOUT, req);
}

static GError *
_m0_remote_m0info (const char *m0, GByteArray *req, GSList **out)
{
	EXTRA_ASSERT (m0 != NULL);
	EXTRA_ASSERT (out != NULL);
	GSList *result = NULL;
	GError *e = gridd_client_exec_and_decode (m0, M0V2_CLIENT_TIMEOUT,
			req, &result, meta0_info_unmarshall);
	if (!e) {
		*out = result;
		return NULL;
	} else {
		g_slist_free_full (result, (GDestroyNotify)meta0_info_clean);
		*out = NULL;
		return e;
	}
}

/* ------------------------------------------------------------------------- */

GError *
meta0_remote_get_meta1_all(const char *m0, GSList **out)
{
	GByteArray *req = message_marshall_gba_and_clean (
			metautils_message_create_named (NAME_MSGNAME_M0_GETALL));
	return _m0_remote_m0info (m0, req, out);
}

GError*
meta0_remote_get_meta1_one(const char *m0, const guint8 *prefix,
		GSList **out)
{
	MESSAGE request = metautils_message_create_named (NAME_MSGNAME_M0_GETONE);
	metautils_message_add_field (request, NAME_MSGKEY_PREFIX, prefix, 2);
	return _m0_remote_m0info (m0, message_marshall_gba_and_clean (request), out);
}

GError*
meta0_remote_cache_refresh(const char *m0)
{
	GByteArray *gba = message_marshall_gba_and_clean (
			metautils_message_create_named (NAME_MSGNAME_M0_RELOAD));
	return _m0_remote_no_return (m0, gba);
}

GError *
meta0_remote_cache_reset (const char *m0, gboolean local)
{
	MESSAGE req = metautils_message_create_named (NAME_MSGNAME_M0_RESET);
	if (local)
		metautils_message_add_field_struint(req, NAME_MSGKEY_LOCAL, 1);
	return _m0_remote_no_return (m0, message_marshall_gba_and_clean (req));
}

GError*
meta0_remote_fill(const char *m0, gchar **urls, guint nbreplicas)
{
	if (nbreplicas < 1)
		return NEWERROR(CODE_BAD_REQUEST, "Too few replicas");
	if (!urls || !*urls)
		return NEWERROR(CODE_BAD_REQUEST, "Too few URL's");
	if (nbreplicas > g_strv_length(urls))
		return NEWERROR(CODE_BAD_REQUEST, "Too many replicas for the URL's set");

	MESSAGE request = metautils_message_create_named(NAME_MSGNAME_M0_FILL);
	metautils_message_add_field_strint64(request, NAME_MSGKEY_REPLICAS, nbreplicas);
	gchar *body = g_strjoinv("\n", urls);
	metautils_message_set_BODY(request, body, strlen(body));
	g_free(body);
	return gridd_client_exec (m0, M0V2_INIT_TIMEOUT,
			message_marshall_gba_and_clean(request));
}

GError*
meta0_remote_fill_v2(const char *m0, guint nbreplicas, gboolean nodist)
{
	if (nbreplicas < 1)
		return NEWERROR(CODE_BAD_REQUEST, "Too few replicas");
	MESSAGE request = metautils_message_create_named(NAME_MSGNAME_M0_V2_FILL);
	metautils_message_add_field_strint64(request, NAME_MSGKEY_REPLICAS, nbreplicas);
	if (nodist)
		metautils_message_add_field_struint(request, NAME_MSGKEY_NODIST, nodist);
	return gridd_client_exec (m0, M0V2_INIT_TIMEOUT,
			message_marshall_gba_and_clean(request));
}

GError*
meta0_remote_force(const char *m0, const gchar *mapping)
{
	if (!mapping || !*mapping)
		return NEWERROR(CODE_BAD_REQUEST, "Empty JSON mapping");

	MESSAGE request = metautils_message_create_named(NAME_MSGNAME_M0_FORCE);
	metautils_message_set_BODY(request, mapping, strlen(mapping));
	return _m0_remote_no_return(m0, message_marshall_gba_and_clean(request));
}

GError*
meta0_remote_assign(const char *m0, gboolean nocheck)
{
	MESSAGE request = metautils_message_create_named(NAME_MSGNAME_M0_ASSIGN);
	if (nocheck)
		metautils_message_add_field_str (request, NAME_MSGKEY_NOCHECK, "yes");
	return _m0_remote_no_return (m0, message_marshall_gba_and_clean(request));
}

GError*
meta0_remote_disable_meta1(const char *m0, gchar **urls, gboolean nocheck)
{
	if (!urls || !*urls)
		return NEWERROR(CODE_BAD_REQUEST, "Too few URL's");
	MESSAGE request = metautils_message_create_named(NAME_MSGNAME_M0_DISABLE_META1);
	if (nocheck)
		metautils_message_add_field_str(request, NAME_MSGKEY_NOCHECK, "yes");
	gchar *body = g_strjoinv("\n", urls);
	metautils_message_set_BODY(request, body, strlen(body));
	g_free(body);
	return _m0_remote_no_return (m0, message_marshall_gba_and_clean(request));
}

GError*
meta0_remote_destroy_meta1ref(const char *m0, const char *urls)
{
	if (!urls || !*urls)
		return NEWERROR(CODE_BAD_REQUEST, "Too few URL's");
	MESSAGE request = metautils_message_create_named(NAME_MSGNAME_M0_DESTROY_META1REF);
	metautils_message_add_field_str (request, NAME_MSGKEY_METAURL, urls);
	return _m0_remote_no_return (m0, message_marshall_gba_and_clean(request));
}

GError*
meta0_remote_destroy_meta0zknode(const char *m0, const char *urls)
{
	if (!urls || !*urls)
		return NEWERROR(CODE_BAD_REQUEST, "Too few URL's");
	MESSAGE request = metautils_message_create_named(NAME_MSGNAME_M0_DESTROY_META0ZKNODE);
	metautils_message_add_field_str (request, NAME_MSGKEY_METAURL, urls);
	return _m0_remote_no_return (m0, message_marshall_gba_and_clean(request));
}

GError*
meta0_remote_get_meta1_info(const char *m0, gchar ***out)
{
	GError *e = NULL;
	gchar **result = NULL;

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
	struct gridd_client_s *client = gridd_client_create(m0, packed, NULL, on_reply);
	g_byte_array_free(packed, TRUE);
	e = gridd_client_run (client);
	gridd_client_free(client);

	if (e) {
		g_strfreev(result);
		return e;
	}
	*out = result;
	return NULL;
}

