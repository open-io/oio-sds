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

#include <netdb.h>
#include <string.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/server_variables.h>

#include "meta0_remote.h"
#include "internals.h"

static GError *
_m0_remote_no_return (const char *m0, GByteArray *req)
{
	EXTRA_ASSERT (m0 != NULL);
	return gridd_client_exec (m0, oio_m0_client_timeout_common, req);
}

static GError *
_m0_remote_m0info (const char *m0, GByteArray *req, GSList **out)
{
	EXTRA_ASSERT (m0 != NULL);
	EXTRA_ASSERT (out != NULL);
	GSList *result = NULL;
	GError *e = gridd_client_exec_and_decode (m0, oio_m0_client_timeout_common,
			req, &result, meta0_info_unmarshall);
	if (!e) {
		*out = result;
		return NULL;
	}
	g_slist_free_full (result, (GDestroyNotify)meta0_info_clean);
	*out = NULL;
	return e;
}

/* ------------------------------------------------------------------------- */

GError *
meta0_remote_get_meta1_all(const char *m0, GSList **out)
{
	MESSAGE request = metautils_message_create_named (NAME_MSGNAME_M0_GETALL);
	return _m0_remote_m0info (m0, message_marshall_gba_and_clean (request), out);
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
	MESSAGE request = metautils_message_create_named (NAME_MSGNAME_M0_RELOAD);
	return _m0_remote_no_return (m0, message_marshall_gba_and_clean (request));
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
meta0_remote_force(const char *m0, const guint8 *mapping, gsize mapping_len)
{
	if (!mapping || !mapping_len || !*mapping)
		return NEWERROR(CODE_BAD_REQUEST, "Empty JSON mapping");

	MESSAGE request = metautils_message_create_named(NAME_MSGNAME_M0_FORCE);
	metautils_message_set_BODY(request, mapping, mapping_len);
	return _m0_remote_no_return(m0, message_marshall_gba_and_clean(request));
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
	MESSAGE request = metautils_message_create_named(NAME_MSGNAME_M0_GET_META1_INFO);
	GByteArray *packed = message_marshall_gba_and_clean(request);
	GByteArray *tmp = NULL;
	GError *err = gridd_client_exec_and_concat(
			m0, oio_m0_client_timeout_common, packed, &tmp);
	g_byte_array_free(packed, TRUE);

	if (err) {
		if (tmp)
			g_byte_array_free(tmp, TRUE);
		return err;
	}
	err = STRV_decode_buffer(tmp->data, tmp->len, out);
	g_byte_array_free(tmp, TRUE);
	return err;
}
