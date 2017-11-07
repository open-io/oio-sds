/*
OpenIO SDS meta0v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#include <metautils/lib/metautils.h>
#include <metautils/lib/common_variables.h>

#include "meta0_remote.h"
#include "internals.h"

static GError *
_m0_remote_no_return (const char *m0, GByteArray *req, gint64 deadline)
{
	EXTRA_ASSERT (m0 != NULL);
	return gridd_client_exec (m0,
			oio_clamp_timeout(oio_m0_client_timeout_common, deadline),
			req);
}

static GError *
_m0_remote_m0info (const char *m0, GByteArray *req, GSList **out, gint64 deadline)
{
	EXTRA_ASSERT (m0 != NULL);
	EXTRA_ASSERT (out != NULL);
	GSList *result = NULL;

	GError *e = gridd_client_exec_and_decode(m0,
			oio_clamp_timeout(oio_m0_client_timeout_common, deadline),
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
meta0_remote_get_meta1_all(const char *m0, GSList **out, gint64 deadline)
{
	MESSAGE request = metautils_message_create_named (NAME_MSGNAME_M0_GETALL, deadline);
	return _m0_remote_m0info (m0, message_marshall_gba_and_clean (request), out, deadline);
}

GError*
meta0_remote_get_meta1_one(const char *m0, const guint8 *prefix,
		GSList **out, gint64 deadline)
{
	MESSAGE request = metautils_message_create_named (NAME_MSGNAME_M0_GETONE, deadline);
	metautils_message_add_field (request, NAME_MSGKEY_PREFIX, prefix, 2);
	return _m0_remote_m0info (m0, message_marshall_gba_and_clean (request), out, deadline);
}

GError*
meta0_remote_cache_refresh(const char *m0, gint64 deadline)
{
	MESSAGE request = metautils_message_create_named (NAME_MSGNAME_M0_RELOAD, deadline);
	return _m0_remote_no_return (m0, message_marshall_gba_and_clean (request), deadline);
}

GError *
meta0_remote_cache_reset (const char *m0, gboolean local, gint64 deadline)
{
	MESSAGE req = metautils_message_create_named (NAME_MSGNAME_M0_RESET, deadline);
	if (local)
		metautils_message_add_field_struint(req, NAME_MSGKEY_LOCAL, 1);
	return _m0_remote_no_return (m0, message_marshall_gba_and_clean (req), deadline);
}

GError*
meta0_remote_force(const char *m0, const guint8 *mapping, gsize mapping_len, gint64 deadline)
{
	if (!mapping || !mapping_len || !*mapping)
		return NEWERROR(CODE_BAD_REQUEST, "Empty JSON mapping");

	MESSAGE request = metautils_message_create_named(NAME_MSGNAME_M0_FORCE, deadline);
	metautils_message_set_BODY(request, mapping, mapping_len);
	return _m0_remote_no_return(m0, message_marshall_gba_and_clean(request), deadline);
}

