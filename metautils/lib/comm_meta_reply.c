/*
OpenIO SDS metautils
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

#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>

#include "./metautils.h"
#include "./metacomm.h"
#include "./gridd_client.h"
#include "./gridd_client_ext.h"

MESSAGE
metaXServer_reply_simple(MESSAGE request, gint code, const gchar *message)
{
	EXTRA_ASSERT (request != NULL);
	MESSAGE reply = metautils_message_create_named(NAME_MSGNAME_METAREPLY, 0);

	gsize mIDSize = 0;
	void *mID = metautils_message_get_ID (request, &mIDSize);
	if (mID && mIDSize)
		metautils_message_set_ID (reply, mID, mIDSize);

	if (CODE_IS_NETWORK_ERROR(code))
		code = CODE_PROXY_ERROR;
	metautils_message_add_field_strint(reply, NAME_MSGKEY_STATUS, code);

	if (message)
		metautils_message_add_field_str (reply, NAME_MSGKEY_MESSAGE, message);
	return reply;
}

GError *
metaXClient_reply_simple(MESSAGE reply, guint * status, gchar ** msg)
{
	EXTRA_ASSERT (reply != NULL);
	EXTRA_ASSERT (status != NULL);
	EXTRA_ASSERT (msg != NULL);

	GError *err = metautils_message_extract_struint(reply, NAME_MSGKEY_STATUS, status);
	if (err) {
		g_prefix_error (&err, "status: ");
		return err;
	}
	*msg = metautils_message_extract_string_copy(reply, NAME_MSGKEY_MESSAGE);
	if (!*msg)
		*msg = g_strdup("?");
	return NULL;
}

