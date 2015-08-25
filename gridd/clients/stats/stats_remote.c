/*
OpenIO SDS gridd
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <math.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include <gridd/plugins/msg_stats/msg_stats.h>

#include "./stats_remote.h"

GError *
gridd_stats_remote (const char *to, const char *pattern, gchar ***out)
{
	if (!to || !metautils_url_valid_for_connect(to))
		return NEWERROR(CODE_BAD_REQUEST, "Bad address");

	MESSAGE req = metautils_message_create_named("REQ_STATS");
	if (pattern)
		metautils_message_add_field_str (req, MSGKEY_PATTERN, pattern);
	GByteArray *encoded = message_marshall_gba_and_clean (req);

	gchar *packed = NULL;
	GError *err = gridd_client_exec_and_concat_string (to, 30.0, encoded, &packed);
	if (err) {
		g_free0 (packed);
		return err;
	}

	if (out)
		*out = metautils_decode_lines(packed, packed + strlen(packed));
	g_free0 (packed);
	return NULL;
}

