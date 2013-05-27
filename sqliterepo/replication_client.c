/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.sqlx.repli"
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <glib.h>

#include "../metautils/lib/loggers.h"
#include "../metautils/lib/hashstr.h"
#include "../metautils/lib/metatypes.h"
#include "../metautils/lib/metautils.h"
#include "../metautils/lib/metacomm.h"

#include "./sqliterepo.h"
#include "./sqlx_remote.h"
#include "./internals.h"
#include "./gridd_client.h"

struct TableSequence;

static GQuark gquark_log = 0;

GError *
peer_restore(const gchar *target, struct sqlx_name_s *name,
		guint8 *dump, gsize dump_size)
{
	struct client_s *client;
	GByteArray *encoded;
	GError *err;

	if (!gquark_log)
		gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	if (!target)
		return g_error_new(gquark_log, 500, "No target URL");

	encoded = sqlx_pack_RESTORE(name, dump, dump_size);
	client = gridd_client_create(target, encoded, NULL, NULL);
	g_byte_array_unref(encoded);

	gridd_client_start(client);
	if (!(err = gridd_client_loop(client)))
		err = gridd_client_error(client);
	gridd_client_free(client);

	return err;
}

GError *
peer_dump(const gchar *target, struct sqlx_name_s *name, GByteArray **result)
{
	GByteArray *dump = NULL;
	struct client_s *client;
	GByteArray *encoded;
	GError *err;

	gboolean on_reply(gpointer ctx, MESSAGE reply) {
		void *b = NULL;
		gsize bsize = 0;
		(void) ctx;

		GRID_TRACE2("%s(%p,%p)", __FUNCTION__, ctx, reply);
		if (0 < message_get_BODY(reply, &b, &bsize, NULL)) {
			if (!dump)
				dump = g_byte_array_new();
			g_byte_array_append(dump, b, bsize);
		}
		return TRUE;
	}

	if (!gquark_log)
		gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	GRID_TRACE2("%s(%s,%p,%p)", __FUNCTION__, target, name, result);

	if (!target)
		return g_error_new(gquark_log, 500, "No target URL");

	encoded = sqlx_pack_DUMP(name);
	client = gridd_client_create(target, encoded, NULL, on_reply);
	g_byte_array_unref(encoded);

	gridd_client_start(client);
	if (!(err = gridd_client_loop(client))) {
		if (!(err = gridd_client_error(client)))
			*result = dump;
	}

	if (err && dump)
		g_byte_array_free(dump, TRUE);

	gridd_client_free(client);
	return err;
}

