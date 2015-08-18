/*
OpenIO SDS sqliterepo
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
#include <stdlib.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <sqliterepo/sqlite_utils.h>
#include <sqliterepo/sqlx_remote.h>
#include <sqliterepo/sqlx_remote_ex.h>

GError*
sqlx_remote_execute_DESTROY(const gchar *target, GByteArray *sid,
		struct sqlx_name_s *name, gboolean local)
{
	(void) sid;
	GError *err = NULL;
	GByteArray *req = sqlx_pack_DESTROY(name, local);

	struct gridd_client_s *client = gridd_client_create(target, req, NULL, NULL);
	g_byte_array_unref(req);

	gridd_client_start(client);
	if (!(err = gridd_client_loop(client))) {
		err = gridd_client_error(client);
	}

	gridd_client_free(client);
	return err;
}

GError*
sqlx_remote_execute_DESTROY_many(gchar **targets, GByteArray *sid,
		struct sqlx_name_s *name)
{
	(void) sid;
	GError *err = NULL;
	GByteArray *req = sqlx_pack_DESTROY(name, TRUE);

	struct gridd_client_s **clients = gridd_client_create_many(targets, req,
			NULL, NULL);
	metautils_gba_unref(req);
	req = NULL;

	if (clients == NULL) {
		err = NEWERROR(0, "Failed to create gridd clients");
		return err;
	}

	gridd_clients_start(clients);
	err = gridd_clients_loop(clients);

	for (struct gridd_client_s **p = clients; !err && p && *p ;p++) {
		if (!(err = gridd_client_error(*p)))
			continue;
		GRID_DEBUG("Database destruction attempts failed: (%d) %s",
				err->code, err->message);
		if (err->code == CODE_CONTAINER_NOTFOUND || err->code == 404) {
			g_clear_error(&err);
			continue;
		}
	}

	gridd_clients_free(clients);
	return err;
}

