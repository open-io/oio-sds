/*
OpenIO SDS sqliterepo
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021-2025 OVH SAS

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

#include "core/oioext.h"
#include "core/oiolog.h"
#include "glib.h"
#include "sqliterepo_remote_variables.h"

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <sqliterepo/sqlite_utils.h>
#include <sqliterepo/sqlx_remote.h>
#include <sqliterepo/sqlx_remote_ex.h>

GError*
sqlx_remote_execute_RESYNC_many(gchar **targets,
		const struct sqlx_name_s *name, const gint check_type, gint64 deadline)
{
	GError *err = NULL;
	gint64 real_deadline = oio_ext_monotonic_time()
			+ oio_election_resync_timeout_req * G_TIME_SPAN_SECOND;
	GByteArray *req = sqlx_pack_RESYNC(name, check_type, real_deadline);
	struct gridd_client_s **clients = gridd_client_create_many(
			targets, req, NULL, NULL);
	metautils_gba_unref(req);
	req = NULL;

	if (clients == NULL) {
		return SYSERR(
			"Failed to create gridd clients (reqid=%s)", oio_ext_get_reqid());
	}

	gridd_clients_set_timeout(clients,
			oio_clamp_timeout(10 * G_TIME_SPAN_SECOND, deadline));

	gridd_clients_start(clients);
	err = gridd_clients_loop(clients);

	for (struct gridd_client_s **p = clients; clients && *p; p++) {
		GError *err2 = NULL;
		if ((err2 = gridd_client_error(*p))) {
			GRID_WARN("Database resync attempts failed: (%d) %s (reqid=%s)",
					err2->code, err2->message, oio_ext_get_reqid());
			g_clear_error(&err2);
		}
	}

	gridd_clients_free(clients);
	return err;
}
