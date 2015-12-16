/*
OpenIO SDS sqlx
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

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

#include <string.h>

#include <glib.h>
#include <sqlite3.h>

/* from oiocore */
#include <core/oiocfg.h>
#include <core/oiolog.h>
#include <core/oiostr.h>
#include <core/oiourl.h>

/* from oiosds */
#include <core/internals.h>

#include <metautils/lib/metautils.h>
#include <sqliterepo/sqlx_remote.h>

#include "sqlx_client.h"

#define CLIENT_CALL(self,F) VTABLE_CALL(self,struct oio_sqlx_client_abstract_s*,F)
#define FACTORY_CALL(self,F) VTABLE_CALL(self,struct oio_sqlx_client_factory_abstract_s*,F)

void
oio_sqlx_client__destroy (struct oio_sqlx_client_s *self)
{
	CLIENT_CALL(self,destroy)(self);
}

GError *
oio_sqlx_client__execute_statement (struct oio_sqlx_client_s *self,
		const char *in_stmt, gchar **in_params,
		struct oio_sqlx_output_ctx_s *out_ctx, gchar ***out)
{
	CLIENT_CALL(self,execute_statement)(self, in_stmt, in_params, out_ctx, out);
}

void
oio_sqlx_client_factory__destroy
(struct oio_sqlx_client_factory_s *self)
{
	FACTORY_CALL(self,destroy)(self);
}

GError *
oio_sqlx_client_factory__open (struct oio_sqlx_client_factory_s *self,
			struct oio_url_s *u, struct oio_sqlx_client_s **out)
{
	FACTORY_CALL(self,open)(self, u, out);
}

