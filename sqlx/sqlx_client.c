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

#include <glib.h>
#include <core/oiostr.h>
#include <core/oiocfg.h>
#include <core/internals.h>
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
		struct oio_sqlx_output_ctx_s *out_ctx, gchar **out_lines)
{
	CLIENT_CALL(self,execute_statement)(self, in_stmt, in_params, out_ctx, out_lines);
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

/* SDS implementation ------------------------------------------------------- */

struct oio_sqlx_client_factory_SDS_s
{
	struct oio_sqlx_client_factory_vtable_s *vtable;
	gchar *url_proxy;
	gchar *ns;
};

static void _sds_factory_destroy (struct oio_sqlx_client_factory_s *self);
static GError * _sds_factory_open (struct oio_sqlx_client_factory_s *self,
			const struct oio_url_s *u, struct oio_sqlx_client_s **out);

struct oio_sqlx_client_factory_vtable_s vtable_factory_SDS = {
	_sds_factory_destroy, _sds_factory_open
};

static void
_sds_factory_destroy (struct oio_sqlx_client_factory_s *self)
{
	g_assert (self != NULL);
	struct oio_sqlx_client_factory_SDS_s *s = (struct oio_sqlx_client_factory_SDS_s*) self;
	g_assert (s->vtable == &vtable_factory_SDS);
	oio_str_clean (&s->url_proxy);
	s->vtable = NULL;
	g_free (s);
}

static GError *
_sds_factory_open (struct oio_sqlx_client_factory_s *self,
			const struct oio_url_s *u, struct oio_sqlx_client_s **out)
{
	g_assert (self != NULL);
	struct oio_sqlx_client_factory_SDS_s *s = (struct oio_sqlx_client_factory_SDS_s*) self;
	g_assert (s->vtable == &vtable_factory_SDS);
	g_assert (out != NULL);
	g_assert (u != NULL);
	*out = NULL;
	return NEWERROR(CODE_NOT_IMPLEMENTED, "NYI");
}

struct oio_sqlx_client_factory_s *
oio_sqlx_client_factory__create_sds (const char *ns)
{
	struct oio_sqlx_client_factory_SDS_s *self = g_slice_new0(struct oio_sqlx_client_factory_SDS_s);
	self->ns = g_strdup (ns);
	self->url_proxy = oio_cfg_get_proxy_directory (ns);
	if (self->url_proxy)
		return (struct oio_sqlx_client_factory_s*) self;
	_sds_factory_destroy ((struct oio_sqlx_client_factory_s*)self);
	return NULL;
}
