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

#ifndef OIO_SDS__sqlx__sqlx_client_h
# define OIO_SDS__sqlx__sqlx_client_h 1

# include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

struct oio_url_s;
struct oio_directory_s;

/* -------------------------------------------------------------------------- */

struct oio_sqlx_client_s;

struct oio_sqlx_output_ctx_s
{
	gint64 changes;
	gint64 total_changes;
	gint64 last_rowid;
};

/* The interface to be implemented */
struct oio_sqlx_client_vtable_s
{
	void (*destroy) (struct oio_sqlx_client_s *self);

	GError * (*execute_statement) (struct oio_sqlx_client_s *self,
			const char *in_stmt, gchar **in_params,
			struct oio_sqlx_output_ctx_s *out_ctx, gchar ***out_lines);
};

/* Any implementation of a oio_sqlx_client_s must respect this preamble */
struct oio_sqlx_client_abstract_s
{
	struct oio_sqlx_client_vtable_s *vtable;
};

void oio_sqlx_client__destroy (struct oio_sqlx_client_s *self);

GError * oio_sqlx_client__execute_statement (struct oio_sqlx_client_s *self,
		const char *in_stmt, gchar **in_params,
		struct oio_sqlx_output_ctx_s *out_ctx, gchar ***out_lines);

/* -------------------------------------------------------------------------- */

struct oio_sqlx_client_factory_s;

struct oio_sqlx_client_factory_vtable_s
{
	void (*destroy) (struct oio_sqlx_client_factory_s *self);

	GError * (*open) (struct oio_sqlx_client_factory_s *self,
			const struct oio_url_s *u, struct oio_sqlx_client_s **out);
};

struct oio_sqlx_client_factory_abstract_s
{
	struct oio_sqlx_client_factory_vtable_s *vtable;
};

void oio_sqlx_client_factory__destroy (struct oio_sqlx_client_factory_s *self);

GError * oio_sqlx_client_factory__open (struct oio_sqlx_client_factory_s *self,
			struct oio_url_s *u, struct oio_sqlx_client_s **out);

/* Implementation specifics ------------------------------------------------- */

/* Creates the default SQLX client that locates then contacts sqlx servers */ 
struct oio_sqlx_client_factory_s * oio_sqlx_client_factory__create_sds (
		const char *ns, struct oio_directory_s *dir);

/* Creates the default SQLX client that locates then contacts sqlx servers */ 
struct oio_sqlx_client_factory_s * oio_sqlx_client_factory__create_local (
		const char *ns, const char *schema);

#ifdef __cplusplus
}
#endif

#endif /*OIO_SDS__sqlx__sqlx_client_h*/
