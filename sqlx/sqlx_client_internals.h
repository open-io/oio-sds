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

#ifndef OIO_SDS__sqlx__sqlx_client_internals_h
# define OIO_SDS__sqlx__sqlx_client_internals_h 1

#ifdef __cplusplus
extern "C" {
#endif

struct oio_sqlx_batch_s
{
	GPtrArray *statements; /* <GPtrArray<gchar*>*> */
};

struct oio_sqlx_statement_result_s
{
	struct oio_sqlx_output_ctx_s ctx;
	GError *err;
	GPtrArray *rows; /* <gchar**> */
};

struct oio_sqlx_batch_result_s
{
	GPtrArray *results; /* <oio_sqlx_statement_result_s*> */
};

struct oio_sqlx_batch_result_s * oio_sqlx_batch_result__create (void);

struct oio_sqlx_statement_result_s * oio_sqlx_statement_result__create (void);


/* -------------------------------------------------------------------------- */

struct oio_sqlx_client_vtable_s
{
	void (*destroy) (struct oio_sqlx_client_s *self);

	GError * (*create_db) (struct oio_sqlx_client_s *self);

	GError * (*execute_batch) (struct oio_sqlx_client_s *self,
			struct oio_sqlx_batch_s *in,
			struct oio_sqlx_batch_result_s **out);
};

struct oio_sqlx_client_abstract_s
{
	struct oio_sqlx_client_vtable_s *vtable;
};

/* -------------------------------------------------------------------------- */

struct oio_sqlx_client_factory_vtable_s
{
	void (*destroy) (struct oio_sqlx_client_factory_s *self);

	/* creates a new client */
	GError * (*open) (struct oio_sqlx_client_factory_s *self,
			const struct oio_url_s *u, struct oio_sqlx_client_s **out);

	/* creates a new batch */
	GError * (*batch) (struct oio_sqlx_client_factory_s *self,
			struct oio_sqlx_batch_s **out);
};

struct oio_sqlx_client_factory_abstract_s
{
	struct oio_sqlx_client_factory_vtable_s *vtable;
};

#ifdef __cplusplus
}
#endif

#endif /*OIO_SDS__sqlx__sqlx_client_internals_h*/
