/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

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

#ifndef OIO_SDS__meta2v2__meta2_filter_context_h
# define OIO_SDS__meta2v2__meta2_filter_context_h 1

/* Forward declaration */

struct gridd_filter_input_data_s;
struct gridd_filter_output_data_s;
struct gridd_filter_ctx_s;

/* ------------------------------------------------------------------ */

struct gridd_filter_ctx_s *meta2_filter_ctx_new(void);

void meta2_filter_ctx_clean(struct gridd_filter_ctx_s *ctx);

void meta2_filter_ctx_gclean(gpointer ctx, gpointer ignored);

struct oio_url_s * meta2_filter_ctx_get_url(const struct gridd_filter_ctx_s *ctx);

void meta2_filter_ctx_set_url(struct gridd_filter_ctx_s *ctx, struct oio_url_s *url);

void meta2_filter_ctx_add_param(struct gridd_filter_ctx_s *ctx, const char *k, const char *v);

const char * meta2_filter_ctx_get_param(const struct gridd_filter_ctx_s *ctx, const char *name);

struct meta2_backend_s * meta2_filter_ctx_get_backend(const struct gridd_filter_ctx_s *ctx);

void meta2_filter_ctx_set_backend(struct gridd_filter_ctx_s *ctx, struct meta2_backend_s *backend);

void meta2_filter_ctx_set_error(struct gridd_filter_ctx_s *ctx, GError *e);

GError * meta2_filter_ctx_get_error(const struct gridd_filter_ctx_s *ctx);

void meta2_filter_ctx_set_input_udata(const struct gridd_filter_ctx_s * ctx, gpointer udata, GDestroyNotify in_cleaner);

/**
 * Set or replace the filter user data and optionally clean the old user data.
 */
void meta2_filter_ctx_set_input_udata2(const struct gridd_filter_ctx_s *ctx,
		gpointer udata, GDestroyNotify in_cleaner, gboolean call_cleaner);

gpointer meta2_filter_ctx_get_input_udata(const struct gridd_filter_ctx_s * ctx);

#endif /*OIO_SDS__meta2v2__meta2_filter_context_h*/
