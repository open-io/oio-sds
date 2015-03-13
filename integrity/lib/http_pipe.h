/*
OpenIO SDS integrity
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

#ifndef OIO_SDS__integrity__lib__http_pipe_h
# define OIO_SDS__integrity__lib__http_pipe_h 1

# include <glib.h>

struct http_pipe_s;

struct http_pipe_s * http_pipe_create(const gchar *from, const gchar *to);

void http_pipe_force_header(struct http_pipe_s *p, const gchar *name,
		const gchar *value);

typedef gboolean (*http_pipe_header_filter_cb) (gpointer u, const gchar *h);

void http_pipe_filter_headers(struct http_pipe_s *p,
		http_pipe_header_filter_cb filter, gpointer u);

typedef void (*http_pipe_data_filter_cb) (gpointer u, guint8 *b, gsize blen);

void http_pipe_filter_data(struct http_pipe_s *p,
		http_pipe_data_filter_cb filter, gpointer u);

GError *http_pipe_run(struct http_pipe_s *p);

void http_pipe_destroy(struct http_pipe_s *p);

#endif /*OIO_SDS__integrity__lib__http_pipe_h*/