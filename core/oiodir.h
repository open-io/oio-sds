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

#ifndef OIO_SDS__core__directory_h
# define OIO_SDS__core__directory_h 1

# include <glib.h>

struct oio_url_s;

struct oio_directory_s;

struct oio_directory_vtable_s
{
	void (*destroy) (struct oio_directory_s *self);

	/* the OIOURL_TYPE in <url> will be ignored */
	GError * (*create) (struct oio_directory_s *self,
			const struct oio_url_s *url);

	/* the OIOURL_TYPE in <url> will be ignored */
	GError * (*list) (struct oio_directory_s *self,
			const struct oio_url_s *url, const char *srvtype,
			gchar ***out_dir, gchar ***out_srv);

	/* the OIOURL_TYPE in <url> will be ignored */
	GError * (*link) (struct oio_directory_s *self,
			const struct oio_url_s *url, const char *srvtype, gboolean autocreate,
			gchar ***out_srv);
};

struct oio_directory_abstract_s
{
	struct oio_directory_vtable_s *vtable;
};

void oio_directory__destroy (struct oio_directory_s *d);

GError * oio_directory__create (struct oio_directory_s *d,
		const struct oio_url_s *url);

GError * oio_directory__list (struct oio_directory_s *d,
		const struct oio_url_s *url, const char *srvtype,
		gchar ***out_dir, gchar ***out_srv);

GError * oio_directory__link (struct oio_directory_s *d,
		const struct oio_url_s *url, const char *srvtype, gboolean autocreate,
		gchar ***out_srv);

/* Implementation specifics ------------------------------------------------- */

/* create a directory that perform dorect access to the meta0 and meta1
 * services */
struct oio_directory_s * oio_directory__create_proxy (const char *ns);

#endif /*OIO_SDS__core__directory_h*/
