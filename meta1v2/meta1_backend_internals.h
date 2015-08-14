/*
OpenIO SDS meta1v2
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

#ifndef OIO_SDS__meta1v2__meta1_backend_internals_h
# define OIO_SDS__meta1v2__meta1_backend_internals_h 1

# include <glib.h>
# include <metautils/lib/metautils.h>
# include <sqlx/sqlx_service.h>

#define M1_SQLITE_GERROR(db,RC) g_error_new(GQ(), (RC), "(%s) %s", \
		sqlite_strerror(RC), (db)?sqlite3_errmsg(db):"unkown error")

struct meta1_backend_s
{
	struct meta_backend_common_s backend;
	struct service_update_policies_s *svcupdate;
	struct meta1_prefixes_set_s *prefixes;

	struct { // Not owned, not to be freed
		gpointer udata;
		GError* (*hook) (gpointer udata, gchar *msg);
	} notify;
};

GError* __create_user(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url);

/*! check the container exists */
GError * __info_user(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		gboolean autocreate, struct hc_url_s ***result);

/*! Open and lock the META1 base responsible for the given container. */
GError* _open_and_lock(struct meta1_backend_s *m1, struct hc_url_s *url,
		enum m1v2_open_type_e how, struct sqlx_sqlite3_s **handle);

void gpa_str_free(GPtrArray *gpa);

/*! Necessarily exported because the old meta1 DESTROY request needs it and
 * the new destroy func needs it too. And they are in different files. */
GError* __destroy_container(struct sqlx_sqlite3_s *sq3,
		struct hc_url_s *url, gboolean flush, gboolean *done);

gboolean m1b_check_ns (struct meta1_backend_s *m1, const char *ns);

gboolean m1b_check_ns_url (struct meta1_backend_s *m1, struct hc_url_s *url);

#endif /*OIO_SDS__meta1v2__meta1_backend_internals_h*/
