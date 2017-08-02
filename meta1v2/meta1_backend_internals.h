/*
OpenIO SDS meta1v2
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

#ifndef OIO_SDS__meta1v2__meta1_backend_internals_h
# define OIO_SDS__meta1v2__meta1_backend_internals_h 1

# include <glib.h>
# include <metautils/lib/metautils.h>
# include <sqlx/sqlx_service.h>
# include <events/oio_events_queue.h>

#ifndef OIO_META1_DIGITS_KEY
#define OIO_META1_DIGITS_KEY "meta1_digits"
#endif

#ifndef OIO_META1_DIGITS_DEFAULT
#define OIO_META1_DIGITS_DEFAULT 4
#endif

#define M1_SQLITE_GERROR(db,RC) NEWERROR((RC), "(%s) %s", \
		sqlite_strerror(RC), (db)?sqlite3_errmsg(db):"unkown error")

struct meta1_backend_s
{
	const char *type;
	struct sqlx_repository_s *repo;
	struct oio_lb_s *lb;

	struct service_update_policies_s *svcupdate;
	struct meta1_prefixes_set_s *prefixes;
	struct oio_events_queue_s *notifier;

	guint nb_digits;
	gchar ns_name[LIMIT_LENGTH_NSNAME];
};

void __exec_cid(sqlite3 *handle, const gchar *sql, const container_id_t cid);

GError* __create_user(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url);

GError * __check_backend_events (struct meta1_backend_s *m1);

/*! check the container exists */
GError * __info_user(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		gboolean autocreate, struct oio_url_s ***result);

/*! Open and lock the META1 base responsible for the given container. */
GError* _open_and_lock(struct meta1_backend_s *m1, struct oio_url_s *url,
		enum m1v2_open_type_e how, struct sqlx_sqlite3_s **handle);

void gpa_str_free(GPtrArray *gpa);

GError * __set_container_properties(struct sqlx_sqlite3_s *sq3,
		struct oio_url_s *url, gchar **props);

#endif /*OIO_SDS__meta1v2__meta1_backend_internals_h*/
