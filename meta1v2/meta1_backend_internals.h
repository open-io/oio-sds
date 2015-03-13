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

#define M1_SQLITE_GERROR(db,RC) g_error_new(GQ(), (RC), "(%s) %s", \
		sqlite_strerror(RC), (db)?sqlite3_errmsg(db):"unkown error")

struct meta1_backend_s
{
	struct meta_backend_common_s backend;

	GRWLock rwlock_ns_policies;
	GHashTable *ns_policies; /* <gchar*,struct service_update_policies_s*> */

	struct meta1_prefixes_set_s *prefixes;
};

/*!
 * @param sq3
 * @param cid
 * @param result
 * @return
 */
GError * __info_container(struct sqlx_sqlite3_s *sq3,
		const container_id_t cid, gchar ***result);

/*!
 * Open and lock the META1 base responsible for the given container.
 *
 * @param m1
 * @param cid
 * @param result
 * @param handle
 * @return
 */
GError* _open_and_lock(struct meta1_backend_s *m1, const container_id_t cid,
		enum m1v2_open_type_e how, struct sqlx_sqlite3_s **handle);

/*!
 *
 * @param gpa
 */
void gpa_str_free(GPtrArray *gpa);

/*!
 * Necessarily exported because the old meta1 DESTROY request needs it
 * and the new destroy func needs it too. And they are in different files.
 *
 * @param sq3
 * @param cid
 * @param flush
 * @param done
 * @return
 */
GError* __destroy_container(struct sqlx_sqlite3_s *sq3,
		const container_id_t cid, gboolean flush, gboolean *done);

#endif /*OIO_SDS__meta1v2__meta1_backend_internals_h*/