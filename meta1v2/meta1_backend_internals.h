#ifndef META1_BACKEND_INTERNALS__H
# define META1_BACKEND_INTERNALS__H 1
# include <glib.h>

#define M1_SQLITE_GERROR(db,RC) g_error_new(GQ(), (RC), "(%s) %s", \
		sqlite_strerror(RC), (db)?sqlite3_errmsg(db):"unkown error")

struct meta1_backend_s
{
	gchar ns_name[256];

	GStaticRWLock rwlock_ns_policies;
	GHashTable *ns_policies; /* <gchar*,struct service_update_policies_s*> */

	struct meta1_prefixes_set_s *prefixes;
	sqlx_repository_t *repository;
	struct grid_lbpool_s *lb;
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

#endif
