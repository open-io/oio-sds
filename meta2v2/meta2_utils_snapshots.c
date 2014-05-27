#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "m2v2.utils"
#endif

#include <meta2v2/meta2_backend_internals.h>
#include <meta2v2/meta2_utils.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>


GError*
m2db_set_snapshots(struct sqlx_sqlite3_s *sq3, GSList *beans,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	for (; err == NULL && beans != NULL; beans = beans->next) {
		err = SNAPSHOTS_save(sq3->db, beans->data);
		if (err == NULL && cb != NULL) {
			cb(u0, beans->data);
		}
	}

	return err;
}

GError*
m2db_get_snapshots(struct sqlx_sqlite3_s *sq3, const gchar *name,
		gint64 version, m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	gchar *clause = " 1 ";
	GVariant *params[] = {NULL, NULL, NULL};

	if (name != NULL && version >= 0) {
		clause = " name = ? AND version = ? ";
		params[0] = g_variant_new_string(name);
		params[1] = g_variant_new_int64(version);;
	} else if (name != NULL) {
		clause = " name = ? ";
		params[0] = g_variant_new_string(name);
	} else if (version >= 0) {
		clause = " version = ? ";
		params[0] = g_variant_new_int64(version);
	}

	err = SNAPSHOTS_load(sq3->db, clause, params, cb, u0);

	if (params[0] != NULL)
		g_variant_unref(params[0]);
	if (params[1] != NULL)
		g_variant_unref(params[1]);

	return err;
}

GError*
m2db_get_snapshot_by_name(struct sqlx_sqlite3_s *sq3, const gchar *name,
		struct bean_SNAPSHOTS_s **snapshot)
{
	GError *err = NULL;
	struct bean_SNAPSHOTS_s *_snapshot = NULL;

	g_assert(name != NULL);
	g_assert(snapshot != NULL);

	void _cb(gpointer u, gpointer bean) {
		(void) u;
		_snapshot = bean;
	}

	err = m2db_get_snapshots(sq3, name, -1, _cb, NULL);
	if (err == NULL) {
		if (_snapshot == NULL) {
			err = NEWERROR(CODE_SNAPSHOT_NOTFOUND, "Snapshot '%s' not found",
					name);
		} else {
			*snapshot = _snapshot;
		}
	}

	return err;
}

GError*
m2db_take_snapshot(struct sqlx_sqlite3_s *sq3, const gchar *name,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	struct bean_SNAPSHOTS_s *snapshot = NULL;

	err = m2db_dup_all_aliases(sq3, -1, FALSE, FALSE);
	if (err != NULL) {
		g_prefix_error(&err, "Failed to create snapshot: ");
		return err;
	}

	snapshot = _bean_create(&descr_struct_SNAPSHOTS);
	SNAPSHOTS_set_version(snapshot, 1 + m2db_get_version(sq3));
	SNAPSHOTS_set2_name(snapshot, name);
	GSList *tmp = g_slist_prepend(NULL, snapshot);

	err = m2db_set_snapshots(sq3, tmp, cb, u0);

	if (err != NULL || cb == NULL) {
		g_free(snapshot);
	}
	g_slist_free(tmp);

	return err;
}

GError*
m2db_delete_snapshot(struct sqlx_sqlite3_s *sq3,
		struct bean_SNAPSHOTS_s *snapshot)
{
	GError *err = NULL;
	gchar *clause = " name = ? ";
	gchar *clause2 = " container_version = ? ";
	GVariant *params[] = {NULL, NULL};
	params[0] = g_variant_new_string(SNAPSHOTS_get_name(snapshot)->str);

	err = SNAPSHOTS_delete(sq3->db, clause, params);
	// You may want to remove this block to speed up deletion
	if (err == NULL) {
		g_variant_unref(params[0]);
		params[0] = g_variant_new_int64(SNAPSHOTS_get_version(snapshot));
		err = ALIASES_delete(sq3->db, clause2, params);
	}

	g_variant_unref(params[0]);
	return err;
}

GError*
m2db_restore_snapshot(struct sqlx_sqlite3_s *sq3,
		struct bean_SNAPSHOTS_s *snapshot, gboolean hard_restore)
{
	GError *err = NULL;
	g_assert(snapshot != NULL);
	gint64 c_ver = SNAPSHOTS_get_version(snapshot);

	if (hard_restore) {
		gchar *clause = " container_version > ? ";
		gchar *clause2 = " version > ? ";
		GVariant *params[] = {g_variant_new_int64(c_ver), NULL};
		// Delete all aliases more recent than the snapshot
		err = ALIASES_delete(sq3->db, clause, params);
		if (err == NULL) {
			// Delete all more recent snapshots
			err = SNAPSHOTS_delete(sq3->db, clause2, params);
		}
		g_variant_unref(params[0]);
	} else {
		// Set deleted flag on all aliases
		err = m2db_dup_all_aliases(sq3, -1, TRUE, FALSE);
		if (err == NULL) {
			// Copy snapshot's aliases (will overwrite some)
			err = m2db_dup_all_aliases(sq3, c_ver, FALSE, TRUE);
		}
	}

	return err;
}

GError*
m2db_restore_snapshot_alias(struct sqlx_sqlite3_s *sq3,
		struct bean_SNAPSHOTS_s *snapshot, const gchar *alias_name)
{
	GError *err = NULL;
	struct dup_alias_params_s cb_params;
	const gchar *clause = " alias = ? AND container_version = ? ";
	GVariant *params[] = {NULL, NULL, NULL};

	g_assert(snapshot != NULL);
	g_assert(alias_name != NULL);

	cb_params.sq3 = sq3;
	cb_params.c_version = m2db_get_version(sq3);
	cb_params.src_c_version = SNAPSHOTS_get_version(snapshot);
	cb_params.overwrite_latest = FALSE;
	cb_params.set_deleted = FALSE;
	cb_params.errors = NULL;

	params[0] = g_variant_new_string(alias_name);
	params[1] = g_variant_new_int64(cb_params.src_c_version);

	err = ALIASES_load(sq3->db, clause, params,
			(m2_onbean_cb)m2v2_dup_alias, &cb_params);

	return err;
}

gboolean
is_in_a_snapshot(struct sqlx_sqlite3_s *sq3, struct bean_ALIASES_s *alias)
{
	GError *err = NULL;
	guint snap_count = 0;
	gint64 c_ver = ALIASES_get_container_version(alias);

	/** Count snapshot beans */
	void _cb(gpointer u, gpointer bean) {
		(void) u;
		snap_count++;
		_bean_clean(bean);
	}

	err = m2db_get_snapshots(sq3, NULL, c_ver, _cb, NULL);
	if (err != NULL) {
		GRID_WARN("Failed to check for snapshots: %s", err->message);
		g_clear_error(&err);
	}

	return (snap_count != 0);
}

