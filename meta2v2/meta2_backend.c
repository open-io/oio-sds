/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#include <glib.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/common_variables.h>
#include <server/server_variables.h>
#include <meta2v2/meta2_variables.h>

#include <cluster/lib/gridcluster.h>

#include <sqliterepo/sqlite_utils.h>
#include <sqliterepo/sqliterepo.h>
#include <sqliterepo/election.h>

#include <events/oio_events_queue.h>

#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>
#include <meta2v2/meta2_macros.h>
#include <meta2v2/meta2_utils_lb.h>
#include <meta2v2/meta2_backend_internals.h>

#include <resolver/hc_resolver.h>

enum m2v2_open_type_e
{
	M2V2_OPEN_LOCAL       = 0x000,
	M2V2_OPEN_MASTERONLY  = 0x001,
	M2V2_OPEN_SLAVEONLY   = 0x002,
	M2V2_OPEN_MASTERSLAVE = 0x003,
#define M2V2_OPEN_REPLIMODE 0x00F

	M2V2_OPEN_AUTOCREATE  = 0x010,
#define M2V2_OPEN_FLAGS     0x0F0

	// Set an OR'ed combination of the following flags to require
	// a check on the container's status during the open phase.
	// No flag set means no check.
	M2V2_OPEN_ENABLED     = 0x100,
	M2V2_OPEN_FROZEN      = 0x200,
	M2V2_OPEN_DISABLED    = 0x400,
#define M2V2_OPEN_STATUS    0xF00
};

struct m2_prepare_data
{
	gint64 max_versions;
	gint64 quota;
	gint64 size;
	gchar storage_policy[LIMIT_LENGTH_STGPOLICY];
};

static void _meta2_backend_force_prepare_data(struct meta2_backend_s *m2b,
		const gchar *key, struct sqlx_sqlite3_s *sq3);

static enum m2v2_open_type_e
_mode_masterslave(guint32 flags)
{
	if (flags & M2V2_FLAG_MASTER)
		return M2V2_OPEN_MASTERONLY;
	return (flags & M2V2_FLAG_LOCAL)
		? M2V2_OPEN_LOCAL : M2V2_OPEN_MASTERSLAVE;

}

static enum m2v2_open_type_e
_mode_readonly(guint32 flags)
{
	return M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN|_mode_masterslave(flags);
}

static gint64
_maxvers(struct sqlx_sqlite3_s *sq3)
{
	return m2db_get_max_versions(sq3, meta2_max_versions);
}

static gint64
_retention_delay(struct sqlx_sqlite3_s *sq3)
{
	return m2db_get_keep_deleted_delay(sq3, meta2_retention_period);
}

static gchar*
_stgpol(struct sqlx_sqlite3_s *sq3)
{
	gchar *stgpol = sqlx_admin_get_str(sq3, M2V2_ADMIN_STORAGE_POLICY);
	return stgpol ?: oio_var_get_string(oio_ns_storage_policy);
}

/* Backend ------------------------------------------------------------------ */

static GError*
_check_policy(struct meta2_backend_s *m2, const gchar *polname)
{
	GError *err = NULL;
	struct storage_policy_s *policy = NULL;

	if (!*polname)
		return NEWERROR(CODE_BAD_REQUEST, "Invalid policy: %s", "empty");

	g_mutex_lock (&m2->nsinfo_lock);
	policy = storage_policy_init(m2->nsinfo, polname);
	g_mutex_unlock (&m2->nsinfo_lock);

	if (!policy)
		err = NEWERROR(CODE_POLICY_NOT_SUPPORTED, "Invalid policy: %s", "not found");
	else
		storage_policy_clean(policy);
	return err;
}

const gchar*
meta2_backend_get_local_addr(struct meta2_backend_s *m2)
{
	return sqlx_repository_get_local_addr(m2->repo);
}

GError *
meta2_backend_init(struct meta2_backend_s **result,
		struct sqlx_repository_s *repo, const gchar *ns,
		struct oio_lb_s *lb, struct hc_resolver_s *resolver)
{
	EXTRA_ASSERT(result != NULL);
	EXTRA_ASSERT(repo != NULL);
	EXTRA_ASSERT(lb != NULL);
	EXTRA_ASSERT(resolver != NULL);

	if (!*ns || strlen(ns) >= LIMIT_LENGTH_NSNAME)
		return BADREQ("Invalid namespace name");

	struct meta2_backend_s *m2 = g_malloc0(sizeof(struct meta2_backend_s));
	g_strlcpy(m2->ns_name, ns, sizeof(m2->ns_name));
	m2->type = NAME_SRVTYPE_META2;
	m2->repo = repo;
	m2->lb = lb;
	m2->policies = service_update_policies_create();
	g_mutex_init(&m2->nsinfo_lock);
	m2->flag_precheck_on_generate = meta2_flag_precheck_on_generate;
	// TODO: use a custom hash function
	m2->prepare_data_cache = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, g_free);
	g_rw_lock_init(&(m2->prepare_data_lock));

	GError *err = sqlx_repository_configure_type(m2->repo,
			NAME_SRVTYPE_META2, schema);
	if (NULL != err) {
		meta2_backend_clean(m2);
		g_prefix_error(&err, "Backend init error: ");
		return err;
	}

	m2->resolver = resolver;
	*result = m2;

	GRID_DEBUG("M2V2 backend created for NS[%s] and repo[%p]",
			m2->ns_name, m2->repo);
	return NULL;
}

void
meta2_backend_clean(struct meta2_backend_s *m2)
{
	if (!m2)
		return;
	if (m2->policies)
		service_update_policies_destroy(m2->policies);
	if (m2->resolver)
		m2->resolver = NULL;
	g_hash_table_unref(m2->prepare_data_cache);
	m2->prepare_data_cache = NULL;
	g_rw_lock_clear(&(m2->prepare_data_lock));
	g_mutex_clear(&m2->nsinfo_lock);
	namespace_info_free(m2->nsinfo);
	g_free(m2);
}

void
meta2_backend_configure_nsinfo(struct meta2_backend_s *m2,
		struct namespace_info_s *ni)
{
	EXTRA_ASSERT(m2 != NULL);
	EXTRA_ASSERT(ni != NULL);

	struct namespace_info_s *old = NULL, *copy = NULL;
	copy = namespace_info_dup (ni);

	g_mutex_lock(&m2->nsinfo_lock);
	old = m2->nsinfo;
	m2->nsinfo = copy;
	g_mutex_unlock(&m2->nsinfo_lock);

	if (old)
		namespace_info_free (old);
}

struct namespace_info_s *
meta2_backend_get_nsinfo (struct meta2_backend_s *m2)
{
	EXTRA_ASSERT(m2 != NULL);
	struct namespace_info_s *out = NULL;

	g_mutex_lock(&m2->nsinfo_lock);
	if (m2->nsinfo)
		out = namespace_info_dup (m2->nsinfo);
	g_mutex_unlock(&m2->nsinfo_lock);

	return out;
}

gboolean
meta2_backend_initiated(struct meta2_backend_s *m2)
{
	EXTRA_ASSERT(m2 != NULL);
	g_mutex_lock (&m2->nsinfo_lock);
	gboolean rc = (NULL != m2->nsinfo);
	g_mutex_unlock (&m2->nsinfo_lock);
	return rc;
}

/* Container -------------------------------------------------------------- */

static enum sqlx_open_type_e
m2_to_sqlx(enum m2v2_open_type_e t)
{
	enum sqlx_open_type_e result = SQLX_OPEN_LOCAL;

	if (t & M2V2_OPEN_MASTERONLY)
		result |= SQLX_OPEN_MASTERONLY;
	if (t & M2V2_OPEN_SLAVEONLY)
		result |= SQLX_OPEN_SLAVEONLY;

	if (t & M2V2_OPEN_AUTOCREATE)
		result |= SQLX_OPEN_CREATE;

	if (t & M2V2_OPEN_ENABLED)
		result |= SQLX_OPEN_ENABLED;
	if (t & M2V2_OPEN_FROZEN)
		result |= SQLX_OPEN_FROZEN;
	if (t & M2V2_OPEN_DISABLED)
		result |= SQLX_OPEN_DISABLED;

	return result;
}

static gboolean
_is_container_initiated(struct sqlx_sqlite3_s *sq3)
{
	if (sqlx_admin_has(sq3, META2_INIT_FLAG))
		return TRUE;

	/* workaround for a known bug, when the container has no flag because
	 * of some failed replication (yet to be determined) but it is used
	 * because of a (now-fixed) inexistant check on the flag. */
	if (sqlx_admin_has(sq3, M2V2_ADMIN_OBJ_COUNT)
			|| sqlx_admin_has(sq3, M2V2_ADMIN_SIZE)) {
		GRID_DEBUG("DB partially initiated: [%s][%.s]",
				sq3->name.base, sq3->name.type);
		return TRUE;
	}

	return FALSE;
}

static void
m2b_close(struct sqlx_sqlite3_s *sq3)
{
	if (sq3) {
		sqlx_repository_unlock_and_close_noerror(sq3);
	}
}

static void
m2b_destroy(struct sqlx_sqlite3_s *sq3)
{
	if (sq3) {
		GRID_INFO("Closing and destroying [%s][%s]", sq3->name.base, sq3->name.type);
		sq3->deleted = TRUE;
		sqlx_repository_unlock_and_close_noerror(sq3);
	}
}

static GError *
m2b_open(struct meta2_backend_s *m2, struct oio_url_s *url,
		enum m2v2_open_type_e how, struct sqlx_sqlite3_s **result)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(result != NULL);
	EXTRA_ASSERT(m2 != NULL);
	EXTRA_ASSERT(m2->repo != NULL);

	struct sqlx_name_inline_s n0;
	sqlx_inline_name_fill (&n0, url, NAME_SRVTYPE_META2, 1);
	NAME2CONST(n,n0);

	err = sqlx_repository_open_and_lock(m2->repo, &n, m2_to_sqlx(how), &sq3, NULL);
	if (NULL != err) {
		if (err->code == CODE_CONTAINER_NOTFOUND)
			err->domain = GQ();
		return err;
	}

	/* beware that LOCAL is maybe == 0 */
	const gboolean _local = (M2V2_OPEN_LOCAL == (how & M2V2_OPEN_REPLIMODE));
	const gboolean _create = (M2V2_OPEN_AUTOCREATE == (how & M2V2_OPEN_AUTOCREATE));

	sq3->no_peers = _local;

	// If the container is being deleted, this is sad ...
	// This MIGHT happen if a cache is present (and this is the
	// common case for m2v2), because the deletion will happen
	// when the base exit the cache.
	// In facts this SHOULD NOT happend because a base being deleted
	// is closed with an instruction to exit the cache immediately.
	// TODO FIXME this is maybe a good place for an assert().
	if (sq3->deleted) {
		m2b_close(sq3);
		return NEWERROR(CODE_CONTAINER_FROZEN, "destruction pending");
	}

	/* The kind of check we do depend of the kind of opening:
	 * - creation : init not done
	 * - local access : no check
	 * - replicated access : int done */
	if (_create) {
		if (_is_container_initiated(sq3)) {
			m2b_close(sq3);
			return NEWERROR(CODE_CONTAINER_EXISTS,
					"container already initiated");
		}
	} else if (!_local) {
		if (!_is_container_initiated(sq3)) {
			m2b_close(sq3);
			return NEWERROR(CODE_CONTAINER_NOTFOUND,
					"container created but not initiated");
		}
	}

	/* Complete URL with full VNS and container name */
	void set(gchar *k, int f) {
		if (oio_url_has(url, f))
			return;
		gchar *s = sqlx_admin_get_str (sq3, k);
		if (s) {
			oio_url_set (url, f, s);
			g_free (s);
		}
	}
	set (SQLX_ADMIN_NAMESPACE, OIOURL_NS);
	set (SQLX_ADMIN_ACCOUNT, OIOURL_ACCOUNT);
	set (SQLX_ADMIN_USERNAME, OIOURL_USER);
	set (SQLX_ADMIN_USERTYPE, OIOURL_TYPE);

	*result = sq3;
	return NULL;
}

static GError *
m2b_open_if_needed(struct meta2_backend_s *m2, struct oio_url_s *url,
		enum m2v2_open_type_e how, struct sqlx_sqlite3_s **result)
{
	if (*result)
		return NULL;
	return m2b_open(m2, url, how, result);
}

static GError*
_transaction_begin(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		struct sqlx_repctx_s **result)
{
	struct sqlx_repctx_s* repctx = NULL;

	EXTRA_ASSERT(result != NULL);
	*result = NULL;

	GError *err = sqlx_transaction_begin(sq3, &repctx);
	if (NULL != err)
		return err;

	m2db_set_container_name(sq3, url);
	*result = repctx;
	return NULL;
}

GError *
meta2_backend_has_container(struct meta2_backend_s *m2,
		struct oio_url_s *url)
{
	GError *err = NULL;

	EXTRA_ASSERT(m2 != NULL);
	EXTRA_ASSERT(url != NULL);
	GRID_DEBUG("HAS(%s)", oio_url_get(url, OIOURL_WHOLE));

	struct sqlx_name_inline_s n0;
	sqlx_inline_name_fill (&n0, url, NAME_SRVTYPE_META2, 1);
	NAME2CONST(n,n0);

	err = sqlx_repository_has_base(m2->repo, &n);
	if (NULL != err) {
		g_prefix_error(&err, "File error: ");
		return err;
	}

	struct sqlx_sqlite3_s *sq3 = NULL;
	err = m2b_open(m2, url, M2V2_OPEN_LOCAL, &sq3);
	if (NULL == err) {
		/* The base is used in LOCAL mode, and with that option the INIT
		 * flag is not checked. As an exception, we want the check to be
		 * performed here. */
		if (!_is_container_initiated(sq3))
			err = NEWERROR(CODE_CONTAINER_NOTFOUND,
					"Container created but not initiated");
		m2b_close(sq3);
	}
	return err;
}

static GError *
_check_if_container_empty (struct sqlx_sqlite3_s *sq3)
{
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;
	gint64 count = 0;

	int rc = sqlite3_prepare(sq3->db,
			"SELECT exists(SELECT 1 FROM chunks LIMIT 1)",
			-1, &stmt, NULL);
	while (SQLITE_ROW == (rc = sqlite3_step(stmt)))
		count = sqlite3_column_int64 (stmt, 0);
	if (rc != SQLITE_OK && rc != SQLITE_DONE) {
		if (err) {
			GRID_WARN("SQLite error: (%d) %s",
					rc, sqlite3_errmsg(sq3->db));
		} else {
			err = NEWERROR(CODE_INTERNAL_ERROR, "SQLite error: (%d) %s",
					rc, sqlite3_errmsg(sq3->db));
		}
	}
	(void) sqlite3_finalize (stmt);

	if (!err && count > 0)
		err = NEWERROR(CODE_CONTAINER_NOTEMPTY, "Container not empty");
	return err;
}

GError *
meta2_backend_container_isempty (struct meta2_backend_s *m2,
		struct oio_url_s *url)
{
	EXTRA_ASSERT(m2 != NULL);
	EXTRA_ASSERT(url != NULL);
	GRID_DEBUG("ISEMPTY(%s)", oio_url_get(url, OIOURL_WHOLE));

	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = m2b_open(m2, url, _mode_masterslave(0), &sq3);
	if (!err) {
		err = _check_if_container_empty (sq3);
		m2b_close(sq3);
	}
	return err;
}

GError*
meta2_backend_get_max_versions(struct meta2_backend_s *m2b,
		struct oio_url_s *url, gint64 *result)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(result != NULL);

	err = m2b_open(m2b, url, _mode_readonly(0), &sq3);
	if (!err) {
		*result = _maxvers(sq3);
		m2b_close(sq3);
	}

	return err;
}

static GError *
_init_container(struct sqlx_sqlite3_s *sq3,
		struct oio_url_s *url, struct m2v2_create_params_s *params)
{
	GError *err = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	if (!params->local && (err = _transaction_begin(sq3, url, &repctx)))
		return err;

	if (!err && params->storage_policy)
		err = m2db_set_storage_policy(sq3, params->storage_policy, 0);
	if (!err && params->version_policy) {
		gint64 max = g_ascii_strtoll(params->version_policy, NULL, 10);
		m2db_set_max_versions(sq3, max);
	}
	if (!err) {
		m2db_set_ctime (sq3, oio_ext_real_time());
		m2db_set_size(sq3, 0);
		m2db_set_obj_count(sq3, 0);
		sqlx_admin_init_i64(sq3, META2_INIT_FLAG, 1);
	}
	if (!err && params->properties) {
		for (gchar **p=params->properties; *p && *(p+1) ;p+=2)
			sqlx_admin_set_str (sq3, *p, *(p+1));
	}
	if (!params->local)
		err = sqlx_transaction_end(repctx, err);
	return err;
}

GError *
meta2_backend_create_container(struct meta2_backend_s *m2,
		struct oio_url_s *url, struct m2v2_create_params_s *params)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	GRID_DEBUG("CREATE(%s,%s,%s)%s", oio_url_get(url, OIOURL_WHOLE),
			params?params->storage_policy:NULL,
			params?params->version_policy:NULL,
			(params && params->local)? " (local)" : "");

	/* We must check storage policy BEFORE opening the base if we don't
	 * want to have an empty base in case of invalid policy */
	if (params->storage_policy) {
		if (NULL != (err = _check_policy(m2, params->storage_policy)))
			return err;
	}

	/* Defer the `m2.init` check to the m2b_open() */
	enum m2v2_open_type_e open_mode = M2V2_OPEN_AUTOCREATE |
		(params->local ? M2V2_OPEN_LOCAL : M2V2_OPEN_MASTERONLY);

	err = m2b_open(m2, url, open_mode, &sq3);
	EXTRA_ASSERT((sq3 != NULL) ^ (err != NULL));
	if (err)
		return err;

	/* At this point the base exist and it has nt been iniated yet */
	err = _init_container(sq3, url, params);
	if (err) {
		m2b_destroy(sq3);
		return err;
	}

	/* Fire an event to notify the world this container exists */
	const enum election_status_e s = sq3->election;
	if (!params->local && m2->notifier && (!s || s == ELECTION_LEADER)) {
		GString *gs = oio_event__create (META2_EVENTS_PREFIX".container.new", url);
		g_string_append_static (gs, ",\"data\":null}");
		oio_events_queue__send (m2->notifier, g_string_free (gs, FALSE));
	}

	/* Reload any cache maybe already associated with the container.
	 * It happens that the cache sometimes exists because created during a
	 * M2_PREP that occured after a GETVERS (the meta1 is filled) but before
	 * the CREATE. */
	meta2_backend_change_callback(sq3, m2);
	m2b_close(sq3);
	return err;
}

GError *
meta2_backend_destroy_container(struct meta2_backend_s *m2,
		struct oio_url_s *url, guint32 flags)
{
	gboolean event = BOOL(flags & M2V2_DESTROY_EVENT);
	gboolean force = BOOL(flags & M2V2_DESTROY_FORCE);
	gboolean flush = BOOL(flags & M2V2_DESTROY_FLUSH);
	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = NULL;

	err = m2b_open(m2, url, M2V2_OPEN_LOCAL, &sq3);
	if (!err) {
		EXTRA_ASSERT(sq3 != NULL);

		if (flush && !force)
			err = _check_if_container_empty (sq3);

		if (!err && flush) {
			err = m2db_flush_container(sq3->db);
			if (NULL != err && force) {
				GRID_WARN ("Destroy error: flush error: (%d) %s",
						err->code, err->message);
				g_clear_error (&err);
			}
		}

		/* TODO(jfs): manage base's subtype */
		hc_decache_reference_service(m2->resolver, url, NAME_SRVTYPE_META2);

		if (!err) {
			GString *gs = NULL;
			if (event && m2->notifier) {
				gs = oio_event__create (META2_EVENTS_PREFIX ".container.deleted", url);
				g_string_append_static (gs, ",\"data\":null}");
			}
			m2b_destroy(sq3);
			if (gs) {
				EXTRA_ASSERT (m2->notifier != NULL);
				oio_events_queue__send (m2->notifier, g_string_free (gs, FALSE));
			}
		} else {
			m2b_close(sq3);
		}
	}

	return err;
}

GError *
meta2_backend_flush_container(struct meta2_backend_s *m2, struct oio_url_s *url)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	err = m2b_open(m2, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED
			|M2V2_OPEN_FROZEN, &sq3);
	if (!err) {
		EXTRA_ASSERT(sq3 != NULL);
		if (!(err = sqlx_transaction_begin(sq3, &repctx))) {
			if (!(err = m2db_flush_container(sq3->db)))
				err = m2db_purge(sq3, _maxvers(sq3), _retention_delay(sq3));
			err = sqlx_transaction_end(repctx, err);
		}
		m2b_close(sq3);
	}

	return err;
}

GError *
meta2_backend_purge_container(struct meta2_backend_s *m2, struct oio_url_s *url)
{
	GError *err;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	err = m2b_open(m2, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		EXTRA_ASSERT(sq3 != NULL);
		if (!(err = sqlx_transaction_begin(sq3, &repctx))) {
			err = m2db_purge(sq3, _maxvers(sq3), _retention_delay(sq3));
			err = sqlx_transaction_end(repctx, err);
		}
		m2b_close(sq3);
	}

	return err;
}

/* Contents --------------------------------------------------------------- */

GError*
meta2_backend_list_aliases(struct meta2_backend_s *m2b, struct oio_url_s *url,
		struct list_params_s *lp, GSList *headers,
		m2_onbean_cb cb, gpointer u0, gchar ***out_properties)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(lp != NULL);

	guint32 open_mode = lp->flag_local? M2V2_FLAG_LOCAL: 0;
	err = m2b_open(m2b, url, _mode_readonly(open_mode), &sq3);
	if (!err) {
		err = m2db_list_aliases(sq3, lp, headers, cb, u0);
		if (!err && out_properties)
			*out_properties = sqlx_admin_get_keyvalues (sq3);
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_get_alias(struct meta2_backend_s *m2b,
		struct oio_url_s *url, guint32 flags,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	err = m2b_open(m2b, url, _mode_readonly(flags), &sq3);
	if (!err) {
		err = m2db_get_alias(sq3, url, flags, cb, u0);
		m2b_close(sq3);
	}

	return err;
}

/* TODO(jfs): merge the container's state with the m2_prepare_data and keep
 *            it cached? */
static gchar *
_container_state (struct sqlx_sqlite3_s *sq3)
{
	void sep (GString *gs) {
		if (gs->len > 1 && !strchr(",[{", gs->str[gs->len-1]))
			g_string_append_c (gs, ',');
	}
	void append_int64 (GString *gs, const char *k, gint64 v) {
		sep (gs);
		g_string_append_printf (gs, "\"%s\":%"G_GINT64_FORMAT, k, v);
	}
	void append_const (GString *gs, const char *k, const char *v) {
		sep (gs);
		oio_str_gstring_append_json_pair(gs, k, v);
	}

	struct oio_url_s *u = sqlx_admin_get_url (sq3);

	/* Patch the SUBTYPE: the URL must represent an object as managed by meta2
	 * services (and also by end-user APIs). Unlike for sqlx services, the user
	 * doesn't know anything about the meta2, and never mentions it in URL.
	 * This is why we strip this from the service type. */
	if (!strcmp(sq3->name.type, NAME_SRVTYPE_META2))
		oio_url_set (u, OIOURL_TYPE, "");
	else if (g_str_has_prefix (sq3->name.type, NAME_SRVTYPE_META2 "."))
		oio_url_set (u, OIOURL_TYPE, sq3->name.type + sizeof(NAME_SRVTYPE_META2));

	GString *gs = oio_event__create (META2_EVENTS_PREFIX ".container.state", u);
	g_string_append_static (gs, ",\"data\":{");
	append_const (gs, "policy", sqlx_admin_get_str(sq3, M2V2_ADMIN_STORAGE_POLICY));
	append_int64 (gs, "ctime", m2db_get_ctime(sq3));
	append_int64 (gs, "bytes-count", m2db_get_size(sq3));
	append_int64 (gs, "object-count", m2db_get_obj_count(sq3));
	g_string_append_static (gs, "}}");

	oio_url_clean (u);
	return g_string_free(gs, FALSE);
}

static void
m2b_add_modified_container(struct meta2_backend_s *m2b,
		struct sqlx_sqlite3_s *sq3)
{
	EXTRA_ASSERT(m2b != NULL);
	if (m2b->notifier)
		oio_events_queue__send_overwritable(m2b->notifier,
				sqlx_admin_get_str(sq3, SQLX_ADMIN_BASENAME),
				_container_state (sq3));

	gboolean has_peers = FALSE;
	NAME2CONST(n, sq3->name);
	GError *err = election_has_peers(sq3->manager, &n, FALSE, &has_peers);
	if (!err && !has_peers) {
		meta2_backend_change_callback(sq3, m2b);
	}
	g_clear_error(&err);
}

/* TODO(jfs): maybe is there a way to keep this in a cache */
GError *
meta2_backend_notify_container_state(struct meta2_backend_s *m2b,
		struct oio_url_s *url)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	if (!(err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY, &sq3))) {
		m2b_add_modified_container(m2b, sq3);
		m2b_close(sq3);
	}
	return err;
}

GError*
meta2_backend_refresh_container_size(struct meta2_backend_s *m2b,
		struct oio_url_s *url, gboolean recompute)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	if (!(err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY, &sq3))) {
		if (recompute) {
			guint64 size = 0u;
			gint64 count = 0;
			m2db_get_container_size_and_obj_count(sq3->db, FALSE,
					&size, &count);
			m2db_set_size(sq3, size);
			m2db_set_obj_count(sq3, count);
		}
		m2b_add_modified_container(m2b, sq3);
		m2b_close(sq3);
	}

	return err;
}

GError *
meta2_backend_drain_content(struct meta2_backend_s *m2,
		struct oio_url_s *url, m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;
	err = m2b_open(m2, url, M2V2_OPEN_MASTERONLY | M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		EXTRA_ASSERT(sq3 != NULL);
		if (!(err = sqlx_transaction_begin(sq3, &repctx))) {
			err = m2db_drain_content(sq3, url, cb, u0);
			err = sqlx_transaction_end(repctx, err);
		}
		m2b_close(sq3);
	}
	return err;
}

GError*
meta2_backend_delete_alias(struct meta2_backend_s *m2b,
		struct oio_url_s *url, m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		struct sqlx_repctx_s *repctx = NULL;
		const gint64 max_versions = _maxvers(sq3);
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (!(err = m2db_delete_alias(sq3, max_versions, url, cb, u0))) {
				m2db_increment_version(sq3);
			}
			err = sqlx_transaction_end(repctx, err);
		}
		if (!err)
			m2b_add_modified_container(m2b, sq3);
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_put_alias(struct meta2_backend_s *m2b, struct oio_url_s *url,
		GSList *in, GSList **out_deleted, GSList **out_added)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);
	if (!in)
		return NEWERROR(CODE_BAD_REQUEST, "No bean");

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {

		struct m2db_put_args_s args;
		memset(&args, 0, sizeof(args));
		args.sq3 = sq3;
		args.url = url;
		args.ns_max_versions = meta2_max_versions;

		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (!(err = m2db_put_alias(&args, in, out_deleted, out_added)))
				m2db_increment_version(sq3);
			err = sqlx_transaction_end(repctx, err);
			if (!err)
				m2b_add_modified_container(m2b, sq3);
		}
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_copy_alias(struct meta2_backend_s *m2b, struct oio_url_s *url,
		const char *src)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(src != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		struct m2db_put_args_s args;
		memset(&args, 0, sizeof(args));
		args.sq3 = sq3;
		args.url = url;
		args.ns_max_versions = meta2_max_versions;

		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (!(err = m2db_copy_alias(&args, src)))
				m2db_increment_version(sq3);
			err = sqlx_transaction_end(repctx, err);
		}
		m2b_close(sq3);
	}

	return err;
}

GError *
meta2_backend_update_content(struct meta2_backend_s *m2b, struct oio_url_s *url,
		GSList *in, GSList **out_deleted, GSList **out_added)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);
	if (!in)
		return NEWERROR(CODE_BAD_REQUEST, "No bean");

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (!(err = m2db_update_content(sq3, url, in,
						out_deleted, out_added)))
				m2db_increment_version(sq3);
			err = sqlx_transaction_end(repctx, err);
			if (!err)
				m2b_add_modified_container(m2b, sq3);
		}
		m2b_close(sq3);
	}

	return err;
}

GError *
meta2_backend_truncate_content(struct meta2_backend_s *m2b,
		struct oio_url_s *url, gint64 truncate_size,
		GSList **out_deleted, GSList **out_added)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);
	if (truncate_size < 0)
		return NEWERROR(CODE_BAD_REQUEST, "Negative truncate size!");

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (!(err = m2db_truncate_content(sq3, url, truncate_size,
						out_deleted, out_added)))
				m2db_increment_version(sq3);
			err = sqlx_transaction_end(repctx, err);
			if (!err)
				m2b_add_modified_container(m2b, sq3);
		}
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_force_alias(struct meta2_backend_s *m2b, struct oio_url_s *url,
		GSList *in, GSList **out_deleted, GSList **out_added)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(out_deleted != NULL);
	EXTRA_ASSERT(out_added != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {

		struct m2db_put_args_s args;
		memset(&args, 0, sizeof(args));
		args.sq3 = sq3;
		args.url = url;
		args.ns_max_versions = meta2_max_versions;

		if (!(err = _transaction_begin(sq3,url, &repctx))) {
			if (!(err = m2db_force_alias(&args, in, out_deleted, out_added)))
				m2db_increment_version(sq3);
			err = sqlx_transaction_end(repctx, err);
		}
		if (!err)
			m2b_add_modified_container(m2b, sq3);

		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_insert_beans(struct meta2_backend_s *m2b,
		struct oio_url_s *url, GSList *beans, gboolean force)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;
	int error_already = 0;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (force)
				err = _db_save_beans_list (sq3->db, beans);
			else
				err = _db_insert_beans_list (sq3->db, beans);
			if (!err)
				m2db_increment_version(sq3);
			else {
				/* A constraint error is usually raised by an actual constraint
				 * violation in the DB (inside the transaction) or also by a
				 * failure of the commit hook (on the final COMMIT). */
				error_already |= (err->code == SQLITE_CONSTRAINT);
			}
			err = sqlx_transaction_end(repctx, err);
		}
		m2b_close(sq3);
	}

	if (error_already) {
		EXTRA_ASSERT(err != NULL);
		g_clear_error(&err);
		err = NEWERROR(CODE_CONTENT_EXISTS, "Bean already present");
	}

	return err;
}

GError*
meta2_backend_link_content (struct meta2_backend_s *m2b,
		struct oio_url_s *url, GBytes *content_id)
{
	EXTRA_ASSERT (m2b != NULL);
	EXTRA_ASSERT (url != NULL);
	EXTRA_ASSERT (content_id != NULL);

	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	err = m2b_open (m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (err) return err;

	if (!(err = sqlx_transaction_begin (sq3, &repctx))) {
		if (NULL != (err = m2db_link_content (sq3, url, content_id)))
			GRID_DEBUG("Link failed: (%d) %s", err->code, err->message);
		err = sqlx_transaction_end (repctx, err);
	}

	m2b_close (sq3);
	return err;
}

GError*
meta2_backend_delete_beans(struct meta2_backend_s *m2b,
		struct oio_url_s *url, GSList *beans)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			for (; !err && beans; beans = beans->next) {
				if (unlikely(NULL == beans->data))
					continue;
				err = _db_delete_bean (sq3->db, beans->data);
			}
			if (!err)
				m2db_increment_version(sq3);
			err = sqlx_transaction_end(repctx, err);
		}
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_update_beans(struct meta2_backend_s *m2b, struct oio_url_s *url,
		GSList *new_chunks, GSList *old_chunks, gboolean frozen)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	if (g_slist_length(new_chunks) != g_slist_length(old_chunks))
		return NEWERROR(CODE_BAD_REQUEST, "BeanSet length mismatch");
	for (GSList *l0=new_chunks, *l1=old_chunks; l0 && l1 ;l0=l0->next,l1=l1->next) {
		if (!l0->data || !l1->data)
			return NEWERROR(CODE_BAD_REQUEST, "BeanSet validity mismatch");
		if (DESCR(l0->data) != DESCR(l1->data))
			return NEWERROR(CODE_BAD_REQUEST, "BeanSet type mismatch");
	}

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);
	gint flags = M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED;
	if (frozen)
		flags |= M2V2_OPEN_FROZEN;
	err = m2b_open(m2b, url, flags, &sq3);
	if (!err) {
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			for (GSList *l0=old_chunks, *l1=new_chunks;
					!err && l0 && l1 ; l0=l0->next,l1=l1->next)
				err = _db_substitute_bean(sq3->db, l0->data, l1->data);
			if (!err)
				m2db_increment_version(sq3);
			err = sqlx_transaction_end(repctx, err);
		}
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_get_alias_version(struct meta2_backend_s *m2b,
		struct oio_url_s *url, gint64 *version)
{
	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = m2b_open(m2b, url, _mode_readonly(0), &sq3);
	if (!err) {
		err = m2db_get_alias_version(sq3, url, version);
		m2b_close(sq3);
	}
	return err;
}

GError*
meta2_backend_append_to_alias(struct meta2_backend_s *m2b,
		struct oio_url_s *url, GSList *beans,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;
	struct namespace_info_s *nsinfo = NULL;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);
	if (!beans)
		return NEWERROR(CODE_BAD_REQUEST, "No bean");
	if (!(nsinfo = meta2_backend_get_nsinfo (m2b)))
		return NEWERROR(CODE_INTERNAL_ERROR, "NS not ready");

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (!(err = m2db_append_to_alias(sq3, url, beans, cb, u0)))
				m2db_increment_version(sq3);
			err = sqlx_transaction_end(repctx, err);
		}
		if (!err)
			m2b_add_modified_container(m2b, sq3);
		m2b_close(sq3);
	}

	namespace_info_free (nsinfo);
	return err;
}

GError*
meta2_backend_get_properties(struct meta2_backend_s *m2b,
		struct oio_url_s *url, guint32 flags,
		m2_onbean_cb cb, gpointer u0)
{
	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = m2b_open(m2b, url, _mode_readonly(flags), &sq3);
	if (!err) {
		err = m2db_get_properties(sq3, url, cb, u0);
		m2b_close(sq3);
	}
	return err;
}

GError*
meta2_backend_del_properties(struct meta2_backend_s *m2b,
		struct oio_url_s *url, gchar **propv)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (!(err = m2db_del_properties(sq3, url, propv)))
				m2db_increment_version(sq3);
			err = sqlx_transaction_end(repctx, err);
		}
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_set_properties(struct meta2_backend_s *m2b, struct oio_url_s *url,
		gboolean flush, GSList *beans, m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	GRID_TRACE("M2 PROPSET(%s)", oio_url_get(url, OIOURL_WHOLE));

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (!(err = m2db_set_properties(sq3, url, flush, beans, cb, u0)))
				m2db_increment_version(sq3);
			err = sqlx_transaction_end(repctx, err);
		}
		m2b_close(sq3);
	}

	return err;
}

/* dedup -------------------------------------------------------------------- */

GError*
meta2_backend_dedup_contents(struct meta2_backend_s *m2b, struct oio_url_s *url)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;
	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		if (!(err = _transaction_begin(sq3,url, &repctx))) {
			err = m2db_deduplicate_contents(sq3, url);
			err = sqlx_transaction_end(repctx, err);
		}
		m2b_close(sq3);
	}
	return err;
}

/* Beans generation --------------------------------------------------------- */

static void
_cb_has_not(gpointer udata, gpointer bean)
{
	if (!bean)
		return;
	*((gboolean*)udata) = FALSE;
	_bean_clean(bean);
}

static GError*
_check_alias_doesnt_exist(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url)
{
	gboolean no_bean = TRUE;
	GError *err = m2db_get_alias(sq3, url, M2V2_FLAG_NODELETED,
			_cb_has_not, &no_bean);
	if (NULL != err) {
		if (err->code == CODE_CONTENT_NOTFOUND) {
			g_clear_error(&err);
		} else {
			g_prefix_error(&err, "Could not check the ALIAS is present"
					" (multiple versions not allowed): ");
		}
	}
	else if (!no_bean)
		err = NEWERROR(CODE_CONTENT_EXISTS, "Alias already present");

	return err;
}

/* Create, save in cache, and possibly return m2_prepare_data */
static void
_meta2_backend_force_prepare_data_unlocked(struct meta2_backend_s *m2b,
		const gchar *key, struct m2_prepare_data *pdata_out,
		struct sqlx_sqlite3_s *sq3)
{
	GRID_DEBUG("Forcing M2_PREPARE data for %s", key);

	struct m2_prepare_data *pdata = g_hash_table_lookup(
			m2b->prepare_data_cache, key);
	if (!pdata) {
		pdata = g_malloc0(sizeof(struct m2_prepare_data));
		g_hash_table_insert(m2b->prepare_data_cache, g_strdup(key), pdata);
	}

	pdata->max_versions = _maxvers(sq3);
	pdata->quota = m2db_get_quota(sq3, meta2_container_max_size);
	pdata->size = m2db_get_size(sq3);
	gchar *stgpol = _stgpol(sq3);
	g_strlcpy(pdata->storage_policy, stgpol, LIMIT_LENGTH_STGPOLICY);
	g_free(stgpol);

	if (pdata_out)
		memcpy(pdata_out, pdata, sizeof(struct m2_prepare_data));
}

/**
 * Update the data structure allowing to answer PREPARE requests
 * without taking the lock on the database file.
 */
static void
_meta2_backend_force_prepare_data(struct meta2_backend_s *m2b,
		const gchar *key, struct sqlx_sqlite3_s *sq3)
{
	g_rw_lock_writer_lock(&(m2b->prepare_data_lock));
	_meta2_backend_force_prepare_data_unlocked(m2b, key, NULL, sq3);
	g_rw_lock_writer_unlock(&(m2b->prepare_data_lock));
}

void
meta2_backend_change_callback(struct sqlx_sqlite3_s *sq3,
		struct meta2_backend_s *m2b)
{
	gchar *account = sqlx_admin_get_str(sq3, SQLX_ADMIN_ACCOUNT);
	gchar *user = sqlx_admin_get_str(sq3, SQLX_ADMIN_USERNAME);
	if (!account || !user) {
		GRID_WARN("Missing "SQLX_ADMIN_ACCOUNT" or "SQLX_ADMIN_USERNAME
				" in database %s", sq3->path_inline);
	} else {
		struct oio_url_s *url = oio_url_empty();
		oio_url_set(url, OIOURL_NS, m2b->ns_name);
		oio_url_set(url, OIOURL_ACCOUNT, account);
		oio_url_set(url, OIOURL_USER, user);

		_meta2_backend_force_prepare_data(m2b,
				oio_url_get(url, OIOURL_HEXID), sq3);

		oio_url_clean(url);
	}
	g_free(user);
	g_free(account);
}

/**
 * Get m2_prepare_data from the cache if available. If it's not,
 * get it from the database and return a pointer to the open database.
 *
 * @param m2b
 * @param url
 * @param pdata_out preallocated (on the stack) output prepare data
 * @param sq3 output database pointer, in case we were forced to open it
 */
static GError*
m2b_get_prepare_data(struct meta2_backend_s *m2b,
		struct oio_url_s *url, struct m2_prepare_data *pdata_out,
		struct sqlx_sqlite3_s **sq3)
{
	GError *err = NULL;
	struct m2_prepare_data *pdata = NULL;
	const gchar *key = oio_url_get(url, OIOURL_HEXID);

	g_rw_lock_reader_lock(&(m2b->prepare_data_lock));
	pdata = g_hash_table_lookup(m2b->prepare_data_cache, key);
	if (pdata)  // do this while still locked
		memcpy(pdata_out, pdata, sizeof(struct m2_prepare_data));
	g_rw_lock_reader_unlock(&(m2b->prepare_data_lock));

	if (!pdata) {
		// Prepare data is not available. Open the base, take the writer lock
		// and check again, in case another thread did the job while we were
		// waiting for the base or the writer lock.
		err = m2b_open(m2b, url, _mode_readonly(0), sq3);
		if (!err) {
			g_rw_lock_writer_lock(&(m2b->prepare_data_lock));
			pdata = g_hash_table_lookup(m2b->prepare_data_cache, key);
			if (pdata) {
				memcpy(pdata_out, pdata, sizeof(struct m2_prepare_data));
			} else {
				_meta2_backend_force_prepare_data_unlocked(m2b, key,
						pdata_out, *sq3);
			}
			g_rw_lock_writer_unlock(&(m2b->prepare_data_lock));
		}
	}
	// Do not close sq3, the caller will do it
	return err;
}

GError *
meta2_backend_check_content(struct meta2_backend_s *m2b,
		GSList *beans, GString *message, gboolean update)
{
	GError *err = NULL;
	struct namespace_info_s *nsinfo = NULL;
	if (!(nsinfo = meta2_backend_get_nsinfo(m2b)))
		return NEWERROR(CODE_INTERNAL_ERROR, "NS not ready");

	err = m2db_check_content(beans, nsinfo, message, update);
	namespace_info_free(nsinfo);
	return err;
}

GError*
meta2_backend_generate_beans(struct meta2_backend_s *m2b,
		struct oio_url_s *url, gint64 size, const gchar *polname,
		gboolean append, m2_onbean_cb cb, gpointer cb_data)
{
	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = NULL;
	struct namespace_info_s *nsinfo;
	struct storage_policy_s *policy = NULL;
	struct m2_prepare_data pdata = {0};

	GRID_TRACE("BEANS(%s,%"G_GINT64_FORMAT",%s)", oio_url_get(url, OIOURL_WHOLE),
			size, polname);
	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(cb != NULL);

	if (!(nsinfo = meta2_backend_get_nsinfo(m2b)))
		return NEWERROR(CODE_INTERNAL_ERROR, "NS not ready");

	/* Get the data needed for the beans preparation.
	 * This call may return an open database. */
	m2b_get_prepare_data(m2b, url, &pdata, &sq3);

	if (m2b->flag_precheck_on_generate &&
			VERSIONS_DISABLED(pdata.max_versions)) {
		err = m2b_open_if_needed(m2b, url,
				_mode_masterslave(0)|M2V2_OPEN_ENABLED, &sq3);
		if (!err) {
			/* If the versioning is not supported, we check the content
			 * is not present */
			err = _check_alias_doesnt_exist(sq3, url);
			if (append) {
				if (err) {
					g_clear_error(&err);
					err = NULL;
				} else {
					err = NEWERROR(CODE_CONTENT_NOTFOUND, "Content [%s] "
							"not found", oio_url_get(url, OIOURL_PATH));
				}
			}
		}
	}

	/* Now check the storage policy */
	if (!err) {
		if (append) {
			/* When appending, we must get the storage policy of
			 * the existing content, thus we must open the base. */
			err = m2b_open_if_needed(m2b, url,
					_mode_masterslave(0)|M2V2_OPEN_ENABLED, &sq3);
			if (!err)
				err = m2db_get_storage_policy(sq3, url, nsinfo, append,
						&policy);
			if (err || !policy) {
				gchar *def = oio_var_get_string(oio_ns_storage_policy);
				if (oio_str_is_set(def)) {
					if (!(policy = storage_policy_init(nsinfo, def)))
						err = NEWERROR(CODE_POLICY_NOT_SUPPORTED,
								"Invalid policy [%s]", def);
				}
				g_free0(def);
			}
		} else {
			if (!polname)
				polname = pdata.storage_policy;

			if (!(policy = storage_policy_init(nsinfo, polname))) {
				err = NEWERROR(CODE_POLICY_NOT_SUPPORTED,
							"Invalid policy [%s]", polname);
			}
		}
	}

	/* check container not full */
	if (!err && pdata.quota > 0 && pdata.quota <= pdata.size)
		err = NEWERROR(CODE_CONTAINER_FULL,
				"Container's quota reached (%"G_GINT64_FORMAT" bytes)",
				pdata.quota);

	m2b_close(sq3);

	/* Let's continue to generate the beans, no need for an open container for the moment */
	if (!err) {
		err = m2_generate_beans(url, size, oio_ns_chunk_size,
				policy, m2b->lb, cb, cb_data);
	}

	namespace_info_free(nsinfo);
	storage_policy_clean(policy);
	return err;
}

static GError*
_load_storage_policy(struct meta2_backend_s *m2b, struct oio_url_s *url,
		const gchar *polname, struct storage_policy_s **pol)
{
	GError *err = NULL;
	namespace_info_t *nsinfo = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	if (!(nsinfo = meta2_backend_get_nsinfo(m2b)))
		return NEWERROR(CODE_INTERNAL_ERROR, "NS not ready");

	if (polname) {
		if (!(*pol = storage_policy_init(nsinfo, polname)))
			err = NEWERROR(CODE_POLICY_NOT_SUPPORTED, "Invalid policy [%s]",
					polname);
	} else {
		err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY
				|M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN, &sq3);
		if (!err) {
			/* check pol from container / ns */
			err = m2db_get_storage_policy(sq3, url, nsinfo, FALSE, pol);
			if (err || !*pol) {
				gchar *def = oio_var_get_string(oio_ns_storage_policy);
				if (oio_str_is_set(def)) {
					if (!(*pol = storage_policy_init(nsinfo, def)))
						err = NEWERROR(CODE_POLICY_NOT_SUPPORTED,
								"Invalid policy [%s]", def);
				}
				g_free0(def);
			}
		}
		m2b_close(sq3);
	}

	namespace_info_free(nsinfo);
	return err;
}

GError*
meta2_backend_get_conditionned_spare_chunks_v2(struct meta2_backend_s *m2b,
		struct oio_url_s *url, const gchar *polname, GSList *notin,
		GSList *broken, GSList **result)
{
	struct storage_policy_s *pol = NULL;
	GError *err = _load_storage_policy(m2b, url, polname, &pol);
	if (!err)
		err = get_conditioned_spare_chunks(m2b->lb,
				storage_policy_get_service_pool(pol),
				m2b->ns_name, notin, broken, result);
	if (pol)
		storage_policy_clean(pol);
	return err;
}

GError*
meta2_backend_get_spare_chunks(struct meta2_backend_s *m2b, struct oio_url_s *url,
		const char *polname, GSList **result)
{
	GRID_TRACE("SPARE(%s,%s)", oio_url_get(url, OIOURL_WHOLE), polname);
	EXTRA_ASSERT(m2b != NULL);

	// TODO: we can avoid instantiating storage policy
	// but we need to review several function calls
	struct storage_policy_s *pol = NULL;
	GError *err = _load_storage_policy(m2b, url, polname, &pol);
	if (!err)
		err = get_spare_chunks(m2b->lb, storage_policy_get_service_pool(pol),
				result);
	if (pol)
		storage_policy_clean(pol);
	return err;
}

/* Contents lookup ---------------------------------------------------------- */

GError*
meta2_backend_content_from_chunkid(struct meta2_backend_s *m2b,
		struct oio_url_s *url, const char *chunk_id,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	err = m2b_open(m2b, url, _mode_readonly(0), &sq3);
	if (!err) {
		GVariant *params[2] = {NULL, NULL};
		params[0] = g_variant_new_string(chunk_id);
		err = CONTENTS_HEADERS_load (sq3->db, " id IN"
				" (SELECT DISTINCT content FROM chunks "
				"  WHERE id = ?) LIMIT 1", params, cb, u0);
		metautils_gvariant_unrefv(params);
		if (!err) {
			/* TODO follow the FK to the aliases */
		}
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_content_from_contenthash (struct meta2_backend_s *m2b,
		struct oio_url_s *url, GBytes *h,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	err = m2b_open(m2b, url, _mode_readonly(0), &sq3);
	if (!err) {
		GVariant *params[2] = {NULL, NULL};
		params[0] = _gb_to_gvariant(h);
		err = CONTENTS_HEADERS_load (sq3->db, " hash = ?", params, cb, u0);
		metautils_gvariant_unrefv(params);
		if (!err) {
			/* TODO follow the FK to the aliases */
		}
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_content_from_contentid (struct meta2_backend_s *m2b,
		struct oio_url_s *url, GBytes *h,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	err = m2b_open(m2b, url, _mode_readonly(0), &sq3);
	if (!err) {
		GVariant *params[2] = {NULL, NULL};
		params[0] = _gb_to_gvariant(h);
		err = CONTENTS_HEADERS_load (sq3->db, " id = ?", params, cb, u0);
		metautils_gvariant_unrefv(params);
		if (!err) {
			/* TODO follow the FK to the aliases */
		}
		m2b_close(sq3);
	}

	return err;
}

