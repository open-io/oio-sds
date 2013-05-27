/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "./meta2_backend_internals.h"
#include <meta2v2_remote.h>
#include <gridcluster.h>
#include <storage_policy.h>
#include <resolv.h>

#include <generic.h>
#include <autogen.h>

#include "../meta2/remote/meta2_remote.h"

enum m2v2_open_type_e
{
	M2V2_OPENBASE_LOCAL       = 0x00,
	M2V2_OPENBASE_MASTERONLY  = 0x01,
	M2V2_OPENBASE_MASTERSLAVE = 0x02,
	M2V2_OPENBASE_SLAVEONLY   = 0x03,
	M2V2_OPENBASE_AUTOCREATE  = 0x10,
};

static gint64
m2b_quota(struct meta2_backend_s *m2b)
{
	struct namespace_info_s nsinfo;
	gint64 quota;

	memset(&nsinfo, 0, sizeof(nsinfo));
	meta2_backend_get_nsinfo(m2b, &nsinfo);
	quota = namespace_container_max_size(&nsinfo);
	namespace_info_clear(&nsinfo);

	return quota;
}

static inline gint64
_quota(struct sqlx_sqlite3_s *sq3, struct meta2_backend_s *m2b)
{
	return m2db_get_quota(sq3->db, m2b_quota(m2b));
}

static gint64
m2b_max_versions(struct meta2_backend_s *m2b)
{
	struct namespace_info_s nsinfo;
	gint64 max_versions;

	memset(&nsinfo, 0, sizeof(nsinfo));
	meta2_backend_get_nsinfo(m2b, &nsinfo);
	max_versions = gridcluster_get_container_max_versions(&nsinfo);
	namespace_info_clear(&nsinfo);

	return max_versions;
}

static inline gint64
_maxvers(struct sqlx_sqlite3_s *sq3, struct meta2_backend_s *m2b)
{
	return m2db_get_max_versions(sq3->db, m2b_max_versions(m2b));
}

/* ------------------------------------------------------------------------- */

void
transient_put(GTree *tree, const gchar *key, gpointer what, GDestroyNotify cleanup)
{
	struct transient_element_s *elt;

	g_assert(tree != NULL);
	g_assert(key != NULL);
	g_assert(what != NULL);

	elt = g_tree_lookup(tree, key);
	if (elt) {
		if (elt->what && elt->cleanup)
			elt->cleanup(elt->what);
	}
	else {
		elt = g_malloc0(sizeof(*elt));
		g_tree_insert(tree, g_strdup(key), elt);
	}

	elt->expiration = time(0) + 3600;
	elt->what = what;
	elt->cleanup = cleanup;
}

gpointer
transient_get(GTree *tree, const gchar *key)
{
	struct transient_element_s *elt;

	g_assert(tree != NULL);
	g_assert(key != NULL);

	elt = g_tree_lookup(tree, key);
	if (elt) {
		elt->expiration = time(0) + 3600;
		return elt->what;
	}

	return NULL;
}

void
transient_del(GTree *tree, const gchar *key)
{
	g_assert(tree != NULL);
	g_assert(key != NULL);

	g_tree_remove(tree, key);
}

void
transient_cleanup(GTree *tree)
{
	struct arg_s {
		GSList *to_delete;
		time_t expiration;
	};

	auto gboolean cb(gpointer k, gpointer v, gpointer u);

	gboolean cb(gpointer k, gpointer v, gpointer u) {
		struct arg_s *parg = u;
		struct transient_element_s *elt = v;
		if (elt->expiration < parg->expiration)
			parg->to_delete = g_slist_prepend(parg->to_delete, k);
		return FALSE;
	}

	struct arg_s arg;
	arg.to_delete = NULL;
	arg.expiration = time(0) - 3600;

	g_tree_foreach(tree, cb, &arg);

	if (arg.to_delete) {
		GSList *l;
		for (l=arg.to_delete; l ;l=l->next) {
			g_tree_remove(tree, l->data);
			l->data = NULL;
		}
		g_slist_free(arg.to_delete);
	}
}

/* -------------------------------------------------------------------------- */

GError *
m2b_transient_put(struct meta2_backend_s *m2b, const gchar *key, const gchar * hexID,
		gpointer what, GDestroyNotify cleanup)
{
	g_assert(m2b != NULL);
	g_assert(key != NULL);
	g_assert(what != NULL);

	GError *err = NULL;

	if (hexID != NULL)
		err = sqlx_repository_status_base(m2b->repo, META2_TYPE_NAME, hexID);
	if ( !err ) {
		g_mutex_lock(m2b->lock_transient);
		transient_put(m2b->tree_transient, key, what, cleanup);
		g_mutex_unlock(m2b->lock_transient);
	}
	return err;
}

gpointer
m2b_transient_get(struct meta2_backend_s *m2b, const gchar *key, const gchar * hexID, GError ** err)
{
	gpointer result;

	g_assert(m2b != NULL);
	g_assert(key != NULL);

	GError *local_err = NULL;

	if (hexID != NULL)
		local_err = sqlx_repository_status_base(m2b->repo, META2_TYPE_NAME, hexID);

	if (local_err) {
		*err = local_err;
		return NULL;
	}
	g_mutex_lock(m2b->lock_transient);
	result = transient_get(m2b->tree_transient, key);
	g_mutex_unlock(m2b->lock_transient);

	return result;
}

GError *
m2b_transient_del(struct meta2_backend_s *m2b, const gchar *key, const gchar * hexID)
{
	g_assert(m2b != NULL);
	g_assert(key != NULL);

	GError *err = NULL;

	if (hexID != NULL)
		err = sqlx_repository_status_base(m2b->repo, META2_TYPE_NAME, hexID);
	if ( !err ) {
		g_mutex_lock(m2b->lock_transient);
		transient_del(m2b->tree_transient, key);
		g_mutex_unlock(m2b->lock_transient);
	}
	return err;
}

void
m2b_transient_cleanup(struct meta2_backend_s *m2b)
{
	g_assert(m2b != NULL);

	g_mutex_lock(m2b->lock_transient);
	transient_cleanup(m2b->tree_transient);
	g_mutex_unlock(m2b->lock_transient);
}

/* Backend ------------------------------------------------------------------ */

void
meta2_file_locator(gpointer ignored, const gchar *n, const gchar *t,
		GString *result)
{
	(void) ignored;
	ASSERT_EXTRA(t != NULL);
	g_string_truncate(result, 0);
	g_string_append(result, n);
}

static GError*
_check_policy(struct meta2_backend_s *m2, const gchar *polname)
{
	GError *err = NULL;
	struct storage_policy_s *policy = NULL;
	struct namespace_info_s nsinfo;

	if (!*polname)
		return NEWERROR(400, "Invalid policy: %s", "empty");

	memset(&nsinfo, 0, sizeof(nsinfo));
	if (!meta2_backend_get_nsinfo(m2, &nsinfo))
		return NEWERROR(500, "Invalid policy: %s", "NS not ready");

	if (!(policy = storage_policy_init(&nsinfo, polname)))
		err = NEWERROR(CODE_POLICY_NOT_SUPPORTED, "Invalid policy: %s", "not found");
	else
		storage_policy_clean(policy);

	namespace_info_clear(&nsinfo);
	return err;
}

GError *
meta2_backend_init(struct meta2_backend_s **result,
		struct sqlx_repository_s *repo, const gchar *ns)
{
	GError *err = NULL;
	struct meta2_backend_s *m2 = NULL;
	gsize s;

	g_assert(result != NULL);
	m2 = g_malloc0(sizeof(struct meta2_backend_s));

	s = metautils_strlcpy_physical_ns(m2->ns_name, ns, sizeof(m2->ns_name));
	if (sizeof(m2->ns_name) <= s) {
		g_free(m2);
		return NEWERROR(400, "Namespace too long");
	}

	m2->repo = repo;
	m2->policies = service_update_policies_create();
	m2->lock_ns_info = g_mutex_new();
	m2->lock = g_mutex_new();
	m2->lock_transient = g_mutex_new();
	m2->tree_transient = g_tree_new_full(metautils_strcmp3, NULL, g_free, NULL);
	m2->tree_lb = g_tree_new_full(metautils_strcmp3, NULL, g_free, NULL);

	m2->event.lock = g_mutex_new();
	m2->event.dir = g_strdup("/GRID/common/spool");

	err = sqlx_repository_configure_type(m2->repo, META2_TYPE_NAME, NULL,
			schema);
	if (NULL != err) {
		meta2_backend_clean(m2);
		g_prefix_error(&err, "Backend init error: ");
		return err;
	}

	sqlx_repository_set_locator(m2->repo, meta2_file_locator, NULL);

	GRID_DEBUG("M2V2 backend created for NS[%s] and repo[%p]",
			m2->ns_name, m2->repo);

	*result = m2;
	return NULL;
}

void
meta2_backend_clean(struct meta2_backend_s *m2)
{
	if (!m2) {
		return;
	}
	if (m2->policies) {
		service_update_policies_destroy(m2->policies);
	}
	if (m2->tree_lb) {
		g_tree_destroy(m2->tree_lb);
	}
	if (m2->lock) {
		g_mutex_free(m2->lock);
	}
	if (m2->lock_ns_info) {
		g_mutex_free(m2->lock_ns_info);
	}
	if (m2->event.lock) {
		g_mutex_free(m2->event.lock);
	}
	if (m2->event.dir) {
		g_free(m2->event.dir);
	}
	namespace_info_clear(&(m2->ns_info));
	g_free(m2);
}

void
meta2_backend_configure_type(struct meta2_backend_s *m2, const gchar *type,
		struct grid_lb_iterator_s *iter)
{
	ASSERT_EXTRA(type != NULL);
	ASSERT_EXTRA(*type != '\0');

	if (!m2 || !m2->tree_lb) {
		return ;
	}

	g_mutex_lock(m2->lock);
	if (iter) {
		g_tree_insert(m2->tree_lb, g_strdup(type), iter);
	}
	else {
		g_tree_remove(m2->tree_lb, type);
	}
	g_mutex_unlock(m2->lock);

	if (iter) {
		GRID_TRACE("Configured LB for [%s]", type);
	}
}

void
meta2_backend_configure_nsinfo(struct meta2_backend_s *m2,
		struct namespace_info_s *ns_info)
{
	ASSERT_EXTRA(m2 != NULL);
	ASSERT_EXTRA(ns_info != NULL);

	g_mutex_lock(m2->lock_ns_info);
	(void) namespace_info_copy(ns_info, &(m2->ns_info), NULL);
	g_mutex_unlock(m2->lock_ns_info);
}

gboolean
meta2_backend_get_nsinfo(struct meta2_backend_s *m2,
		struct namespace_info_s *dst)
{
	gboolean rc = FALSE;

	ASSERT_EXTRA(m2 != NULL);
	ASSERT_EXTRA(dst != NULL);

	g_mutex_lock(m2->lock_ns_info);
	if (m2->ns_info.name[0]) {
		(void) namespace_info_copy(&(m2->ns_info), dst, NULL);
		rc = TRUE;
	}
	g_mutex_unlock(m2->lock_ns_info);

	return rc;
}

GError*
meta2_backend_poll_service(struct meta2_backend_s *m2,
		const gchar *type, struct service_info_s **si)
{
	struct grid_lb_iterator_s *iter;
	GError *err = NULL;

	g_assert(m2 != NULL);
	g_assert(type != NULL);
	g_assert(si != NULL);

	g_mutex_lock(m2->lock);
	if (!(iter = g_tree_lookup(m2->tree_lb, type)))
		err = g_error_new(GQ(), CODE_SRVTYPE_NOTMANAGED, "no such service");
	else if (!grid_lb_iterator_next(iter, si, 300))
		err = g_error_new(GQ(), CODE_SRVTYPE_NOTMANAGED,
			"no service available");
	g_mutex_unlock(m2->lock);

	return err;
}

gboolean
meta2_backend_initiated(struct meta2_backend_s *m2)
{
	gboolean rc;

	ASSERT_EXTRA(m2 != NULL);

	g_mutex_lock(m2->lock_ns_info);
	rc = (m2->ns_info.name[0] != '\0');
	g_mutex_unlock(m2->lock_ns_info);

	return rc;
}

/* Container -------------------------------------------------------------- */

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
		GRID_INFO("Closing and destroying [%s][%s]",
				sq3->logical_name, sq3->logical_type);
		sq3->deleted = TRUE;
		sqlx_repository_unlock_and_close_noerror(sq3);
	}
}

static GError *
m2b_open(struct meta2_backend_s *m2, struct hc_url_s *url,
		enum m2v2_open_type_e how, struct sqlx_sqlite3_s **result)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	ASSERT_EXTRA(url != NULL);
	ASSERT_EXTRA(result != NULL);
	ASSERT_EXTRA(m2 != NULL);
	ASSERT_EXTRA(m2->repo != NULL);

	if ( how != M2V2_OPENBASE_LOCAL) {
		err = sqlx_repository_status_base(m2->repo, META2_TYPE_NAME,
				hc_url_get(url, HCURL_HEXID));
		if (!err) { /* MASTER */
			if ((how&M2V2_OPENBASE_SLAVEONLY) == M2V2_OPENBASE_SLAVEONLY)
				return NEWERROR(CODE_BADOPFORSLAVE, "Not slave!");
		} else {
			if (err->code == CODE_REDIRECT) { /* SLAVE */
				if ((how&M2V2_OPENBASE_MASTERONLY) == M2V2_OPENBASE_MASTERONLY) {
					return err;
				}
				g_clear_error(&err);
			} else {
				GRID_TRACE("STATUS error [%s][%s]: (%d) %s",
					hc_url_get(url, HCURL_HEXID), META2_TYPE_NAME,err->code,
					err->message);
				return err;
			}
		}
	}

	err = sqlx_repository_open_and_lock(m2->repo, META2_TYPE_NAME,
			hc_url_get(url, HCURL_HEXID), how & 0x1F, &sq3, NULL);
	if (!err) {
		if (!sq3->deleted) {
			*result = sq3;
			m2db_set_container_name(sq3->db, url);
		}
		else {
			err = NEWERROR(CODE_CONTAINER_FROZEN, "Retry later, destruction pending");
			m2b_close(sq3);
		}
	}
	else {
		if (err->code == CODE_CONTAINER_NOTFOUND)
			err->domain = g_quark_from_static_string(G_LOG_DOMAIN);
	}

	return err;
}

GError *
meta2_backend_has_master_container(struct meta2_backend_s *m2,
		struct hc_url_s *url)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	GRID_DEBUG("HAS(%s)", hc_url_get(url, HCURL_WHOLE));
	err = m2b_open(m2, url, M2V2_OPENBASE_MASTERONLY, &sq3);
	if (sq3) {
		sqlx_repository_unlock_and_close_noerror(sq3);
	}
	return err;
}

GError *
meta2_backend_has_container(struct meta2_backend_s *m2,
		struct hc_url_s *url)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	GRID_DEBUG("HAS(%s)", hc_url_get(url, HCURL_WHOLE));
	err = m2b_open(m2, url, M2V2_OPENBASE_MASTERSLAVE, &sq3);
	if (sq3) {
		sqlx_repository_unlock_and_close_noerror(sq3);
	}
	return err;
}

GError *
meta2_backend_create_container(struct meta2_backend_s *m2,
		struct hc_url_s *url, struct m2v2_create_params_s *params)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx;

	GRID_DEBUG("CREATE(%s,%s,%s)", hc_url_get(url, HCURL_WHOLE),
			params?params->storage_policy:NULL,
			params?params->version_policy:NULL);
	err = m2b_open(m2, url, M2V2_OPENBASE_AUTOCREATE|M2V2_OPENBASE_MASTERONLY,
			&sq3);
	if (sq3) {
		repctx = sqlx_transaction_begin(sq3);
		if (!err && params->storage_policy) {
			if (!(err = _check_policy(m2, params->storage_policy)))
				err = m2db_set_storage_policy(sq3->db, params->storage_policy, 0);
		}
		if (!err && params->version_policy) {
			gint64 max = g_ascii_strtoll(params->version_policy, NULL, 10);
			m2db_set_max_versions(sq3->db, max);
		}
		err = sqlx_transaction_end(repctx, err);
		m2b_close(sq3);
	}
	return err;
}

GError *
meta2_backend_destroy_container(struct meta2_backend_s *m2,
		struct hc_url_s *url, guint32 flags)
{
	auto void counter_cb(gpointer, gpointer);
	GError *err;
	struct sqlx_sqlite3_s *sq3 = NULL;
	guint counter = 0;

	void counter_cb(gpointer u, gpointer bean) {
		(void) u;
		(void) bean;
		counter ++;
		_bean_clean(bean);
	}

	err = meta2_backend_list_aliases(m2, url, M2V2_FLAG_NODELETED, counter_cb, NULL);
	if (!err) {
		if (counter > 0) {
			// TODO call the PURGE
			// TODO implement the FLUSH
			// TODO recompute the counter
		}
		if (counter > 0 && !(flags & M2V2_DESTROY_FORCE)) {
			return NEWERROR(CODE_CONTAINER_NOTEMPTY, "%d elements still in container", counter);
		}
		GRID_DEBUG("DESTROY(%s)", hc_url_get(url, HCURL_WHOLE));
		err = m2b_open(m2, url, M2V2_OPENBASE_LOCAL, &sq3);
		if (!err) {
			g_assert(sq3 != NULL);
			m2b_destroy(sq3);
			// TODO leave the election
		}
	}

	return err;
}

GError *
meta2_backend_purge_container(struct meta2_backend_s *m2,
                struct hc_url_s *url, GSList** del)
{
        GError *err;
        struct sqlx_sqlite3_s *sq3 = NULL;
        struct sqlx_repctx_s *repctx;

        err = m2b_open(m2, url, M2V2_OPENBASE_MASTERONLY, &sq3);
        if (!err) {
                g_assert(sq3 != NULL);
                repctx = sqlx_transaction_begin(sq3);
                err = m2db_purge(sq3->db, _maxvers(sq3, m2), del);
                err = sqlx_transaction_end(repctx, err);
                m2b_close(sq3);
        }

        return err;
}

GError*
meta2_backend_open_container(struct meta2_backend_s *m2, struct hc_url_s *url)
{
	GError *err;
	struct sqlx_sqlite3_s *sq3 = NULL;

	GRID_DEBUG("OPEN(%s)", hc_url_get(url, HCURL_WHOLE));
	err = m2b_open(m2, url, M2V2_OPENBASE_MASTERSLAVE, &sq3);
	if (!err) {
		g_assert(sq3 != NULL);
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_close_container(struct meta2_backend_s *m2,
		struct hc_url_s *url)
{
	GError *err;
	struct sqlx_sqlite3_s *sq3 = NULL;

	GRID_DEBUG("CLOSE(%s)", hc_url_get(url, HCURL_WHOLE));
	err = m2b_open(m2, url, M2V2_OPENBASE_MASTERSLAVE, &sq3);
	if (!err) {
		g_assert(sq3 != NULL);
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_set_container_properties(struct meta2_backend_s *m2b,
		struct hc_url_s *url, guint32 flags, GSList *props)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx;

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	GRID_DEBUG("PROPSET(%s,...)", hc_url_get(url, HCURL_WHOLE));
	if (!(err = m2b_open(m2b, url, M2V2_OPENBASE_MASTERONLY, &sq3))) {
		repctx = sqlx_transaction_begin(sq3);
		if (!(err = m2db_set_container_properties(sq3->db, flags, props))) {
			m2db_increment_version(sq3->db);
		}
		err = sqlx_transaction_end(repctx, err);
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_get_container_properties(struct meta2_backend_s *m2b,
		struct hc_url_s *url, guint32 flags, gpointer cb_data, m2_onprop_cb cb)
{
	GError *err;
	struct sqlx_sqlite3_s *sq3 = NULL;

	GRID_DEBUG("PROPGET(%s)", hc_url_get(url, HCURL_WHOLE));
	err = m2b_open(m2b, url, M2V2_OPENBASE_MASTERSLAVE, &sq3);
	if (!err) {
		g_assert(sq3 != NULL);
		err = m2db_get_container_properties(sq3->db, flags, cb_data, cb);
		m2b_close(sq3);
	}

	return err;
}

/* Contents --------------------------------------------------------------- */

GError*
meta2_backend_list_aliases(struct meta2_backend_s *m2b, struct hc_url_s *url,
		guint32 flags, m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	if (!(err = m2b_open(m2b, url, M2V2_OPENBASE_MASTERSLAVE, &sq3))) {
		err = m2db_list_aliases(sq3->db, flags, cb, u0);
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_get_alias(struct meta2_backend_s *m2b,
		struct hc_url_s *url, guint32 flags,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	if (!(err = m2b_open(m2b, url, M2V2_OPENBASE_MASTERSLAVE, &sq3))) {
		err = m2db_get_alias(sq3->db, url, flags, cb, u0);
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_delete_alias(struct meta2_backend_s *m2b,
		struct hc_url_s *url, m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx;
	gint64 max_versions;

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	if (!(err = m2b_open(m2b, url, M2V2_OPENBASE_MASTERONLY, &sq3))) {
		max_versions = _maxvers(sq3, m2b);
		repctx = sqlx_transaction_begin(sq3);
		if (!(err = m2db_delete_alias(sq3->db, max_versions, url, cb, u0))) {
			m2db_increment_version(sq3->db);
		}
		err = sqlx_transaction_end(repctx, err);
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_put_alias(struct meta2_backend_s *m2b, struct hc_url_s *url,
		GSList *beans, m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx;
	struct m2db_put_args_s args;

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	if (!(err = m2b_open(m2b, url, M2V2_OPENBASE_MASTERONLY, &sq3))) {

		memset(&args, 0, sizeof(args));
		args.db = sq3->db;
		args.url = url;
		args.max_versions = _maxvers(sq3, m2b);
		meta2_backend_get_nsinfo(m2b, &(args.nsinfo));

		repctx = sqlx_transaction_begin(sq3);
		if (!(err = m2db_put_alias(&args, beans, cb, u0)))
			m2db_increment_version(sq3->db);
		err = sqlx_transaction_end(repctx, err);
		m2b_close(sq3);

		namespace_info_clear(&(args.nsinfo));
	}

	return err;
}

GError*
meta2_backend_force_alias(struct meta2_backend_s *m2b,
		struct hc_url_s *url, GSList *beans)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx;

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	if (!(err = m2b_open(m2b, url, M2V2_OPENBASE_MASTERONLY, &sq3))) {
		repctx = sqlx_transaction_begin(sq3);
		if (!(err = m2db_force_alias(sq3->db, url, beans))) {
			m2db_increment_version(sq3->db);
		}
		err = sqlx_transaction_end(repctx, err);
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_delete_chunks(struct meta2_backend_s *m2b, 
		struct hc_url_s *url, GSList *beans)
{
	GError *e = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx;

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	if (!(e = m2b_open(m2b, url, M2V2_OPENBASE_MASTERONLY, &sq3))) {
		repctx = sqlx_transaction_begin(sq3);
		for(; !e && beans; beans = beans->next) {
			if(!beans->data)
				continue;
			if(DESCR(beans->data) == &descr_struct_CONTENTS) {
				e = m2db_delete_content(sq3->db, beans->data);
			}
		}
		if(!e)
			m2db_increment_version(sq3->db);
		e = sqlx_transaction_end(repctx, e);
		m2b_close(sq3);
	}

	return e;
}

GError*
meta2_backend_get_alias_version(struct meta2_backend_s *m2b,
		struct hc_url_s *url, guint32 flags, gint64 *version)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	if (!(err = m2b_open(m2b, url, M2V2_OPENBASE_MASTERSLAVE, &sq3))) {
		err = m2db_get_alias_version(sq3->db, url, flags, version);
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_append_to_alias(struct meta2_backend_s *m2b,
		struct hc_url_s *url, GSList *beans,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx;
	gint64 max_versions;

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	if (!(err = m2b_open(m2b, url, M2V2_OPENBASE_MASTERONLY, &sq3))) {
		max_versions = _maxvers(sq3, m2b);
		repctx = sqlx_transaction_begin(sq3);
		if (!(err = m2db_append_to_alias(sq3->db, max_versions, url, beans, cb, u0))) {
			m2db_increment_version(sq3->db);
		}
		err = sqlx_transaction_end(repctx, err);
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_get_properties(struct meta2_backend_s *m2b,
		struct hc_url_s *url, guint32 flags,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	if (!(err = m2b_open(m2b, url, M2V2_OPENBASE_MASTERSLAVE, &sq3))) {
		err = m2db_get_properties(sq3->db, url, flags, cb, u0);
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_get_property(struct meta2_backend_s *m2b,
		struct hc_url_s *url, const gchar *prop_name,
		guint32 flags, m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	if (!(err = m2b_open(m2b, url, M2V2_OPENBASE_MASTERSLAVE, &sq3))) {
		err = m2db_get_property(sq3->db, url, prop_name, flags, cb, u0);
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_del_property(struct meta2_backend_s *m2b,
		struct hc_url_s *url, const gchar *prop_name)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx;

	g_assert(m2b != NULL);
	g_assert(url != NULL);
	g_assert(prop_name != NULL);

	if (!(err = m2b_open(m2b, url, M2V2_OPENBASE_MASTERONLY, &sq3))) {
		repctx = sqlx_transaction_begin(sq3);
		err = m2db_del_property(sq3->db, url, prop_name);
		if (!err)
			m2db_increment_version(sq3->db);
		err = sqlx_transaction_end(repctx, err);
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_flush_property(struct meta2_backend_s *m2b,
		struct hc_url_s *url, const gchar *prop_name)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx;

	g_assert(m2b != NULL);
	g_assert(url != NULL);
	g_assert(prop_name != NULL);

	if (!(err = m2b_open(m2b, url, M2V2_OPENBASE_MASTERONLY, &sq3))) {
		repctx = sqlx_transaction_begin(sq3);
		err = m2db_flush_property(sq3->db, prop_name);
		if (!err)
			m2db_increment_version(sq3->db);
		err = sqlx_transaction_end(repctx, err);
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_set_properties(struct meta2_backend_s *m2b,
		struct hc_url_s *url, GSList *beans,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx;
	gint64 max_versions;

	GRID_TRACE("M2 GET(%s)", hc_url_get(url, HCURL_WHOLE));

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	if (!(err = m2b_open(m2b, url, M2V2_OPENBASE_MASTERONLY, &sq3))) {
		max_versions = _maxvers(sq3, m2b);
		repctx = sqlx_transaction_begin(sq3);
		if (!(err = m2db_set_properties(sq3->db, max_versions, url, beans, cb, u0))) {
			m2db_increment_version(sq3->db);
		}
		err = sqlx_transaction_end(repctx, err);
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_generate_beans(struct meta2_backend_s *m2b,
		struct hc_url_s *url, gint64 size, const gchar *polname,
		gboolean append, m2_onbean_cb cb, gpointer cb_data)
{
	return meta2_backend_generate_beans_v1(m2b, url, size, polname, append,
		NULL, NULL, cb, cb_data);
}

GError*
meta2_backend_generate_beans_v1(struct meta2_backend_s *m2b,
		struct hc_url_s *url, gint64 size, const gchar *polname,
		gboolean append, const char *mdsys, const char *mdusr,
		m2_onbean_cb cb, gpointer cb_data)
{

	auto void _cb(gpointer udata, gpointer bean);

	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = NULL;
	struct namespace_info_s nsinfo;
	struct storage_policy_s *policy = NULL;
	struct grid_lb_iterator_s *iter = NULL;
	gboolean no_bean = TRUE;

	void _cb(gpointer udata, gpointer bean) {
		(void) udata;
		if(bean) {
			no_bean = FALSE;
			_bean_clean(bean);
		}
	}

	GRID_TRACE("BEANS(%s,%"G_GINT64_FORMAT",%s)", hc_url_get(url, HCURL_WHOLE),
			size, polname);
	g_assert(m2b != NULL);
	g_assert(url != NULL);
	g_assert(cb != NULL);

	memset(&nsinfo, 0, sizeof(nsinfo));
	if (!meta2_backend_get_nsinfo(m2b, &nsinfo))
		return NEWERROR(500, "NS not ready");

	/* Several checks are to be performed on the container state */
	if (!(err = m2b_open(m2b, url, M2V2_OPENBASE_MASTERONLY, &sq3))) {

		/* If the versioning is not supported, we check the content is not present */
		gint64 max_version = _maxvers(sq3, m2b);
		if (max_version <= 0) {
			err = m2db_get_alias(sq3->db, url, M2V2_FLAG_NODELETED, _cb, NULL);
			if(NULL != err) {
				if (err->code == CODE_CONTENT_NOTFOUND) {
					g_clear_error(&err);
				} else {
					g_prefix_error(&err, "Could not check the ALIAS is present"
							" (multiple versions not allowed): ");
				}
			} else {
				if (!append && !no_bean) {
					err = NEWERROR(CODE_CONTENT_EXISTS, "Alias already present");
				}
			}
		}

		/* Now check the storage policy */
		if (!err) {
			if (polname) {
				if (!(policy = storage_policy_init(&nsinfo, polname)))
					err = NEWERROR(CODE_POLICY_NOT_SUPPORTED, "Invalid policy [%s]", polname);
			} else {
				/* check polname not in mdsys */
				char *polstr = storage_policy_from_mdsys_str(mdsys);
				GRID_TRACE("Storage policy from sys md = %s", polstr);
				if(NULL != polstr){
					if (!(policy = storage_policy_init(&nsinfo, polstr)))
						err = NEWERROR(CODE_POLICY_NOT_SUPPORTED, "Invalid policy [%s]", polstr);
					g_free(polstr);
				} else {
					err = m2db_get_storage_policy(sq3->db, url, &nsinfo, append, &policy);
					if (err || !policy) {
						gchar *default_ns_policy_name = namespace_storage_policy(&nsinfo);
						if (NULL != default_ns_policy_name) {
							if (!(policy = storage_policy_init(&nsinfo, default_ns_policy_name)))
								err = NEWERROR(CODE_POLICY_NOT_SUPPORTED, "Invalid policy [%s]", default_ns_policy_name);
							g_free(default_ns_policy_name);
						}
					}
				}
			}
		}

		/* check container not full */
		gint64 quota = _quota(sq3, m2b);
		if(quota > 0 && quota <= m2db_get_size(sq3->db))
			err = NEWERROR(CODE_CONTAINER_FULL, "Container's quota reached (%"G_GINT64_FORMAT" bytes)", quota);

		m2b_close(sq3);
	}

	/* Let's continue to generate the beans, no need for an open container for the moment */
	if (!err) {
		g_mutex_lock(m2b->lock);
		if (!(iter = g_tree_lookup(m2b->tree_lb, "rawx")))
			err = NEWERROR(CODE_POLICY_NOT_SATISFIABLE, "No RAWX available");
		else {
			err = m2_generate_beans_v1(url, size, nsinfo.chunk_size, policy, mdsys, mdusr,
					iter, cb, cb_data);
		}
		g_mutex_unlock(m2b->lock);
	}

	namespace_info_clear(&nsinfo);
	if (policy)
		storage_policy_clean(policy);
	return err;
}

GError*
meta2_backend_get_max_versions(struct meta2_backend_s *m2b,
		struct hc_url_s *url, gint64 *result)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	g_assert(m2b != NULL);
	g_assert(url != NULL);
	g_assert(result != NULL);

	if (!(err = m2b_open(m2b, url, M2V2_OPENBASE_MASTERSLAVE, &sq3))) {
		*result = _maxvers(sq3, m2b);
		m2b_close(sq3);
	}

	return err;
}

/* ------------------------------------------------------------------------- */

GError*
meta2_backend_get_container_status(struct meta2_backend_s *m2b,
		struct hc_url_s *url, guint32 *status)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	g_assert(m2b != NULL);
	g_assert(url != NULL);
	g_assert(status != NULL);

	if (!(err = m2b_open(m2b, url, M2V2_OPENBASE_MASTERSLAVE, &sq3))) {
		err = m2db_get_container_status(sq3->db, status);
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_set_container_status(struct meta2_backend_s *m2b,
		struct hc_url_s *url, guint32 *expected, guint32 repl)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx;

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	if (!(err = m2b_open(m2b, url, M2V2_OPENBASE_MASTERONLY, &sq3))) {
		repctx = sqlx_transaction_begin(sq3);
		err = m2db_set_container_status(sq3->db, expected, repl);
		err = sqlx_transaction_end(repctx, err);
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_get_all_properties(struct meta2_backend_s *m2b,
		struct hc_url_s *url, const gchar *k, guint32 flags,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err;
	struct sqlx_sqlite3_s *sq3 = NULL;

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	if (!(err = m2b_open(m2b, url, M2V2_OPENBASE_MASTERSLAVE, &sq3))) {
		err = m2db_get_all_properties(sq3->db, k, flags, cb, u0);
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_update_alias_header(struct meta2_backend_s *m2b, struct hc_url_s *url,
		GSList *beans)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx;
	guint32 max_versions = 0;

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	if (!(err = m2b_open(m2b, url, M2V2_OPENBASE_MASTERONLY, &sq3))) {
		max_versions = _maxvers(sq3, m2b);
		repctx = sqlx_transaction_begin(sq3);
		err = m2db_update_alias_header(sq3->db, max_versions, url, beans);
		err = sqlx_transaction_end(repctx, err);
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_deduplicate_contents(struct meta2_backend_s *m2b,
		struct hc_url_s *url, GString **status_message)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx;
	g_assert(m2b != NULL);
	g_assert(url != NULL);

	if (!(err = m2b_open(m2b, url, M2V2_OPENBASE_MASTERONLY, &sq3))) {
		GRID_INFO("Starting content deduplication on %s",
				hc_url_get(url, HCURL_WHOLE));
		repctx = sqlx_transaction_begin(sq3);
		err = m2db_deduplicate_contents(sq3->db, url, status_message);
		if (err == NULL) {
			GRID_INFO("Finished content deduplication");
		} else {
			GRID_WARN("Got error while performing content deduplication");
		}
		err = sqlx_transaction_end(repctx, err);
		m2b_close(sq3);
	} else {
		GRID_WARN("Got error when opening database: %s", err->message);
	}
	return err;
}

GError*
meta2_backend_deduplicate_chunks(struct meta2_backend_s *m2b,
		struct hc_url_s *url)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	namespace_info_t nsinfo;
	memset(&nsinfo, 0, sizeof(nsinfo));
	meta2_backend_get_nsinfo(m2b, &nsinfo);

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	if (!(err = m2b_open(m2b, url, M2V2_OPENBASE_MASTERONLY, &sq3))) {
		GRID_INFO("Starting chunk deduplication on %s",
				hc_url_get(url, HCURL_WHOLE));
		err = m2db_deduplicate_chunks(sq3->db, &nsinfo, url);
		GRID_INFO("Finished chunk deduplication");
		m2b_close(sq3);
	} else {
		GRID_WARN("Got error when opening database: %s", err->message);
	}
	return err;
}

GError*
meta2_backend_deduplicate_alias_chunks(struct meta2_backend_s *m2b,
		struct hc_url_s *url)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	namespace_info_t nsinfo;
	memset(&nsinfo, 0, sizeof(nsinfo));
	meta2_backend_get_nsinfo(m2b, &nsinfo);

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	if (!(err = m2b_open(m2b, url, M2V2_OPENBASE_MASTERONLY, &sq3))) {
		GRID_INFO("Starting chunk deduplication on %s (%s)",
				hc_url_get(url, HCURL_WHOLE),
				hc_url_get(url, HCURL_PATH));
		m2b_close(sq3);
		err = m2db_deduplicate_alias_chunks(sq3->db, &nsinfo, url);
	} else {
		GRID_WARN("Got error when opening database: %s", err->message);
	}
	return err;
}


/* --------------- RESTORE -------------------- */

typedef GError* meta2_dumpv1_wrapper_cb(gpointer wrapper_data,
                gpointer dump_hooks_data, struct meta2_dumpv1_hooks_s *dump_hooks);

struct cb_data_s
{
	struct meta2_backend_s *m2b;
	struct sqlx_sqlite3_s *sq3;
	struct hc_url_s *url;
	GError **perr;
	gpointer notify_data;
	struct meta2_restorev1_hooks_s notify_hooks;
	gint64 max_versions;
	gboolean event_discarded;
};

static gboolean _restore_content(gpointer u, meta2_raw_content_v2_t *p);
static gboolean _restore_admin(gpointer u, key_value_pair_t *p);
static gboolean _restore_property(gpointer u, meta2_property_t *p);
static gboolean _restore_event(gpointer u, container_event_t *p);

static struct meta2_dumpv1_hooks_s dump_hooks = {
	_restore_content,
	_restore_admin,
	_restore_property,
	_restore_event,
};


struct wrapper_data_s
{
	container_id_t peer_cid;
	char peer_addr_str[STRLEN_ADDRINFO+1];
	struct metacnx_ctx_s peer_cnx;
};

static GError *
_dumpv1_wrapper(gpointer wrapper_data,
		gpointer dump_hooks_data, struct meta2_dumpv1_hooks_s *dh)
{
	GError *e = NULL; 
	int rc;
	struct wrapper_data_s *wd = wrapper_data;
	rc = meta2_remote_dumpv1_container(&(wd->peer_cnx), wd->peer_cid,
			(struct meta2_dumpv1_hooks_remote_s*)dh, dump_hooks_data,
			&e);
	if (!rc)
		g_prefix_error(&e, "Peer dump failed");

	return e; 
}

gboolean
_restore_content(gpointer u, meta2_raw_content_v2_t *p)
{
	gboolean rc = FALSE;
	struct cb_data_s *cb_data = u;
	struct sqlx_repctx_s *repctx;
	struct m2db_put_args_s args;
	GSList *beans = NULL;

	if (!p)
		return TRUE;

	g_assert(cb_data != NULL);
	GRID_TRACE("%s(%p,%p)", __FUNCTION__, u, p);

	/* path the grid URL of the current content */
	hc_url_set(cb_data->url, HCURL_PATH, p->header.path);

	/* prepare the PUT arguments */
	memset(&args, 0, sizeof(args));
	args.db = cb_data->sq3->db;
	args.url = cb_data->url;
	args.max_versions = cb_data->max_versions;
	meta2_backend_get_nsinfo(cb_data->m2b, &(args.nsinfo));

	beans = m2v2_beans_from_raw_content_v2("1", p);
	repctx = sqlx_transaction_begin(cb_data->sq3);
	if (!(*(cb_data->perr) = m2db_put_alias(&args, beans, NULL, NULL))) {
		m2db_increment_version(cb_data->sq3->db);
		rc = TRUE;
	}
	*(cb_data->perr) = sqlx_transaction_end(repctx, *(cb_data->perr));

	namespace_info_clear(&(args.nsinfo));
	meta2_raw_content_v2_clean(p);
	return rc;
}

static const gchar*
_gba_ensure(GByteArray *gba)
{
	if (!gba)
		return "";
	if (0 != gba->data[gba->len-1]) {
		g_byte_array_append(gba, (guint8*)"", 1);
		g_byte_array_set_size(gba, gba->len-1);
	}
	return (const gchar*) gba->data;
}

gboolean
_restore_admin(gpointer u, key_value_pair_t *p)
{
	auto int skip(const gchar *key);
	int skip(const gchar *key) {
		return !g_ascii_strcasecmp(key, "namespace")
			|| g_str_has_prefix(key, "sys.")
			|| g_str_has_prefix(key, "user.");
	}
	struct cb_data_s *cb_data = u;

	GRID_TRACE("%s(%p,%p)", __FUNCTION__, u, p);

	if (p) {
		if (!skip(p->key)) {
			sqlx_set_admin_entry_noerror(cb_data->sq3->db, p->key,
					_gba_ensure(p->value));
		}
		key_value_pair_clean(p);
	}

	return TRUE;
}

gboolean
_restore_property(gpointer u, meta2_property_t *p)
{
	auto int skip(const gchar *k);
	int skip(const gchar *k) {
		return !g_str_has_prefix(k, "user.")
			&& !g_str_has_prefix(k, "sys.");
	}
	struct cb_data_s *cb_data = u;

	GRID_TRACE("%s(%p,%p)", __FUNCTION__, u, p);

	if (p) {
		if (!skip(p->name)) {
			sqlx_set_admin_entry_noerror(cb_data->sq3->db, p->name,
					_gba_ensure(p->value));
		}
		meta2_property_clean(p);
	}

	return  TRUE;
}

gboolean
_restore_event(gpointer u, container_event_t *p)
{
	struct cb_data_s *cb_data = u;

	GRID_TRACE("%s(%p,%p)", __FUNCTION__, u, p);

	if (p) { /* We do nothing ATM */
		if (cb_data->event_discarded) {
			GRID_DEBUG("RESTORE [%s] : events discarded",
					hc_url_get(cb_data->url, HCURL_WHOLE));
			cb_data->event_discarded = 1;
		}
		container_event_clean(p);
	}

	return TRUE;
}


static GError*
_restore_container(struct meta2_backend_s *m2b, struct hc_url_s *url, 
		gpointer wrapper_data, meta2_dumpv1_wrapper_cb (*dump_cb),
		gpointer notify_data, struct meta2_restorev1_hooks_s (*notify_hooks))
{
	struct cb_data_s cb_data;
	GError *e = NULL, *cbe = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	g_assert(dump_cb != NULL);
	g_assert(notify_hooks != NULL);

	if (!(e = m2b_open(m2b, url, 0x00, &sq3))) {
		memset(&cb_data, '\0', sizeof(cb_data));
		cb_data.m2b = m2b;
		cb_data.sq3 = sq3;
		cb_data.url = url;
		cb_data.perr = &cbe;
		cb_data.notify_data = notify_data;
		memcpy(&(cb_data.notify_hooks), notify_hooks, sizeof(notify_hooks));
		cb_data.max_versions = _maxvers(sq3, m2b);
		e = dump_cb(wrapper_data, &cb_data, &dump_hooks);
		m2b_close(sq3);
	}


	if (NULL != e || NULL != cbe) {
		g_prefix_error(&e, "Dump|Restore failed");
		/* TODO: destroy container */
	}

	if(NULL != cbe) {
		g_clear_error(&cbe);
	}

	return e;
}

GError*
meta2_backend_restore_container_from_peer(struct meta2_backend_s *m2b,
		struct hc_url_s *url,
		const container_id_t peer_cid, const addr_info_t *peer_addr,
		gpointer notify_udata, struct meta2_restorev1_hooks_s (*notify_hooks))
{
	GError *e = NULL;
	struct wrapper_data_s wd;

	g_assert(peer_addr != NULL);
	g_assert(url != NULL);
	g_assert(peer_cid != NULL);

	// Prepare the restoration context, then connect to the peer
	memset(&wd, 0x00, sizeof(wd));
	memcpy(wd.peer_cid, peer_cid, sizeof(container_id_t));
	addr_info_to_string(peer_addr, wd.peer_addr_str, sizeof(wd.peer_addr_str)-1);
	metacnx_clear(&wd.peer_cnx);
	if (!metacnx_init_with_addr(&wd.peer_cnx, peer_addr, &e)) {
		return e;
	}
	wd.peer_cnx.timeout.cnx = 90000;
	wd.peer_cnx.timeout.req = 90000;

	if (!metacnx_open(&wd.peer_cnx, &e)) {
		metacnx_clear(&wd.peer_cnx);
		return e;
	}

	e = _restore_container(m2b, url, &wd, _dumpv1_wrapper, notify_udata, notify_hooks);

	metacnx_close(&wd.peer_cnx);
	metacnx_clear(&wd.peer_cnx);
	return e;
}

