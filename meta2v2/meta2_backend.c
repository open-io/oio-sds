/*
OpenIO SDS meta2v2
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

#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "m2v2"
#endif

#include <glib.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/event_config.h>
#include <cluster/lib/gridcluster.h>

#include <sqliterepo/sqliterepo.h>
#include <sqliterepo/election.h>

#include <meta0v2/meta0_remote.h>
#include <meta0v2/meta0_utils.h>

#include <meta1v2/meta1_remote.h>

#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>
#include <meta2v2/meta2v2_remote.h>
#include <meta2v2/meta2_macros.h>
#include <meta2v2/meta2_utils_lb.h>
#include <meta2v2/meta2_backend_internals.h>

#include <meta2/remote/meta2_remote.h>

#include <resolver/hc_resolver.h>

enum m2v2_open_type_e
{
	M2V2_OPEN_LOCAL       = 0x000,
	M2V2_OPEN_MASTERONLY  = 0x001,
	M2V2_OPEN_SLAVEONLY   = 0x002,
	M2V2_OPEN_MASTERSLAVE = 0x003,
#define M2V2_OPEN_REPLIMODE 0x00F

	M2V2_OPEN_AUTOCREATE  = 0x010,
	M2V2_OPEN_NOREFCHECK  = 0x020,
#define M2V2_OPEN_FLAGS     0x0F0

	// Set an OR'ed combination of the following flags to require
	// a check on the container's status during the open phase.
	// No flag set means no check.
	M2V2_OPEN_ENABLED     = 0x100,
	M2V2_OPEN_FROZEN      = 0x200,
	M2V2_OPEN_DISABLED    = 0x400,
#define M2V2_OPEN_STATUS    0xF00
};

#define _M2B_GET_VNS_INFO(m2b, vns, nsinfo) \
	struct namespace_info_s nsinfo;\
	memset(&nsinfo, 0, sizeof(nsinfo));\
	meta2_backend_get_nsinfo((m2b), &nsinfo);\
	if ((vns))\
		g_strlcpy(nsinfo.name, (vns), LIMIT_LENGTH_NSNAME);

static gint64
m2b_quota(struct meta2_backend_s *m2b, const gchar *vns)
{
	gint64 quota;
	_M2B_GET_VNS_INFO(m2b, vns, nsinfo)
	quota = namespace_container_max_size(&nsinfo);
	namespace_info_clear(&nsinfo);

	return quota;
}

static gint64
_quota(struct sqlx_sqlite3_s *sq3, struct meta2_backend_s *m2b)
{
	gchar *vns = m2db_get_namespace(sq3, m2b->backend.ns_name);
	gint64 res = m2db_get_quota(sq3, m2b_quota(m2b, vns));
	g_free(vns);
	return res;
}

static gint64
m2b_max_versions(struct meta2_backend_s *m2b, const gchar *vns)
{
	gint64 max_versions;
	_M2B_GET_VNS_INFO(m2b, vns, nsinfo)
	max_versions = gridcluster_get_container_max_versions(&nsinfo);
	namespace_info_clear(&nsinfo);

	return max_versions;
}

static gint64
m2b_keep_deleted_delay(struct meta2_backend_s *m2b, const gchar *vns)
{
	gint64 delay;
	_M2B_GET_VNS_INFO(m2b, vns, nsinfo)
	delay = gridcluster_get_keep_deleted_delay(&nsinfo);
	namespace_info_clear(&nsinfo);

	return delay;
}

static gint64
_maxvers(struct sqlx_sqlite3_s *sq3, struct meta2_backend_s *m2b)
{
	gchar *vns = m2db_get_namespace(sq3, m2b->backend.ns_name);
	gint64 res = m2db_get_max_versions(sq3, m2b_max_versions(m2b, vns));
	g_free(vns);
	return res;
}

static gint64
_retention_delay(struct sqlx_sqlite3_s *sq3, struct meta2_backend_s *m2b)
{
	gchar *vns = m2db_get_namespace(sq3, m2b->backend.ns_name);
	gint64 res = m2db_get_keep_deleted_delay(sq3,
			m2b_keep_deleted_delay(m2b, vns));
	g_free(vns);
	return res;
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
transient_cleanup(struct transient_s *transient)
{
	g_assert(transient != NULL);

	g_mutex_clear(&transient->lock);
	transient_tree_cleanup(transient->tree);
	g_free(transient);
}

void
transient_tree_cleanup(GTree *tree)
{
	struct arg_s {
		GSList *to_delete;
		time_t expiration;
	};

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

	if (hexID != NULL) {
		struct sqlx_name_s n = {
			.base = hexID,
			.type = META2_TYPE_NAME,
			.ns = m2b->backend.ns_name
		};
		err = sqlx_repository_status_base(m2b->backend.repo, &n);
	}
	if ( !err ) {
		struct transient_s *trans = NULL;

		g_mutex_lock(&m2b->lock_transient);
		trans = g_hash_table_lookup(m2b->transient, hexID);
		if (trans == NULL) {
			trans = g_new0(struct transient_s, 1);
			g_mutex_init(&trans->lock);
			trans->tree = g_tree_new_full(metautils_strcmp3, NULL, g_free, NULL);
			g_hash_table_insert(m2b->transient, g_strdup(hexID), trans);
		}
		g_mutex_unlock(&m2b->lock_transient);
		g_mutex_lock(&trans->lock);
		transient_put(trans->tree, key, what, cleanup);
		g_mutex_unlock(&trans->lock);
	}
	return err;
}

gpointer
m2b_transient_get(struct meta2_backend_s *m2b, const gchar *key, const gchar * hexID, GError ** err)
{
	struct transient_s *trans = NULL;

	g_assert(m2b != NULL);
	g_assert(key != NULL);

	GError *local_err = NULL;

	if (hexID != NULL) {
		struct sqlx_name_s n = {
			.base = hexID,
			.type = META2_TYPE_NAME,
			.ns = m2b->backend.ns_name,
		};
		local_err = sqlx_repository_status_base(m2b->backend.repo, &n);
	}
	if (local_err) {
		*err = local_err;
		return NULL;
	}

	g_mutex_lock(&m2b->lock_transient);
	trans = g_hash_table_lookup(m2b->transient, hexID);
	g_mutex_unlock(&m2b->lock_transient);
	if (trans == NULL) {
		*err = NEWERROR(CODE_INTERNAL_ERROR, "Transient data not found in hash");
		return NULL;
	}

	gpointer result;
	g_mutex_lock(&trans->lock);
	result = transient_get(trans->tree, key);
	g_mutex_unlock(&trans->lock);
	return result;
}

GError *
m2b_transient_del(struct meta2_backend_s *m2b, const gchar *key, const gchar * hexID)
{
	g_assert(m2b != NULL);
	g_assert(key != NULL);

	GError *err = NULL;

	if (hexID != NULL) {
		struct sqlx_name_s n = {
			.base = hexID,
			.type = META2_TYPE_NAME,
			.ns = m2b->backend.ns_name,
		};
		err = sqlx_repository_status_base(m2b->backend.repo, &n);
	}

	if ( !err ) {
		struct transient_s *trans = NULL;

		g_mutex_lock(&m2b->lock_transient);
		trans = g_hash_table_lookup(m2b->transient, hexID);
		g_mutex_unlock(&m2b->lock_transient);
		if (trans == NULL)
			return NEWERROR(CODE_INTERNAL_ERROR, "Transient data not found in hash");

		g_mutex_lock(&trans->lock);
		transient_del(trans->tree, key);
		g_mutex_unlock(&trans->lock);
	}
	return err;
}

void
m2b_transient_cleanup(struct meta2_backend_s *m2b)
{
	g_assert(m2b != NULL);

	g_mutex_lock(&m2b->lock_transient);
	g_hash_table_destroy(m2b->transient);
	g_mutex_unlock(&m2b->lock_transient);
}

/* Backend ------------------------------------------------------------------ */

void
meta2_file_locator(gpointer ignored, struct sqlx_name_s *n, GString *result)
{
	SQLXNAME_CHECK(n);
	EXTRA_ASSERT(result != NULL);
	(void) ignored;

	g_string_truncate(result, 0);
	gchar *sep = strchr(n->base, '@');
	if (!sep)
		g_string_append(result, n->base);
	else
		g_string_append(result, sep+1);
}

static GError*
_check_policy(struct meta2_backend_s *m2, const gchar *polname)
{
	GError *err = NULL;
	struct storage_policy_s *policy = NULL;
	struct namespace_info_s nsinfo;

	if (!*polname)
		return NEWERROR(CODE_BAD_REQUEST, "Invalid policy: %s", "empty");

	memset(&nsinfo, 0, sizeof(nsinfo));
	if (!meta2_backend_get_nsinfo(m2, &nsinfo))
		return NEWERROR(CODE_INTERNAL_ERROR, "Invalid policy: %s", "NS not ready");

	if (!(policy = storage_policy_init(&nsinfo, polname)))
		err = NEWERROR(CODE_POLICY_NOT_SUPPORTED, "Invalid policy: %s", "not found");
	else
		storage_policy_clean(policy);

	namespace_info_clear(&nsinfo);
	return err;
}

metautils_notif_pool_t *
meta2_backend_get_notifier(struct meta2_backend_s *m2)
{
	return event_config_repo_get_notifier(m2->backend.evt_repo);
}

struct event_config_repo_s *
meta2_backend_get_evt_config_repo(const struct meta2_backend_s *m2)
{
	return m2->backend.evt_repo;
}

const gchar*
meta2_backend_get_local_addr(struct meta2_backend_s *m2)
{
	return sqlx_repository_get_local_addr(m2->backend.repo);
}

struct event_config_s *
meta2_backend_get_event_config(struct meta2_backend_s *m2)
{
	return event_config_repo_get(m2->backend.evt_repo);
}

GError *
meta2_backend_init(struct meta2_backend_s **result,
		struct sqlx_repository_s *repo, const gchar *ns,
		struct grid_lbpool_s *glp, struct hc_resolver_s *resolver,
		struct event_config_repo_s *evt_repo)
{
	GError *err = NULL;
	struct meta2_backend_s *m2 = NULL;
	gsize s;

	g_assert(result != NULL);
	g_assert(glp != NULL);
	g_assert(repo != NULL);
	g_assert(resolver != NULL);

	m2 = g_malloc0(sizeof(struct meta2_backend_s));
	s = metautils_strlcpy_physical_ns(m2->backend.ns_name, ns,
			sizeof(m2->backend.ns_name));
	if (sizeof(m2->backend.ns_name) <= s) {
		g_free(m2);
		return NEWERROR(CODE_BAD_REQUEST, "Namespace too long");
	}

	m2->backend.type = META2_TYPE_NAME;
	m2->backend.repo = repo;
	m2->backend.lb = glp;
	m2->backend.evt_repo = evt_repo;
	m2->policies = service_update_policies_create();
	g_mutex_init(&m2->backend.ns_info_lock);
	g_mutex_init(&m2->lock_transient);
	m2->transient = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, (GDestroyNotify) transient_cleanup);

	m2->flag_precheck_on_generate = TRUE;

	err = sqlx_repository_configure_type(m2->backend.repo, META2_TYPE_NAME,
			NULL, schema);
	if (NULL != err) {
		meta2_backend_clean(m2);
		g_prefix_error(&err, "Backend init error: ");
		return err;
	}

	sqlx_repository_set_locator(m2->backend.repo, meta2_file_locator, NULL);
	m2->resolver = resolver;

	GRID_DEBUG("M2V2 backend created for NS[%s] and repo[%p]",
			m2->backend.ns_name, m2->backend.repo);

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
	if (m2->transient) {
		g_hash_table_destroy(m2->transient);
	}
	if (m2->resolver) {
		m2->resolver = NULL;
	}
	g_mutex_clear(&m2->backend.ns_info_lock);
	g_mutex_clear(&m2->lock_transient);
	namespace_info_clear(&(m2->backend.ns_info));
	g_free(m2);
}

void
meta2_backend_configure_nsinfo(struct meta2_backend_s *m2,
		struct namespace_info_s *ns_info)
{
	EXTRA_ASSERT(m2 != NULL);
	EXTRA_ASSERT(ns_info != NULL);

	g_mutex_lock(&m2->backend.ns_info_lock);
	(void) namespace_info_copy(ns_info, &(m2->backend.ns_info), NULL);
	g_mutex_unlock(&m2->backend.ns_info_lock);
}

gboolean
meta2_backend_get_nsinfo(struct meta2_backend_s *m2,
		struct namespace_info_s *dst)
{
	gboolean rc = FALSE;

	EXTRA_ASSERT(m2 != NULL);
	EXTRA_ASSERT(dst != NULL);

	g_mutex_lock(&m2->backend.ns_info_lock);
	if (m2->backend.ns_info.name[0]) {
		(void) namespace_info_copy(&(m2->backend.ns_info), dst, NULL);
		rc = TRUE;
	}
	g_mutex_unlock(&m2->backend.ns_info_lock);

	return rc;
}

GError*
meta2_backend_poll_service(struct meta2_backend_s *m2,
		const gchar *type, struct service_info_s **si)
{
	struct grid_lb_iterator_s *iter;

	g_assert(m2 != NULL);
	g_assert(type != NULL);
	g_assert(si != NULL);

	if (!(iter = grid_lbpool_get_iterator(m2->backend.lb, type)))
		return NEWERROR(CODE_SRVTYPE_NOTMANAGED, "no such service");

	struct lb_next_opt_ext_s opt_ext;
	memset(&opt_ext, 0, sizeof(opt_ext));
	opt_ext.req.distance = 0;
	opt_ext.req.max = 1;
	opt_ext.req.duplicates = TRUE;
	opt_ext.req.stgclass = NULL;
	opt_ext.req.strict_stgclass = TRUE;

	struct service_info_s **siv = NULL;
	if (!grid_lb_iterator_next_set2(iter, &siv, &opt_ext))
		return NEWERROR(CODE_SRVTYPE_NOTMANAGED, "no service available");

	*si = service_info_dup(siv[0]);
	service_info_cleanv(siv, FALSE);
	return NULL;
}

gboolean
meta2_backend_initiated(struct meta2_backend_s *m2)
{
	EXTRA_ASSERT(m2 != NULL);
	gboolean rc = (m2->backend.ns_info.name[0] != '\0');
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
	if (t & M2V2_OPEN_NOREFCHECK)
		result |= SQLX_OPEN_NOREFCHECK;

	if (t & M2V2_OPEN_ENABLED)
		result |= SQLX_OPEN_ENABLED;
	if (t & M2V2_OPEN_FROZEN)
		result |= SQLX_OPEN_FROZEN;
	if (t & M2V2_OPEN_DISABLED)
		result |= SQLX_OPEN_DISABLED;

	return result;
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
m2b_open(struct meta2_backend_s *m2, struct hc_url_s *url,
		enum m2v2_open_type_e how, struct sqlx_sqlite3_s **result)
{
	GError *err = NULL;
	gboolean no_peers = FALSE;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(result != NULL);
	EXTRA_ASSERT(m2 != NULL);
	EXTRA_ASSERT(m2->backend.repo != NULL);

	no_peers = hc_url_get_option_value(url, META2_URL_LOCAL_BASE) != NULL;
	if (no_peers) {
		how &= ~M2V2_OPEN_REPLIMODE;
		how |= M2V2_OPEN_LOCAL|M2V2_OPEN_NOREFCHECK;
	}

	struct sqlx_name_s n = {
		.base = hc_url_get(url, HCURL_HEXID),
		.type = META2_TYPE_NAME,
		.ns = m2->backend.ns_name,
	};
	err = sqlx_repository_open_and_lock(m2->backend.repo, &n, m2_to_sqlx(how), &sq3, NULL);
	if (NULL != err) {
		if (err->code == CODE_CONTAINER_NOTFOUND)
			err->domain = g_quark_from_static_string(G_LOG_DOMAIN);
		return err;
	}

	sq3->no_peers = no_peers;

	// XXX If the container is being deleted, this is sad ...
	// This MIGHT happen if a cache is present (and this is the
	// common case for m2v2), because the deletion will happen
	// when the base exit the cache.
	// In facts this SHOULD NOT happend because a base being deleted
	// is closed with an instruction to exit the cache immediately.
	// TODO FIXME this is maybe a good place for an assert().
	if (sq3->deleted) {
		err = NEWERROR(CODE_CONTAINER_FROZEN, "destruction pending");
		m2b_close(sq3);
		return err;
	}

	// Complete URL with full VNS and container name
	if (!hc_url_has(url, HCURL_REFERENCE)) {
		gchar *ref = sqlx_admin_get_str(sq3, SQLX_ADMIN_REFERENCE);
		gchar *full_vns = sqlx_admin_get_str(sq3, SQLX_ADMIN_NAMESPACE);
		if (ref && full_vns) {
			hc_url_set(url, HCURL_NS, full_vns);
			hc_url_set(url, HCURL_REFERENCE, ref);
		}
		g_free0(ref);
		g_free0(full_vns);
	}

	*result = sq3;
	return NULL;
}

static GError*
_transaction_begin(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
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
meta2_backend_has_master_container(struct meta2_backend_s *m2,
		struct hc_url_s *url)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	GRID_DEBUG("HAS(%s)", hc_url_get(url, HCURL_WHOLE));
	err = m2b_open(m2, url, M2V2_OPEN_MASTERONLY
			|M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN, &sq3);
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

	EXTRA_ASSERT(m2 != NULL);
	EXTRA_ASSERT(url != NULL);
	GRID_DEBUG("HAS(%s)", hc_url_get(url, HCURL_WHOLE));

	struct sqlx_name_s n = {
		.base = hc_url_get(url, HCURL_HEXID),
		.type = META2_TYPE_NAME,
		.ns = m2->backend.ns_name,
	};
	err = sqlx_repository_has_base(m2->backend.repo, &n);
	if (NULL != err) {
		g_prefix_error(&err, "File error: ");
		return err;
	}

	struct sqlx_sqlite3_s *sq3 = NULL;
	err = m2b_open(m2, url, M2V2_OPEN_LOCAL, &sq3);
	if (NULL == err) {
		if (!sqlx_admin_has(sq3, META2_INIT_FLAG))
			err = NEWERROR(CODE_CONTAINER_NOTFOUND,
					"Container created but not initiated");
		m2b_close(sq3);
	}
	return err;
}

static GError *
_create_container_init_phase(struct sqlx_sqlite3_s *sq3,
		struct hc_url_s *url, struct m2v2_create_params_s *params)
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
		m2db_set_ctime (sq3, time(0));
		sqlx_admin_init_i64(sq3, META2_INIT_FLAG, 1);
	}
	if (!params->local)
		err = sqlx_transaction_end(repctx, err);
	return err;
}

GError *
meta2_backend_create_container(struct meta2_backend_s *m2,
		struct hc_url_s *url, struct m2v2_create_params_s *params)
{
	GError *err = NULL;
	enum m2v2_open_type_e open_mode = 0;
	struct sqlx_sqlite3_s *sq3 = NULL;

	GRID_DEBUG("CREATE(%s,%s,%s)%s", hc_url_get(url, HCURL_WHOLE),
			params?params->storage_policy:NULL,
			params?params->version_policy:NULL,
			(params && params->local)? " (local)" : "");

	/* We must check storage policy BEFORE opening the base if we don't
	 * want to have an empty base in case of invalid policy */
	if (params->storage_policy) {
		if (NULL != (err = _check_policy(m2, params->storage_policy)))
			return err;
	}

	if (params->local) // NOREFCHECK: do not call get_peers()
		open_mode = M2V2_OPEN_LOCAL|M2V2_OPEN_NOREFCHECK;
	else
		open_mode = M2V2_OPEN_MASTERONLY;
	open_mode |= M2V2_OPEN_AUTOCREATE;

	err = m2b_open(m2, url, open_mode, &sq3);
	if (sq3 && !err) {
		if (sqlx_admin_has(sq3, META2_INIT_FLAG))
			err = NEWERROR(CODE_CONTAINER_EXISTS, "Container already initiated");
		else {
			err = _create_container_init_phase(sq3, url, params);
			if (err) {
				m2b_destroy(sq3);
				return err;
			}
		}
		m2b_close(sq3);
	}
	return err;
}

GError *
meta2_backend_destroy_container(struct meta2_backend_s *m2,
		struct hc_url_s *url, guint32 flags)
{
	GError *err = NULL;
	gboolean local = flags & M2V2_DESTROY_LOCAL;
	gchar **peers = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	guint counter = 0;

	void counter_cb(gpointer u, gpointer bean) {
		(void) u;
		counter ++;
		_bean_clean(bean);
	}

	struct list_params_s lp;
	memset(&lp, '\0', sizeof(struct list_params_s));
	lp.flag_nodeleted = ~0;
	lp.maxkeys = 1;

	GRID_DEBUG("DESTROY(%s)%s", hc_url_get(url, HCURL_WHOLE),
			local? " (local)" : "");
	err = m2b_open(m2, url, local? M2V2_OPEN_LOCAL : M2V2_OPEN_MASTERONLY,
			&sq3);
	if (!err) {
		g_assert(sq3 != NULL);

		// Performs checks only if client did not ask for a local destroy
		if (!local)
			err = m2db_list_aliases(sq3, &lp, counter_cb, NULL);

		if (err) {
			m2b_close(sq3);
			return err;
		}

		if (counter > 0 && !(flags & (M2V2_DESTROY_FORCE|M2V2_DESTROY_FLUSH))) {
			m2b_close(sq3);
			return NEWERROR(CODE_CONTAINER_NOTEMPTY,
					"%d elements still in container", counter);
		}

		if (counter > 0 && flags & M2V2_DESTROY_FLUSH) {
			err = m2db_flush_container(sq3->db);
			if (err != NULL) {
				GRID_WARN("Error flushing container: %s", err->message);
				g_clear_error(&err);
			}
		}

		if (!local) {
			struct sqlx_name_s n = {
				.base = hc_url_get(url, HCURL_HEXID),
				.type = META2_TYPE_NAME,
				.ns = m2->backend.ns_name,
			};
			err = sqlx_config_get_peers(election_manager_get_config(
					sqlx_repository_get_elections_manager(m2->backend.repo)),
					&n, &peers);
			// peers may be NULL if no zookeeper URL is configured
			if (!err && peers != NULL && g_strv_length(peers) > 0) {
				err = m2v2_remote_execute_DESTROY_many(peers, url, flags);
				g_strfreev(peers);
				peers = NULL;
			}
		}

		if (!err) {
			m2b_destroy(sq3);
		} else {
			m2b_close(sq3);
		}

		// There is a get_peers() call in close callback that puts back
		// the reference in the cache. But it MUST NOT stay in it if
		// we want to recreate the container on another meta2.
		hc_decache_reference_service(m2->resolver, url, META2_TYPE_NAME);
	}

	return err;
}

GError *
meta2_backend_flush_container(struct meta2_backend_s *m2,
		struct hc_url_s *url)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	err = m2b_open(m2, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		g_assert(sq3 != NULL);
		if (!(err = sqlx_transaction_begin(sq3, &repctx))) {
			if (!(err = m2db_flush_container(sq3->db))) {
				err = m2db_purge(sq3,
						_maxvers(sq3, m2),
						_retention_delay(sq3, m2), 0, NULL, NULL);
			}
			err = sqlx_transaction_end(repctx, err);
		}
		m2b_close(sq3);
	}

	return err;
}

GError *
meta2_backend_purge_container(struct meta2_backend_s *m2,
		struct hc_url_s *url, guint32 flags, m2_onbean_cb cb, gpointer u0)
{
	GError *err;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	err = m2b_open(m2, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		g_assert(sq3 != NULL);
		if (!(err = sqlx_transaction_begin(sq3, &repctx))) {
			err = m2db_purge(sq3, _maxvers(sq3, m2),
					_retention_delay(sq3, m2), flags, cb, u0);
			err = sqlx_transaction_end(repctx, err);
		}
		m2b_close(sq3);
	}

	return err;
}

/* Contents --------------------------------------------------------------- */

GError*
meta2_backend_list_aliases(struct meta2_backend_s *m2b, struct hc_url_s *url,
		struct list_params_s *lp, m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	g_assert(m2b != NULL);
	g_assert(url != NULL);
	g_assert(lp != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERSLAVE
			|M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN, &sq3);
	if (!err) {
		err = m2db_list_aliases(sq3, lp, cb, u0);
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

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERSLAVE
			|M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN, &sq3);
	if (!err) {
		err = m2db_get_alias(sq3, url, flags, cb, u0);
		m2b_close(sq3);
	}

	return err;
}

static void
meta2_backend_add_modified_container(struct meta2_backend_s *m2b,
		const gchar *strid, gint64 size)
{
	EXTRA_ASSERT(m2b != NULL);
	if (m2b->q_notify) {
		gchar *tmp = g_strdup_printf("%s:%"G_GINT64_FORMAT, strid, size);
		g_async_queue_push (m2b->q_notify, tmp);
	}
}

GError*
meta2_backend_refresh_container_size(struct meta2_backend_s *m2b,
		struct hc_url_s *url, gboolean bRecalc)
{
    GError *err = NULL;
    struct sqlx_sqlite3_s *sq3 = NULL;

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	if (!(err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY, &sq3))) {
		guint64 sizeOrg = m2db_get_size(sq3);
		guint64 sizeNew = sizeOrg;
		if (bRecalc) {
			sizeNew = m2db_get_container_size(sq3->db, FALSE);
			GRID_DEBUG("sizeNew: F=%ld, T=%ld", sizeNew,
					m2db_get_container_size(sq3->db, TRUE));
			m2db_set_size(sq3, (gint64)sizeNew);
		}

		if (!err)
			meta2_backend_add_modified_container(m2b,
					hc_url_get(url, HCURL_HEXID), sizeNew);
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_delete_alias(struct meta2_backend_s *m2b,
		struct hc_url_s *url, gboolean sync_delete,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	gint64 max_versions;

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		struct sqlx_repctx_s *repctx = NULL;
		max_versions = _maxvers(sq3, m2b);
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (!(err = m2db_delete_alias(sq3, max_versions, url, sync_delete, cb, u0))) {
				m2db_increment_version(sq3);
				meta2_backend_add_modified_container(m2b, hc_url_get(url, HCURL_HEXID), m2db_get_size(sq3));
			}
			err = sqlx_transaction_end(repctx, err);
		}
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
	struct sqlx_repctx_s *repctx = NULL;

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {

		struct m2db_put_args_s args;
		memset(&args, 0, sizeof(args));
		args.sq3 = sq3;
		args.url = url;
		args.max_versions = _maxvers(sq3, m2b);
		meta2_backend_get_nsinfo(m2b, &(args.nsinfo));
		args.lbpool = m2b->backend.lb;

		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (!(err = m2db_put_alias(&args, beans, cb, u0))) {
				m2db_increment_version(sq3);
				meta2_backend_add_modified_container(m2b,
						hc_url_get(url, HCURL_HEXID), m2db_get_size(sq3));
			}
			err = sqlx_transaction_end(repctx, err);
		}
		m2b_close(sq3);

		namespace_info_clear(&(args.nsinfo));
	}

	return err;
}

GError*
meta2_backend_copy_alias(struct meta2_backend_s *m2b, struct hc_url_s *url,
		const char *src)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;
	struct m2db_put_args_s args;

	g_assert(m2b != NULL);
	g_assert(url != NULL);
	g_assert(src != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		memset(&args, 0, sizeof(args));
		args.sq3 = sq3;
		args.url = url;
		args.max_versions = _maxvers(sq3, m2b);
		meta2_backend_get_nsinfo(m2b, &(args.nsinfo));
		args.lbpool = m2b->backend.lb;

		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (!(err = m2db_copy_alias(&args, src)))
				m2db_increment_version(sq3);
			err = sqlx_transaction_end(repctx, err);
		}
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
	struct sqlx_repctx_s *repctx = NULL;

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {

		struct m2db_put_args_s args;
		memset(&args, 0, sizeof(args));
		args.sq3 = sq3;
		args.url = url;
		args.max_versions = _maxvers(sq3, m2b);
		meta2_backend_get_nsinfo(m2b, &(args.nsinfo));
		args.lbpool = m2b->backend.lb;

		if (!(err = _transaction_begin(sq3,url, &repctx))) {
			if (!(err = m2db_force_alias(&args, beans))) {
				m2db_increment_version(sq3);
				meta2_backend_add_modified_container(m2b,
	                       hc_url_get(url, HCURL_HEXID), m2db_get_size(sq3));
			}
			err = sqlx_transaction_end(repctx, err);
		}
		m2b_close(sq3);
		namespace_info_clear(&(args.nsinfo));
	}

	return err;
}

GError*
meta2_backend_insert_beans(struct meta2_backend_s *m2b,
		struct hc_url_s *url, GSList *beans)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			err = _db_save_beans_list (sq3->db, beans);
			if (!err)
				m2db_increment_version(sq3);
			err = sqlx_transaction_end(repctx, err);
		}
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_delete_beans(struct meta2_backend_s *m2b,
		struct hc_url_s *url, GSList *beans)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	g_assert(m2b != NULL);
	g_assert(url != NULL);

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
meta2_backend_update_beans(struct meta2_backend_s *m2b, struct hc_url_s *url, 
		GSList *new_chunks, GSList *old_chunks)
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

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			for (GSList *l0=old_chunks, *l1=new_chunks;
					!err && l0 && l1 ; l0=l0->next,l1=l1->next)
			{
				err = _db_delete_bean (sq3->db, l0->data);
				if (!err)
					err = _db_save_bean (sq3->db, l1->data);
				if (!err && DESCR(l0->data) == &descr_struct_CHUNKS) {
					gchar *stmt = g_strdup_printf(
							"UPDATE content_v2 SET chunk_id = '%s' WHERE chunk_id = '%s'",
							CHUNKS_get_id(l1->data)->str, CHUNKS_get_id(l0->data)->str);
					int rc = sqlx_exec(sq3->db, stmt);
					g_free(stmt);
					if (!sqlx_code_good(rc))
						err = SQLITE_GERROR(sq3->db, rc);
				}
			}
			if (!err)
				m2db_increment_version(sq3);
			err = sqlx_transaction_end(repctx, err);
		}
		m2b_close(sq3);
	}

	return err;
}

static GSList*
_filter_beans(GSList *beans, const struct bean_descriptor_s *descr)
{
	GSList *result = NULL;

	for (; beans ;beans=beans->next) {
		gpointer bean = beans->data;
		if (unlikely(NULL == bean))
			continue;
		if (descr == DESCR(bean))
			result = g_slist_prepend(result, _bean_dup(bean));
	}

	return result;
}

static GSList*
_filter_contents(GSList *beans)
{
	return _filter_beans(beans, &descr_struct_CONTENTS);
}

GError*
meta2_backend_delete_chunks(struct meta2_backend_s *m2b,
		struct hc_url_s *url, GSList *beans)
{
	GSList *contents = _filter_contents(beans);
	GError *err = meta2_backend_delete_beans(m2b, url, beans);
	g_slist_free_full(contents, _bean_clean);
	return err;
}

GError*
meta2_backend_get_alias_version(struct meta2_backend_s *m2b,
		struct hc_url_s *url, gint64 *version)
{
	g_assert(m2b != NULL);
	g_assert(url != NULL);

	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = m2b_open(m2b, url, M2V2_OPEN_MASTERSLAVE
			|M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN, &sq3);
	if (!err) {
		err = m2db_get_alias_version(sq3, url, version);
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
	struct sqlx_repctx_s *repctx = NULL;
	struct namespace_info_s ni;
	gint64 max_versions;

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	memset(&ni, '\0', sizeof(struct namespace_info_s));

	meta2_backend_get_nsinfo(m2b, &ni);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		max_versions = _maxvers(sq3, m2b);
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (!(err = m2db_append_to_alias(sq3, &ni, max_versions, url, beans,
							cb, u0))) {
				m2db_increment_version(sq3);
				meta2_backend_add_modified_container(m2b,
						hc_url_get(url, HCURL_HEXID), m2db_get_size(sq3));
			}
			err = sqlx_transaction_end(repctx, err);
		}
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_get_properties(struct meta2_backend_s *m2b,
		struct hc_url_s *url, m2_onbean_cb cb, gpointer u0)
{
	g_assert(m2b != NULL);
	g_assert(url != NULL);

	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = m2b_open(m2b, url, M2V2_OPEN_MASTERSLAVE
			|M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN, &sq3);
	if (!err) {
		err = m2db_get_properties(sq3, url, cb, u0);
		m2b_close(sq3);
	}
	return err;
}

GError*
meta2_backend_del_properties(struct meta2_backend_s *m2b,
		struct hc_url_s *url, gchar **propv)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	g_assert(m2b != NULL);
	g_assert(url != NULL);

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
meta2_backend_set_properties(struct meta2_backend_s *m2b,
		struct hc_url_s *url, GSList *beans,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	GRID_TRACE("M2 GET(%s)", hc_url_get(url, HCURL_WHOLE));

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (!(err = m2db_set_properties(sq3, url, beans, cb, u0)))
				m2db_increment_version(sq3);
			err = sqlx_transaction_end(repctx, err);
		}
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

static GError*
_check_alias_doesnt_exist(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url)
{
	void _cb(gpointer udata, gpointer bean) {
		if(bean) {
			*((gboolean*)udata) = FALSE;
			_bean_clean(bean);
		}
	}

	gboolean no_bean = TRUE;
	GError *err = m2db_get_alias(sq3, url, M2V2_FLAG_NODELETED, _cb, &no_bean);
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

GError*
meta2_backend_generate_beans_v1(struct meta2_backend_s *m2b,
		struct hc_url_s *url, gint64 size, const gchar *polname,
		gboolean append, const char *mdsys, const char *mdusr,
		m2_onbean_cb cb, gpointer cb_data)
{
	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = NULL;
	struct namespace_info_s nsinfo;
	struct storage_policy_s *policy = NULL;
	struct grid_lb_iterator_s *iter = NULL;

	GRID_TRACE("BEANS(%s,%"G_GINT64_FORMAT",%s)", hc_url_get(url, HCURL_WHOLE),
			size, polname);
	g_assert(m2b != NULL);
	g_assert(url != NULL);
	g_assert(cb != NULL);

	memset(&nsinfo, 0, sizeof(nsinfo));
	if (!meta2_backend_get_nsinfo(m2b, &nsinfo))
		return NEWERROR(CODE_INTERNAL_ERROR, "NS not ready");

	/* Several checks are to be performed on the container state */
	err = m2b_open(m2b, url, M2V2_OPEN_MASTERSLAVE|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {

		gint64 max_version = _maxvers(sq3, m2b);
		if (m2b->flag_precheck_on_generate && VERSIONS_DISABLED(max_version)) {
			/* If the versioning is not supported, we check the content
			 * is not present */
			err = _check_alias_doesnt_exist(sq3, url);
			if(append) {
				if(err) {
					g_clear_error(&err);
					err = NULL;
				} else {
					err = NEWERROR(CODE_CONTENT_NOTFOUND, "Content [%s] "
							"not found", hc_url_get(url, HCURL_PATH));
				}
			}
		}

		/* Now check the storage policy */
		if (!err) {
			if (polname) {
				if (!(policy = storage_policy_init(&nsinfo, polname)))
					err = NEWERROR(CODE_POLICY_NOT_SUPPORTED,
							"Invalid policy [%s]", polname);
			} else {
				/* check polname not in mdsys */
				char *polstr = storage_policy_from_mdsys_str(mdsys);
				GRID_TRACE("Storage policy from sys md = %s", polstr);
				if(NULL != polstr){
					if (!(policy = storage_policy_init(&nsinfo, polstr)))
						err = NEWERROR(CODE_POLICY_NOT_SUPPORTED,
								"Invalid policy [%s]", polstr);
					g_free(polstr);
				} else {
					err = m2db_get_storage_policy(sq3, url, &nsinfo, append, &policy);
					if (err || !policy) {
						gchar *default_ns_policy_name = 
							namespace_storage_policy(&nsinfo, hc_url_get(url, HCURL_NS));
						if (NULL != default_ns_policy_name) {
							if (!(policy = storage_policy_init(&nsinfo,
											default_ns_policy_name)))
								err = NEWERROR(CODE_POLICY_NOT_SUPPORTED,
										"Invalid policy [%s]", default_ns_policy_name);
							g_free(default_ns_policy_name);
						}
					}
				}
			}
		}

		/* check container not full */
		gint64 quota = _quota(sq3, m2b);
		if(quota > 0 && quota <= m2db_get_size(sq3))
			err = NEWERROR(CODE_CONTAINER_FULL, "Container's quota reached (%"G_GINT64_FORMAT" bytes)", quota);

		m2b_close(sq3);
	}

	/* Let's continue to generate the beans, no need for an open container for the moment */
	if (!err) {
		iter = grid_lbpool_get_iterator(m2b->backend.lb, "rawx");
		if (!iter)
			err = NEWERROR(CODE_POLICY_NOT_SATISFIABLE, "No RAWX available");
		else
			err = m2_generate_beans_v1(url, size,
					namespace_chunk_size(&nsinfo, hc_url_get(url, HCURL_NS)),
					policy, mdsys, mdusr, iter, cb, cb_data);
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

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERSLAVE
			|M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN, &sq3);
	if (!err) {
		*result = _maxvers(sq3, m2b);
		m2b_close(sq3);
	}

	return err;
}

/* ------------------------------------------------------------------------- */

GError*
meta2_backend_update_alias_header(struct meta2_backend_s *m2b,
		struct hc_url_s *url, GSList *beans)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;
	guint32 max_versions = 0;

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		max_versions = _maxvers(sq3, m2b);
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			err = m2db_update_alias_header(sq3, max_versions, url, beans);
			err = sqlx_transaction_end(repctx, err);
		}
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_deduplicate_contents(struct meta2_backend_s *m2b,
		struct hc_url_s *url, guint32 flags, GString **status_message)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;
	g_assert(m2b != NULL);
	g_assert(url != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		GRID_INFO("Starting content deduplication on %s",
				hc_url_get(url, HCURL_WHOLE));
		if (!(err = _transaction_begin(sq3,url, &repctx))) {
			err = m2db_deduplicate_contents(sq3, url, flags, status_message);
			if (err == NULL) {
				GRID_INFO("Finished content deduplication");
			} else {
				GRID_WARN("Got error while performing content deduplication");
			}
			err = sqlx_transaction_end(repctx, err);
		}
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

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		GRID_INFO("Starting chunk deduplication on %s",
				hc_url_get(url, HCURL_WHOLE));
		err = m2db_deduplicate_chunks(sq3, &nsinfo, url);
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

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		GRID_INFO("Starting chunk deduplication on %s (%s)",
				hc_url_get(url, HCURL_WHOLE),
				hc_url_get(url, HCURL_PATH));
		m2b_close(sq3);
		err = m2db_deduplicate_alias_chunks(sq3, &nsinfo, url);
	} else {
		GRID_WARN("Got error when opening database: %s", err->message);
	}
	return err;
}

// TODO FIXME too many arguments
// TODO 'url' seems only useful for logging purposes
GError*
meta2_backend_get_conditionned_spare_chunks(struct meta2_backend_s *m2b,
		struct hc_url_s *url, gint64 count, gint64 dist, const char *notin,
		const char *broken, GSList **result, gboolean answer_beans)
{
	GError *err = NULL;
	GSList *notin2 = NULL;
	GSList *broken2 = NULL;
	struct storage_policy_s *stgpol = NULL;

	GSList * srvinfo_from_piped_chunkid(const char *str)
	{
		GError *err2 = NULL;
		GSList *sil = NULL;

		if(!str || strlen(str) <= 0)
			return NULL;

		char **urls = g_strsplit(str, "|", 0);
		for (uint i = 0; i < g_strv_length(urls); i++) {
			if (strlen(urls[i]) <= 0)
				continue;
			struct service_info_s *si = NULL;
			err2 = service_info_from_chunk_id(m2b->backend.lb, urls[i], &si);
			if (NULL != si)
				sil = g_slist_prepend(sil, si);
			if (err2 != NULL) {
				GRID_WARN("Failed getting service info from '%s': %s",
						urls[i], err2->message);
				g_clear_error(&err2);
			}
		}

		g_strfreev(urls);
		return sil;
	}

	(void) url;
	GRID_TRACE("CONDITIONNED SPARE(%s, %"G_GINT64_FORMAT", %"G_GINT64_FORMAT", %s, %s)",
			hc_url_get(url, HCURL_WHOLE),
			count,
			dist,
			notin,
			broken);

	notin2 = srvinfo_from_piped_chunkid(notin);
	broken2 = srvinfo_from_piped_chunkid(broken);

	// FIXME: storage class should come as parameter
	stgpol = storage_policy_init(&(m2b->backend.ns_info), NULL);

	err = get_conditioned_spare_chunks(m2b->backend.lb, count, dist,
			storage_policy_get_storage_class(stgpol), notin2, broken2, result,
			answer_beans);

	g_slist_free_full(notin2, (GDestroyNotify) service_info_gclean);
	g_slist_free_full(broken2, (GDestroyNotify) service_info_gclean);
	storage_policy_clean(stgpol);

	return err;
}

static GError*
_load_storage_policy(struct meta2_backend_s *m2b, struct hc_url_s *url,
		const gchar *polname, struct storage_policy_s **pol)
{
	GError *err = NULL;
	namespace_info_t nsinfo;
	struct sqlx_sqlite3_s *sq3 = NULL;

	memset(&nsinfo, 0, sizeof(nsinfo));
	if (!meta2_backend_get_nsinfo(m2b, &nsinfo))
		return NEWERROR(CODE_INTERNAL_ERROR, "NS not ready");

	if (polname) {
		if (!(*pol = storage_policy_init(&nsinfo, polname)))
			err = NEWERROR(CODE_POLICY_NOT_SUPPORTED, "Invalid policy [%s]",
					polname);
	} else {
		err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY
				|M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN, &sq3);
		if (!err) {
			/* check pol from container / ns */
			err = m2db_get_storage_policy(sq3, url, &nsinfo, FALSE, pol);
			if (err || !*pol) {
				gchar *default_ns_policy_name =
					namespace_storage_policy(&nsinfo, hc_url_get(url, HCURL_NS));
				if (NULL != default_ns_policy_name) {
					if (!(*pol = storage_policy_init(&nsinfo,
									default_ns_policy_name)))
						err = NEWERROR(CODE_POLICY_NOT_SUPPORTED,
								"Invalid policy [%s]", default_ns_policy_name);
					g_free(default_ns_policy_name);
				}
			}
		}
		m2b_close(sq3);
	}

	namespace_info_clear(&nsinfo);
	return err;
}

GError*
meta2_backend_get_conditionned_spare_chunks_v2(struct meta2_backend_s *m2b,
		struct hc_url_s *url, const gchar *polname, GSList *notin,
		GSList *broken, GSList **result)
{
	GError *err = NULL;
	struct storage_policy_s *pol = NULL;

	err = _load_storage_policy(m2b, url, polname, &pol);
	if (err != NULL)
		return err;

	err = get_conditioned_spare_chunks2(m2b->backend.lb, pol, notin, broken,
			result, TRUE);

	storage_policy_clean(pol);
	return err;
}

GError*
meta2_backend_get_spare_chunks(struct meta2_backend_s *m2b, struct hc_url_s *url,
		const char *polname, GSList **result, gboolean use_beans)
{
	struct storage_policy_s *pol = NULL;
	GError *err = NULL;

	GRID_TRACE("SPARE(%s,%s)", hc_url_get(url, HCURL_WHOLE), polname);
	g_assert(m2b != NULL);

	err = _load_storage_policy(m2b, url, polname, &pol);

	if (!err) {
		err = get_spare_chunks(m2b->backend.lb, pol, result, use_beans);
	}

	if (pol)
		storage_policy_clean(pol);
	return err;
}

/* --------------- SNAPSHOTS -------------------- */
GError*
meta2_backend_take_snapshot(struct meta2_backend_s *m2b, struct hc_url_s *url,
		const char *snapshot_name)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;
	struct bean_SNAPSHOTS_s *snapshot = NULL;
	g_assert(m2b != NULL);
	g_assert(url != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		GRID_INFO("Taking snapshot of '%s' with name '%s'",
				hc_url_get(url, HCURL_REFERENCE), snapshot_name);
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (!SNAPSHOTS_ENABLED(_maxvers(sq3, m2b))) {
				err = NEWERROR(CODE_BAD_REQUEST,
						"Versioning disabled, cannot take snapshot");
			}
			if (err == NULL) {
				err = m2db_get_snapshot_by_name(sq3, snapshot_name, &snapshot);
			}
			if (err == NULL) {
				err = NEWERROR(CODE_SNAPSHOT_EXISTS, "Snapshot '%s' already exists",
						snapshot_name);
				_bean_clean(snapshot);
			} else if (err->code == CODE_SNAPSHOT_NOTFOUND) {
				g_clear_error(&err);
			}
			if (err == NULL)
				err = m2db_take_snapshot(sq3, snapshot_name, NULL, NULL);
			if (err == NULL) {
				m2db_increment_version(sq3);
				GRID_INFO("Finished taking snapshot");
			} else {
				GRID_WARN("Got error while taking snapshot: %s", err->message);
			}
		}
		err = sqlx_transaction_end(repctx, err);
		m2b_close(sq3);
	} else {
		GRID_WARN("Got error when opening database: %s", err->message);
	}
	return err;
}

GError*
meta2_backend_delete_snapshot(struct meta2_backend_s *m2b,
		struct hc_url_s *url, const char *snapshot_name)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;
	struct bean_SNAPSHOTS_s *snapshot = NULL;
	g_assert(m2b != NULL);
	g_assert(url != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		GRID_INFO("Deleting snapshot '%s' of '%s'",
				snapshot_name, hc_url_get(url, HCURL_REFERENCE));
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			// Check if snapshot exists
			err = m2db_get_snapshot_by_name(sq3, snapshot_name, &snapshot);
			if (err == NULL)
				err = m2db_delete_snapshot(sq3, snapshot);
			if (err != NULL) {
				GRID_WARN("Failed to delete snapshot '%s' of '%s'",
						snapshot_name, hc_url_get(url, HCURL_REFERENCE));
			} else {
				m2db_increment_version(sq3);
			}
			err = sqlx_transaction_end(repctx, err);
		}
		m2b_close(sq3);
		_bean_clean(snapshot);
	} else {
		GRID_WARN("Got error when opening database: %s", err->message);
	}
	return err;
}

GError*
meta2_backend_list_snapshots(struct meta2_backend_s *m2b,
		struct hc_url_s *url, m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;
	g_assert(m2b != NULL);
	g_assert(url != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERSLAVE
			|M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN,
			&sq3);
	if (!err) {
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			err = m2db_get_snapshots(sq3, NULL, -1, cb, u0);
			if (err != NULL) {
				GRID_WARN("Failed to list snapshots: %s", err->message);
			}
			err = sqlx_transaction_end(repctx, err);
		}
		m2b_close(sq3);
	} else {
		GRID_WARN("Got error when opening database: %s", err->message);
	}

	return err;
}

GError*
meta2_backend_restore_snapshot(struct meta2_backend_s *m2b,
        struct hc_url_s *url, const gchar *snapshot_name, gboolean hard_restore)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;
	struct bean_SNAPSHOTS_s *snapshot = NULL;
	g_assert(m2b != NULL);
	g_assert(url != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		GRID_INFO("Restoring snapshot '%s' of '%s' (%s)",
				snapshot_name, hc_url_get(url, HCURL_REFERENCE),
				hc_url_get(url, HCURL_WHOLE));
		if (!(err = _transaction_begin(sq3, url, &repctx))) {

			if (!SNAPSHOTS_ENABLED(_maxvers(sq3, m2b))) {
				err = NEWERROR(CODE_BAD_REQUEST,
						"Versioning disabled, cannot restore snapshot");
				err = sqlx_transaction_end(repctx, err);
				m2b_close(sq3);
				return err;
			}

			err = m2db_get_snapshot_by_name(sq3, snapshot_name, &snapshot);
			if (err == NULL) {
				if (hc_url_has(url, HCURL_PATH)) {
					err = m2db_restore_snapshot_alias(sq3, snapshot,
							hc_url_get(url, HCURL_PATH));
				} else {
					err = m2db_restore_snapshot(sq3, snapshot, hard_restore);
				}
			}

			if (err == NULL)
				m2db_increment_version(sq3);

			err = sqlx_transaction_end(repctx, err);
		}
		m2b_close(sq3);
		_bean_clean(snapshot);
		if (err != NULL) {
			g_prefix_error(&err, "Failed to restore snapshot '%s': ",
					snapshot_name);
		}
	} else {
		GRID_WARN("Got error when opening database: %s", err->message);
	}

	return err;
}

GError*
meta2_backend_get_content_urls_from_chunk_id(struct meta2_backend_s *m2b,
		struct hc_url_s *url, const gchar* chunk_id, gint64 limit, GSList **urls)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERSLAVE|
			M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN, &sq3);
	if (!err) {
		err = m2db_content_urls_from_chunk_id(sq3, url, chunk_id, limit, urls);
		m2b_close(sq3);
	}

	return err;
}

