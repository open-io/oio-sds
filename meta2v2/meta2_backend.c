#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "m2v2"
#endif

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>

#include <sqliterepo/sqliterepo.h>
#include <sqliterepo/election.h>

#include <meta0v2/meta0_remote.h>
#include <meta0v2/meta0_utils.h>

#include <meta1v2/meta1_remote.h>

#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>
#include <meta2v2/meta2v2_remote.h>
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
	// No flag set mean no check.
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

static inline gint64
_quota(struct sqlx_sqlite3_s *sq3, struct meta2_backend_s *m2b)
{
	gchar *vns = m2db_get_namespace(sq3, m2b->ns_name);
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

static inline gint64
_maxvers(struct sqlx_sqlite3_s *sq3, struct meta2_backend_s *m2b)
{
	gchar *vns = m2db_get_namespace(sq3, m2b->ns_name);
	gint64 res = m2db_get_max_versions(sq3, m2b_max_versions(m2b, vns));
	g_free(vns);
	return res;
}

static inline gint64
_retention_delay(struct sqlx_sqlite3_s *sq3, struct meta2_backend_s *m2b)
{
	gchar *vns = m2db_get_namespace(sq3, m2b->ns_name);
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

	g_mutex_free(transient->lock);
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

	if (hexID != NULL)
		err = sqlx_repository_status_base(m2b->repo, META2_TYPE_NAME, hexID);
	if ( !err ) {
		struct transient_s *trans = NULL;

		g_mutex_lock(m2b->lock_transient);
		trans = g_hash_table_lookup(m2b->transient, hexID);
		if (trans == NULL) {
			trans = g_new0(struct transient_s, 1);
			trans->lock = g_mutex_new();
			trans->tree = g_tree_new_full(metautils_strcmp3, NULL, g_free, NULL);
			g_hash_table_insert(m2b->transient, g_strdup(hexID), trans);
		}
		g_mutex_unlock(m2b->lock_transient);
		g_mutex_lock(trans->lock);
		transient_put(trans->tree, key, what, cleanup);
		g_mutex_unlock(trans->lock);
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

	if (hexID != NULL)
		local_err = sqlx_repository_status_base(m2b->repo, META2_TYPE_NAME, hexID);

	if (local_err) {
		*err = local_err;
		return NULL;
	}

	g_mutex_lock(m2b->lock_transient);
	trans = g_hash_table_lookup(m2b->transient, hexID);
	g_mutex_unlock(m2b->lock_transient);
	if (trans == NULL) {
		*err = NEWERROR(500, "Transient data not found in hash");
		return NULL;
	}

	gpointer result;
	g_mutex_lock(trans->lock);
	result = transient_get(trans->tree, key);
	g_mutex_unlock(trans->lock);
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
		struct transient_s *trans = NULL;

		g_mutex_lock(m2b->lock_transient);
		trans = g_hash_table_lookup(m2b->transient, hexID);
		g_mutex_unlock(m2b->lock_transient);
		if (trans == NULL)
			return NEWERROR(500, "Transient data not found in hash");

		g_mutex_lock(trans->lock);
		transient_del(trans->tree, key);
		g_mutex_unlock(trans->lock);
	}
	return err;
}

void
m2b_transient_cleanup(struct meta2_backend_s *m2b)
{
	g_assert(m2b != NULL);

	g_mutex_lock(m2b->lock_transient);
	g_hash_table_destroy(m2b->transient);
	g_mutex_unlock(m2b->lock_transient);
}

static void
_m0_mapping_gclean(gpointer _cid_list)
{
	GSList *cid_list = _cid_list;
	g_slist_free_full(cid_list, g_free);
}

/* Backend ------------------------------------------------------------------ */

void
meta2_file_locator(gpointer ignored, const gchar *n, const gchar *t,
		GString *result)
{
	(void) ignored, (void) t;
	EXTRA_ASSERT(t != NULL);
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
		struct sqlx_repository_s *repo, const gchar *ns,
		struct grid_lbpool_s *glp, struct hc_resolver_s *resolver)
{
	GError *err = NULL;
	struct meta2_backend_s *m2 = NULL;
	gsize s;

	g_assert(result != NULL);
	g_assert(glp != NULL);
	g_assert(repo != NULL);
	g_assert(resolver != NULL);

	m2 = g_malloc0(sizeof(struct meta2_backend_s));

	s = metautils_strlcpy_physical_ns(m2->ns_name, ns, sizeof(m2->ns_name));
	if (sizeof(m2->ns_name) <= s) {
		g_free(m2);
		return NEWERROR(400, "Namespace too long");
	}

	m2->repo = repo;
	m2->glp = glp;
	m2->policies = service_update_policies_create();
	m2->evt_config = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, (GDestroyNotify) event_config_destroy);

	m2->lock_ns_info = g_mutex_new();

	m2->lock_transient = g_mutex_new();
	m2->transient = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, (GDestroyNotify) transient_cleanup);

	m2->flag_precheck_on_generate = TRUE;

	m2->m0_mapping = g_ptr_array_new_with_free_func(
			(GDestroyNotify) _m0_mapping_gclean);
	g_ptr_array_set_size(m2->m0_mapping, 65536);
	m2->modified_containers_lock = g_mutex_new();
	m2->modified_containers = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, g_free);

	err = sqlx_repository_configure_type(m2->repo, META2_TYPE_NAME, NULL,
			schema);
	if (NULL != err) {
		meta2_backend_clean(m2);
		g_prefix_error(&err, "Backend init error: ");
		return err;
	}

	sqlx_repository_set_locator(m2->repo, meta2_file_locator, NULL);
	m2->resolver = resolver;

	GRID_DEBUG("M2V2 backend created for NS[%s] and repo[%p]",
			m2->ns_name, m2->repo);

	*result = m2;
	return NULL;
}

struct event_config_s *
meta2_backend_get_event_config(struct meta2_backend_s *m2, const char *ns_name)
{
	struct event_config_s *event = NULL;
	if(NULL != m2) {
		g_static_rw_lock_writer_lock(&m2->rwlock_evt_config);
		if(!(event = g_hash_table_lookup(m2->evt_config, ns_name))) {
			event = event_config_create();
			g_hash_table_insert(m2->evt_config, g_strdup(ns_name), event);
		}
		g_static_rw_lock_writer_unlock(&m2->rwlock_evt_config);
	}
	return event;
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
	if (m2->lock_ns_info) {
		g_mutex_free(m2->lock_ns_info);
	}
	if (m2->evt_config) {
		g_hash_table_destroy(m2->evt_config);
	}
	if (m2->m0_mapping) {
		g_ptr_array_free(m2->m0_mapping, TRUE);
	}
	if (m2->lock_transient) {
		g_mutex_free(m2->lock_transient);
	}
	if (m2->transient) {
		g_hash_table_destroy(m2->transient);
	}
	if (m2->modified_containers_lock) {
		g_mutex_free(m2->modified_containers_lock);
	}
	if (m2->modified_containers) {
		g_hash_table_destroy(m2->modified_containers);
	}
	if (m2->resolver) {
		m2->resolver = NULL;
	}
	g_static_rw_lock_free(&m2->rwlock_evt_config);
	namespace_info_clear(&(m2->ns_info));
	g_free(m2);
}

static GSList*
_extract_writable_vns(namespace_info_t *ns_info)
{
	if (!ns_info || !ns_info->options)
		return NULL;

	// KEY_WRITABLE_VNS = "writable_vns"
	GByteArray *writable_gba;
	writable_gba = g_hash_table_lookup(ns_info->options, "writable_vns");

	if (!writable_gba || !writable_gba->len || !writable_gba->data) {
		TRACE("writable namespace list not found in ns_options table");
		return NULL;
	}

	/* Ensures the GByteArray's buffer is terminated by a '\0' */
	g_byte_array_append(writable_gba, (guint8*)"", 1);
	g_byte_array_set_size(writable_gba, writable_gba->len - 1);
	TRACE("gba data from ns_info opt = %s", (gchar*)writable_gba->data);

	gchar **tmp, **p;
	GSList *l = NULL;

	tmp = g_strsplit((gchar*)writable_gba->data,",", 0);
	for (p=tmp; p && *p ;p++)
		l = g_slist_prepend(l, g_strdup(*p));
	g_strfreev(tmp);
	return l;
}

static void
_update_writable_vns_list(namespace_info_t *ns_info)
{
	if (ns_info->writable_vns)
		g_slist_free_full(ns_info->writable_vns, g_free);
	ns_info->writable_vns = _extract_writable_vns(ns_info);
}

void
meta2_backend_configure_nsinfo(struct meta2_backend_s *m2,
		struct namespace_info_s *ns_info)
{
	EXTRA_ASSERT(m2 != NULL);
	EXTRA_ASSERT(ns_info != NULL);

	g_mutex_lock(m2->lock_ns_info);
	(void) namespace_info_copy(ns_info, &(m2->ns_info), NULL);
	_update_writable_vns_list(&(m2->ns_info));
	g_mutex_unlock(m2->lock_ns_info);
}

gboolean
meta2_backend_get_nsinfo(struct meta2_backend_s *m2,
		struct namespace_info_s *dst)
{
	gboolean rc = FALSE;

	EXTRA_ASSERT(m2 != NULL);
	EXTRA_ASSERT(dst != NULL);

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

	g_assert(m2 != NULL);
	g_assert(type != NULL);
	g_assert(si != NULL);

	if (!(iter = grid_lbpool_get_iterator(m2->glp, type)))
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
	gboolean rc = (m2->ns_info.name[0] != '\0');
	return rc;
}

/* Container -------------------------------------------------------------- */

static inline int
m2_to_sqlx(enum m2v2_open_type_e t)
{
	int result = SQLX_OPEN_LOCAL;
	switch (t & M2V2_OPEN_REPLIMODE) {
		case M2V2_OPEN_LOCAL:
			result = SQLX_OPEN_LOCAL;
			break;
		case M2V2_OPEN_MASTERONLY:
			result = SQLX_OPEN_MASTERONLY;
			break;
		case M2V2_OPEN_SLAVEONLY:
			result = SQLX_OPEN_SLAVEONLY;
			break;
		case M2V2_OPEN_MASTERSLAVE:
			result = SQLX_OPEN_MASTERSLAVE;
			break;
	}

	if (M2V2_OPEN_AUTOCREATE == (t & M2V2_OPEN_AUTOCREATE))
		result |= SQLX_OPEN_CREATE;
	if (M2V2_OPEN_NOREFCHECK == (t & M2V2_OPEN_NOREFCHECK))
		result |= SQLX_OPEN_NOREFCHECK;

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

	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(result != NULL);
	EXTRA_ASSERT(m2 != NULL);
	EXTRA_ASSERT(m2->repo != NULL);

	enum m2v2_open_type_e repli = how & M2V2_OPEN_REPLIMODE;
	if (repli != M2V2_OPEN_LOCAL && !(how & M2V2_OPEN_NOREFCHECK)) {
		err = sqlx_repository_status_base(m2->repo, META2_TYPE_NAME,
				hc_url_get(url, HCURL_HEXID));
		if (!err) { /* MASTER */
			if (repli == M2V2_OPEN_SLAVEONLY)
				return NEWERROR(CODE_BADOPFORSLAVE, "Not slave!");
		} else {
			if (err->code == CODE_REDIRECT) { /* SLAVE */
				if (repli == M2V2_OPEN_MASTERONLY)
					return err;
				g_clear_error(&err);
			} else {
				g_prefix_error(&err, "Status error: ");
				return err;
			}
		}
	}

	err = sqlx_repository_open_and_lock(m2->repo, META2_TYPE_NAME,
			hc_url_get(url, HCURL_HEXID), m2_to_sqlx(how), &sq3, NULL);
	if (NULL != err) {
		if (err->code == CODE_CONTAINER_NOTFOUND)
			err->domain = g_quark_from_static_string(G_LOG_DOMAIN);
		return err;
	}

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

	// Check the M2 flags
	gint64 expected_status = how & M2V2_OPEN_STATUS;
	if (expected_status) {

		gint64 flags = sqlx_admin_get_status(sq3);
		gint64 mode = M2V2_OPEN_ENABLED;
		if (flags == ADMIN_STATUS_FROZEN)
			mode = M2V2_OPEN_FROZEN;
		else if (flags == ADMIN_STATUS_DISABLED)
			mode = M2V2_OPEN_DISABLED;

		if (!(mode & expected_status)) {
			err = NEWERROR(CODE_CONTAINER_FROZEN, "Invalid status");
			m2b_close(sq3);
			return err;
		}
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

	err = sqlx_repository_has_base(m2->repo, META2_TYPE_NAME,
			hc_url_get(url, HCURL_HEXID));
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

	if ((err = _transaction_begin(sq3, url, &repctx)))
		return err;

	if (!err && params->storage_policy)
		err = m2db_set_storage_policy(sq3, params->storage_policy, 0);
	if (!err && params->version_policy) {
		gint64 max = g_ascii_strtoll(params->version_policy, NULL, 10);
		m2db_set_max_versions(sq3, max);
	}
	if (!err)
		sqlx_admin_init_i64(sq3, META2_INIT_FLAG, 1);
	return sqlx_transaction_end(repctx, err);
}

GError *
meta2_backend_create_container(struct meta2_backend_s *m2,
		struct hc_url_s *url, struct m2v2_create_params_s *params)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	GRID_DEBUG("CREATE(%s,%s,%s)", hc_url_get(url, HCURL_WHOLE),
			params?params->storage_policy:NULL,
			params?params->version_policy:NULL);

	/* We must check storage policy BEFORE opening the base if we don't
	 * want to have an empty base in case of invalid policy */
	if (params->storage_policy) {
		if (NULL != (err = _check_policy(m2, params->storage_policy)))
			return err;
	}

	err = m2b_open(m2, url, M2V2_OPEN_AUTOCREATE|M2V2_OPEN_MASTERONLY, &sq3);
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
	lp.flags = M2V2_FLAG_NODELETED;
	lp.type = DEFAULT;

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
			err = sqlx_config_get_peers(election_manager_get_config(
					sqlx_repository_get_elections_manager(m2->repo)),
					hc_url_get(url, HCURL_HEXID), META2_TYPE_NAME, &peers);
			// peers may be NULL if no zookeeper URL is configured
			if (!err && peers != NULL && g_strv_length(peers) > 0) {
				err = m2v2_remote_execute_DESTROY_many(
						peers, NULL, url, flags);
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

GError*
meta2_backend_open_container(struct meta2_backend_s *m2, struct hc_url_s *url)
{
	GError *err;
	struct sqlx_sqlite3_s *sq3 = NULL;

	GRID_DEBUG("OPEN(%s)", hc_url_get(url, HCURL_WHOLE));
	err = m2b_open(m2, url, M2V2_OPEN_MASTERSLAVE|M2V2_OPEN_ENABLED, &sq3);
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
	gboolean has = FALSE;

	err = sqlx_config_has_peers(election_manager_get_config(
				sqlx_repository_get_elections_manager(m2->repo)),
			hc_url_get(url, HCURL_HEXID), META2_TYPE_NAME, &has);
	if (NULL != err) {
		g_prefix_error(&err, "Not managed: ");
		return err;
	}

	err = sqlx_repository_has_base(m2->repo, META2_TYPE_NAME,
			hc_url_get(url, HCURL_HEXID));
	if (NULL != err) {
		g_prefix_error(&err, "File error: ");
		return err;
	}

	return NULL;
}

GError*
meta2_backend_set_container_properties(struct meta2_backend_s *m2b,
		struct hc_url_s *url, guint32 flags, GSList *props)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	GRID_DEBUG("PROPSET(%s,...)", hc_url_get(url, HCURL_WHOLE));
	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		struct sqlx_repctx_s *repctx = NULL;
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (!(err = m2db_set_container_properties(sq3, flags, props)))
				m2db_increment_version(sq3);
			err = sqlx_transaction_end(repctx, err);
		}
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
	err = m2b_open(m2b, url, M2V2_OPEN_MASTERSLAVE
			|M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN, &sq3);
	if (!err) {
		g_assert(sq3 != NULL);
		err = m2db_get_container_properties(sq3, flags, cb_data, cb);
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
meta2_backend_add_modified_container(struct meta2_backend_s *m2b, const gchar *strid, gint64 size)
{
	if (m2b && strid) {
		g_mutex_lock(m2b->modified_containers_lock);
		g_hash_table_replace(m2b->modified_containers, g_strdup(strid), g_memdup(&size, sizeof(gint64)));
		g_mutex_unlock(m2b->modified_containers_lock);
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
		args.lbpool = m2b->glp;

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
		args.lbpool = m2b->glp;

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
		args.lbpool = m2b->glp;

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
				if (DESCR(beans->data) == &descr_struct_CONTENTS)
					err = m2db_delete_content(sq3, beans->data);
				else if (DESCR(beans->data) == &descr_struct_CHUNKS)
					err = m2db_delete_chunk(sq3, beans->data);
				else
					continue;
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
		struct hc_url_s *url, guint32 flags, gint64 *version)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERSLAVE
			|M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN, &sq3);
	if (!err) {
		err = m2db_get_alias_version(sq3, url, flags, version);
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
		err = m2db_get_properties(sq3, url, flags, cb, u0);
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

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERSLAVE
			|M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN, &sq3);
	if (!err) {
		err = m2db_get_property(sq3, url, prop_name, flags, cb, u0);
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
	struct sqlx_repctx_s *repctx = NULL;

	g_assert(m2b != NULL);
	g_assert(url != NULL);
	g_assert(prop_name != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (!(err = m2db_del_property(sq3, url, prop_name)))
				m2db_increment_version(sq3);
			err = sqlx_transaction_end(repctx, err);
		}
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
	struct sqlx_repctx_s *repctx = NULL;

	g_assert(m2b != NULL);
	g_assert(url != NULL);
	g_assert(prop_name != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (!(err = m2db_flush_property(sq3, prop_name)))
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
	gint64 max_versions;

	GRID_TRACE("M2 GET(%s)", hc_url_get(url, HCURL_WHOLE));

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		max_versions = _maxvers(sq3, m2b);
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (!(err = m2db_set_properties(sq3, max_versions, url, beans, cb, u0)))
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
		return NEWERROR(500, "NS not ready");

	/* Several checks are to be performed on the container state */
	err = m2b_open(m2b, url, M2V2_OPEN_MASTERSLAVE|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {

		gint64 max_version = _maxvers(sq3, m2b);
		if (m2b->flag_precheck_on_generate && !append &&
				VERSIONS_DISABLED(max_version)) {
			/* If the versioning is not supported, we check the content
			 * is not present */
			err = _check_alias_doesnt_exist(sq3, url);
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
		iter = grid_lbpool_get_iterator(m2b->glp, "rawx");
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
meta2_backend_get_container_status(struct meta2_backend_s *m2b,
		struct hc_url_s *url, guint32 *status)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	g_assert(m2b != NULL);
	g_assert(url != NULL);
	g_assert(status != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_LOCAL|M2V2_OPEN_NOREFCHECK, &sq3);
	if (!err) {
		err = m2db_get_container_status(sq3, status);
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
	enum m2v2_open_type_e type = M2V2_OPEN_LOCAL|M2V2_OPEN_NOREFCHECK;

	g_assert(m2b != NULL);
	g_assert(url != NULL);

	if (expected != NULL) {
		if (*expected == CONTAINER_STATUS_ENABLED)
			type |= M2V2_OPEN_ENABLED;
		else if (*expected == CONTAINER_STATUS_FROZEN)
			type |= M2V2_OPEN_FROZEN;
		else if (*expected == CONTAINER_STATUS_DISABLED)
			type |= M2V2_OPEN_DISABLED;
	}

	if (!(err = m2b_open(m2b, url, type, &sq3))) {
		err = m2db_set_container_status(sq3, repl);
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

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERSLAVE
			|M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN, &sq3);
	if (!err) {
		err = m2db_get_all_properties(sq3, k, flags, cb, u0);
		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_update_alias_header(struct meta2_backend_s *m2b, struct hc_url_s *url,
		GSList *beans, gboolean skip_checks)
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
			err = m2db_update_alias_header(sq3, max_versions, url, beans, skip_checks);
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
			err2 = service_info_from_chunk_id(m2b->glp, urls[i], &si);
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
	stgpol = storage_policy_init(&(m2b->ns_info), NULL);

	err = get_conditioned_spare_chunks(m2b->glp, count, dist,
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
		return NEWERROR(500, "NS not ready");

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

	err = get_conditioned_spare_chunks2(m2b->glp, pol, notin, broken,
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
		err = get_spare_chunks(m2b->glp, pol, result, use_beans);
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


// RESTORE ---------------------------------------------------------------------

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
	struct cb_data_s *cb_data = u;
	struct m2db_put_args_s args;
	GSList *beans = NULL;
	gboolean rc = FALSE;

	if (!p)
		return TRUE;

	g_assert(cb_data != NULL);
	GRID_TRACE("%s(%p,%p)", __FUNCTION__, u, p);

	/* patch the grid URL of the current content */
	hc_url_set(cb_data->url, HCURL_PATH, p->header.path);

	/* prepare the PUT arguments */
	memset(&args, 0, sizeof(args));
	args.sq3 = cb_data->sq3;
	args.url = cb_data->url;
	args.max_versions = cb_data->max_versions;
	args.lbpool = cb_data->m2b->glp;
	meta2_backend_get_nsinfo(cb_data->m2b, &(args.nsinfo));

	GRID_DEBUG("Restoring content %s", p->header.path);
	beans = m2v2_beans_from_raw_content_v2(NULL, p);
	GRID_DEBUG("Content converted to %d beans", (NULL != beans) ? g_slist_length(beans) : 0);

	GError *err = NULL;
		if (!(err = m2db_put_alias(&args, beans, NULL, NULL))) {
			m2db_increment_version(cb_data->sq3);
			meta2_backend_add_modified_container(cb_data->m2b,
					hc_url_get(cb_data->url, HCURL_HEXID),
					m2db_get_size(cb_data->sq3));
			rc = TRUE;
		}
	*(cb_data->perr) = err;

	namespace_info_clear(&(args.nsinfo));
	meta2_raw_content_v2_clean(p);
	return rc;
}

gboolean
_restore_admin(gpointer u, key_value_pair_t *p)
{
	int skip(const gchar *key) {
		return !g_ascii_strcasecmp(key, "namespace")
			|| g_str_has_prefix(key, "sys.")
			|| g_str_has_prefix(key, "user.");
	}
	struct cb_data_s *cb_data = u;

	GRID_TRACE("%s(%p,%p)", __FUNCTION__, u, p);

	if (p) {
		if (!skip(p->key)) {
			sqlx_admin_set_gba(cb_data->sq3, p->key, metautils_gba_dup(p->value));
		}
		key_value_pair_clean(p);
	}

	return TRUE;
}

gboolean
_restore_property(gpointer u, meta2_property_t *p)
{
	int skip(const gchar *k) {
		return !g_str_has_prefix(k, "user.")
			&& !g_str_has_prefix(k, "sys.");
	}
	struct cb_data_s *cb_data = u;

	GRID_TRACE("%s(%p,%p)", __FUNCTION__, u, p);

	if (p) {
		if (!skip(p->name)) {
			sqlx_admin_set_gba(cb_data->sq3, p->name, metautils_gba_dup(p->value));
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

	e = m2b_open(m2b, url, M2V2_OPEN_LOCAL
			|M2V2_OPEN_NOREFCHECK|M2V2_OPEN_AUTOCREATE
			|M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN, &sq3);
	if (!e) {
		if (sqlx_admin_has(sq3, META2_INIT_FLAG))
			e = NEWERROR(CODE_CONTAINER_EXISTS, "Container already initiated");
		else {
			// TODO FIXME XXX Pour bien faire il faudrait ici initialiser le
			// container comme lors d'un CREATE, c'est a dire lui affecter
			// une storage policy, un max de versions viable, etc
			sqlx_admin_init_i64(sq3, META2_INIT_FLAG, 1);
			m2db_set_max_versions(sq3, 0);

			memset(&cb_data, '\0', sizeof(cb_data));
			cb_data.m2b = m2b;
			cb_data.sq3 = sq3;
			cb_data.url = url;
			cb_data.perr = &cbe;
			cb_data.notify_data = notify_data;
			memcpy(&(cb_data.notify_hooks), notify_hooks, sizeof(cb_data.notify_hooks));
			cb_data.max_versions = _maxvers(sq3, m2b);
			GRID_DEBUG("Dump...");
			e = dump_cb(wrapper_data, &cb_data, &dump_hooks);
			GRID_DEBUG("Dump done");
		}
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

	GRID_DEBUG("Starting container restoration...");
	e = _restore_container(m2b, url, &wd, _dumpv1_wrapper, notify_udata, notify_hooks);
	GRID_DEBUG("Restoration done.");

	metacnx_close(&wd.peer_cnx);
	metacnx_clear(&wd.peer_cnx);
	return e;
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


//------------------------------------------------------------------------------

static void
_meta2_backend_send_container_list_to_m1(gchar *strm1, GSList *cid_list, GError **err)
{
	DEBUG("Sending list with %d elements", g_slist_length(cid_list));

	if (!meta1_remote_update_containers(strm1, cid_list, 4000, err)) {
		if(err && *err) {
			WARN("Request containers update to meta1 [%s] failed :%s", strm1, (*err)->message);
		} else {
			WARN("Request containers update to meta1 [%s] failed: no error", strm1);
		}
	}
}

void _add_cinfo_to_modified_containers(gpointer _cinfo, gpointer _m2b)
{
	container_info_t *cinfo = _cinfo;
	struct meta2_backend_s *m2b = _m2b;
	gchar strid[65];

	container_id_to_string(cinfo->id, strid, sizeof(strid));

	g_mutex_lock(m2b->modified_containers_lock);
	if (g_hash_table_lookup(m2b->modified_containers, strid)) {
		DEBUG("Container [%s] is already present in modified container list, "
				"no need to replace it.", strid);
	} else {
		g_hash_table_insert(m2b->modified_containers,
				g_strdup(strid), g_memdup(&(cinfo->size), sizeof(cinfo->size)));
		DEBUG("Container [%s] is back in modified containers list with a size of %"G_GINT64_FORMAT,
				strid, cinfo->size);
	}
	g_mutex_unlock(m2b->modified_containers_lock);
}

static void
_meta2_backend_process_containers_to_update(gpointer _p_prefix, gpointer _cinfo_list, gpointer _m2b)
{
	// k is actually a pointer to guint16
	guint16 *p_prefix = _p_prefix;
	const guint8 pfx0 = ((guint8*)_p_prefix)[0];
	const guint8 pfx1 = ((guint8*)_p_prefix)[1];
	GSList *cinfo_list = _cinfo_list;
	struct meta2_backend_s *m2b = _m2b;
	const guint nb_meta1 = g_slist_length(g_ptr_array_index(m2b->m0_mapping, 0));
	guint m1_index_to_pick = 0U, nb_tries = 0U;
	GError *err = NULL;
	gchar strm1[64];
	addr_info_t m1_addr;
	GSList *m1_list;

	// Get m1 address from m0_mapping and convert it to its string
	// representation.  If m1 are replicated, pick one randomly among
	// those available for this prefix.
	if (nb_meta1 > 1)
		m1_index_to_pick = g_random_int_range(0, nb_meta1);
	m1_list = g_ptr_array_index(m2b->m0_mapping, *p_prefix);

	do {
		g_clear_error(&err);
		memcpy (&m1_addr, g_slist_nth_data(m1_list, m1_index_to_pick), sizeof(addr_info_t));
		addr_info_to_string(&m1_addr, strm1, sizeof(strm1));
		nb_tries++;
		DEBUG("Processing update of container sizes for prefix [%02X%02X] (try %u with meta1 [%s]).",
				pfx0, pfx1, nb_tries, strm1);
		_meta2_backend_send_container_list_to_m1(strm1, cinfo_list, &err);
		m1_index_to_pick = (m1_index_to_pick + 1) % nb_meta1;
	} while (err && nb_tries < nb_meta1);

	if (err) {
		WARN("Could not update modified container sizes for prefix [%02X%02X]."
				"  Keeping track of modified containers for this prefix.",
				pfx0, pfx1);
		g_slist_foreach(cinfo_list, _add_cinfo_to_modified_containers, m2b);
		g_clear_error(&err);
	}
}

static GHashTable*
_meta2_backend_renew_modified_containers(struct meta2_backend_s *m2b)
{
	GHashTable *ht = m2b->modified_containers;
	m2b->modified_containers = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, g_free);
	return ht;
}

static void
_free_container_list(gpointer _clist)
{
	GSList *clist = _clist;
	g_slist_free_full(clist, g_free);
}

static void
_add_to_update_container_ht(GHashTable *containers_ht,
		container_info_t *p_ci, guint16 prefix)
{
	GSList *cid_list = NULL;
	// prefixes stored in hash table are gints
	gint *orig_prefix = NULL;
	gint prefix_int = prefix;

	// The g_hash_table_insert function calls destroy functions if the key
	// is found.  Here the list is updated, so the pointer may change and
	// we need to update the hash table, but we do not want the list to be
	// destroyed. This is why the key is removed manually before insertion.
	if (g_hash_table_lookup_extended(containers_ht, &prefix_int,
			(gpointer*) &orig_prefix, (gpointer*) &cid_list)) {
		// 'steal' removes a key without calling the destroy functions
		g_assert(g_hash_table_steal(containers_ht, orig_prefix));
		g_free(orig_prefix);
	}

	cid_list = g_slist_prepend(cid_list, g_memdup(p_ci, sizeof(*p_ci)));
	g_hash_table_insert(containers_ht, g_memdup(&prefix_int, sizeof(prefix_int)), cid_list);
}

void
meta2_backend_notify_modified_containers(struct meta2_backend_s *m2b)
{
	GHashTable *modified_containers, *containers_to_update;

	void _add_container_to_update(gpointer _strci, gpointer _p_csize, gpointer _udata)
	{
		gchar *strci = _strci;
		gint64 *p_csize = _p_csize;
		container_info_t ci;
		guint16 prefix;
		(void) _udata;

		// init container info
		ci.size = *p_csize;
		container_id_hex2bin(strci, strlen(strci), &(ci.id), NULL);
		TRACE("Add container to update id=%s size=%"G_GINT64_FORMAT, strci, *p_csize);

		// extract the prefix from the container id
		prefix = meta0_utils_bytes_to_prefix(ci.id);

		_add_to_update_container_ht(containers_to_update, &ci, prefix);
	}

	GRID_DEBUG("Sending modified containers list to concerned META1 services");

	g_mutex_lock(m2b->modified_containers_lock);
	modified_containers = _meta2_backend_renew_modified_containers(m2b);
	g_mutex_unlock(m2b->modified_containers_lock);

	// <prefix, [list of cid]>
	containers_to_update = g_hash_table_new_full(g_int_hash, g_int_equal,
			g_free, _free_container_list);

	// k is the container id in hex string, v is the size of the container
	g_hash_table_foreach(modified_containers, _add_container_to_update, NULL);
	g_hash_table_destroy(modified_containers);

	/* send containers list to update to m1 and free the list */
	g_hash_table_foreach(containers_to_update, _meta2_backend_process_containers_to_update, m2b);
	g_hash_table_destroy(containers_to_update);
}

#define CONNECT_RETRY_DELAY 10

gboolean
meta2_backend_build_meta0_prefix_mapping(struct meta2_backend_s *m2b)
{
	meta0_info_t* m0 = NULL;
	GError *err_local = NULL;
	GSList *m0_list = NULL;
	guint nb_updates = 0;
	gboolean status = FALSE;

	void _meta0_mapping_fill(gpointer d, gpointer u)
	{
		size_t j, max;
		guint16 prefix;
		GSList *m1_addr_list = NULL;
		meta0_info_t *mapping = (meta0_info_t*) d;
		(void)u;

		if (mapping->prefixes_size < 2)
			return;

		for (j=0, max=(mapping->prefixes_size-1); j<max ;j+=sizeof(guint16)) {
			memcpy (&prefix, mapping->prefixes+j, sizeof(guint16));
			prefix = GUINT16_FROM_LE(prefix);
			m1_addr_list = g_ptr_array_index(m2b->m0_mapping, prefix);
			m1_addr_list = g_slist_prepend(m1_addr_list,
					g_memdup(&(mapping->addr), sizeof(mapping->addr)));
			g_ptr_array_index(m2b->m0_mapping, prefix) = m1_addr_list;
			nb_updates ++;
		}
	}
	do {
		/* Get meta0 addr */
		err_local = NULL;
		m0 = get_meta0_info(m2b->ns_name, &err_local);
		if (!m0) {
			/* conscience or gridagent are probably not ready, see bug TO-HONEYCOMB-221 */
			if(err_local) {
				GRID_WARN("Cannot update containers in meta1, failed to get meta0 info from cluster: %s",
						err_local->message);
				g_clear_error(&err_local);
			} else {
				GRID_WARN("Cannot update containers in meta1, failed to get meta0 info from cluster: no_error");
			}
		} else {
			/* meta0 info OK, load meta1 mapping */
			err_local = NULL;
			m0_list = meta0_remote_get_meta1_all(&(m0->addr), 4000, &err_local);
			if (!m0_list) {
				/* meta0 is probably not ready, see bug TO-HONEYCOMB-221 */
				if (err_local) {
					GRID_WARN("Cannot get meta1 informations from meta0: %s", err_local->message);
					g_clear_error(&err_local);
				} else {
					GRID_WARN("Cannot get meta1 informations from meta0: no_error");
				}
				/* We must reload meta0 info each time in address in conscience changes. */
				meta0_info_clean(m0);
				m0 = NULL;
			} else {
				/* We got the list, we can leave the loop. */
				break;
			}
		}

		GRID_WARN("Retrying in %d seconds...", CONNECT_RETRY_DELAY);
		sleep(CONNECT_RETRY_DELAY);

	/* If we do not check that, meta2 won't die until meta0 actually answers */
	} while (grid_main_is_running());

	if (!grid_main_is_running()) {
		GRID_INFO("Was asked to stop, abort loading meta1 mappings");
		goto error_label;
	}

	g_slist_foreach (m0_list, _meta0_mapping_fill, NULL);
	g_slist_foreach (m0_list, meta0_info_gclean, NULL);
	g_slist_free (m0_list);

	/*sanity check : verify the number of mappings loaded*/
	if (nb_updates % 65536) {
		ERROR("The number of META0 mappings should be a multiple of 65536: %u mappings set.", nb_updates);
	} else {
		INFO("%u META0 mappings have been set (ok if meta1 are replicated %u times).", nb_updates, nb_updates / 65536U);
	}

	status = TRUE;

error_label:
	if (m0)
		meta0_info_clean(m0);
	return status;

}

gboolean
meta2_backend_is_quota_enabled(struct meta2_backend_s *m2b)
{
	return m2b && m2b->ns_info.writable_vns;
}



const gchar*
meta2_backend_get_local_addr(struct meta2_backend_s *m2)
{
	const gchar* m2url = NULL;

    struct election_manager_s* em = sqlx_repository_get_elections_manager(m2->repo);
    if (em) {
        const struct replication_config_s *emrc = election_manager_get_config(em);
        if (emrc) {
            m2url = emrc->get_local_url(emrc->ctx);
            GRID_DEBUG("%s: m2url:[%s]", __FUNCTION__, m2url);
        }
    }
	return m2url;
}



