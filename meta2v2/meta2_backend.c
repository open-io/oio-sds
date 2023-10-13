/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021-2023 OVH SAS

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

#include <errno.h>

#include <math.h>
#include <glib.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/common_variables.h>
#include <core/client_variables.h>
#include <server/server_variables.h>
#include <meta2v2/meta2_variables.h>
#include <events/events_variables.h>
#include <sqlx/sqlx_service.h>

#include <cluster/lib/gridcluster.h>

#include <sqliterepo/sqlite_utils.h>
#include <sqliterepo/sqliterepo.h>
#include <sqliterepo/election.h>

#include <events/beanstalkd.h>
#include <events/oio_events_queue.h>

#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>
#include <meta2v2/meta2_macros.h>
#include <meta2v2/meta2_utils_lb.h>
#include <meta2v2/meta2_utils_json.h>
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
	M2V2_OPEN_NOREFCHECK  = 0x020,
	M2V2_OPEN_URGENT      = 0x040,

	// Set an OR'ed combination of the following flags to require
	// a check on the container's status during the open phase.
	// No flag set means no check.
	M2V2_OPEN_ENABLED     = 0x100,
	M2V2_OPEN_FROZEN      = 0x200,
	M2V2_OPEN_DISABLED    = 0x400,
};

struct m2_open_args_s
{
	enum m2v2_open_type_e how;
	const gchar *peers;
	gint64 deadline;
};

struct m2_prepare_data
{
	gint64 max_versions;
	gint64 quota;
	gint64 size;
	gchar storage_policy[LIMIT_LENGTH_STGPOLICY];
};

gchar* SHARED_KEYS[4] = {
	M2V2_ADMIN_BUCKET_NAME,
	M2V2_ADMIN_VERSIONING_POLICY,
	SQLX_ADMIN_STATUS,
	NULL
};

static GError* _connect_to_sharding_queue(struct oio_url_s *url,
		gchar *beanstalkd_endpoint, gint64 timestamp,
		struct beanstalkd_s **pbeanstalkd);

static void _meta2_backend_force_prepare_data(struct meta2_backend_s *m2b,
		const gchar *key, struct sqlx_sqlite3_s *sq3);

static GError* _transaction_begin(struct sqlx_sqlite3_s *sq3,
		struct oio_url_s *url, struct sqlx_repctx_s **result);

static void m2b_add_modified_container(struct meta2_backend_s *m2b,
		struct sqlx_sqlite3_s *sq3);
/* Interface is a little different from m2b_add_modified_container
 * because this will be called after sq3 is released. */
static void m2b_flush_modified_container(struct meta2_backend_s *m2b,
		gchar *basename);

static GError* _meta2_abort_sharding(struct meta2_backend_s *m2b,
		struct sqlx_sqlite3_s *sq3, struct oio_url_s *url);

static enum m2v2_open_type_e
_mode_masterslave(guint32 flags)
{
	if ((flags & M2V2_FLAG_MASTER) || oio_ext_has_force_master())
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

static GError *
_init_notifiers(struct meta2_backend_s *m2, const char *ns)
{
#define INIT(Out,Tube) if (!err) { \
	err = oio_events_queue_factory__create(url, (Tube), &(Out)); \
	g_assert((err != NULL) ^ ((Out) != NULL)); \
	if (!err) {\
		err = oio_events_queue__start((Out)); \
		oio_events_stats_register(#Out + sizeof("m2->notifier"), Out); \
	} \
}
	gchar *url = oio_cfg_get_eventqueue(ns, "meta2");
	if (!url)
		return NULL;
	STRING_STACKIFY(url);

	GError *err = NULL;
	INIT(m2->notifier_container_created, oio_meta2_tube_container_new);
	INIT(m2->notifier_container_deleted, oio_meta2_tube_container_deleted);
	INIT(m2->notifier_container_state, oio_meta2_tube_container_state);
	INIT(m2->notifier_container_updated, oio_meta2_tube_container_updated);

	INIT(m2->notifier_content_created, oio_meta2_tube_content_created);
	INIT(m2->notifier_content_appended, oio_meta2_tube_content_appended);
	INIT(m2->notifier_content_deleted, oio_meta2_tube_content_deleted);
	INIT(m2->notifier_content_updated, oio_meta2_tube_content_updated);
	INIT(m2->notifier_content_broken, oio_meta2_tube_content_broken);
	INIT(m2->notifier_content_drained, oio_meta2_tube_content_drained);

	INIT(m2->notifier_meta2_deleted, oio_meta2_tube_meta2_deleted);

	return err;
#undef INIT
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
	m2->resolver = resolver;

	GError *err;

	err = sqlx_repository_configure_type(m2->repo, NAME_SRVTYPE_META2, schema);
	if (NULL != err) {
		g_prefix_error(&err, "Schema error: ");
		goto exit;
	}

	err = _init_notifiers(m2, ns);
	if (err) {
		g_prefix_error(&err, "Events queue error: ");
		goto exit;
	}

	*result = m2;
	return NULL;
exit:
	meta2_backend_clean(m2);
	g_prefix_error(&err, "Backend init error: ");
	return err;
}

#define CLEAN(N) if (N) { \
	oio_events_stats_unregister(#N + sizeof("m2->notifier")); \
	oio_events_queue__destroy(N); \
	N = NULL; \
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

	CLEAN(m2->notifier_container_created);
	CLEAN(m2->notifier_container_deleted);
	CLEAN(m2->notifier_container_state);
	CLEAN(m2->notifier_container_updated);

	CLEAN(m2->notifier_content_created);
	CLEAN(m2->notifier_content_appended);
	CLEAN(m2->notifier_content_deleted);
	CLEAN(m2->notifier_content_updated);
	CLEAN(m2->notifier_content_broken);
	CLEAN(m2->notifier_content_drained);

	CLEAN(m2->notifier_meta2_deleted);

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
	if (t & M2V2_OPEN_NOREFCHECK)
		result |= SQLX_OPEN_NOREFCHECK;
	if (t & M2V2_OPEN_URGENT)
		result |= SQLX_OPEN_URGENT;

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
	 * because of a (now-fixed) inexistent check on the flag. */
	if (sqlx_admin_has(sq3, M2V2_ADMIN_OBJ_COUNT)
			|| sqlx_admin_has(sq3, M2V2_ADMIN_SIZE)) {
		GRID_DEBUG("DB partially initiated: [%s][%.s]",
				sq3->name.base, sq3->name.type);
		return TRUE;
	}

	return FALSE;
}

static gchar *
_container_state(struct sqlx_sqlite3_s *sq3, gboolean deleted)
{
	void sep (GString *gs1) {
		if (gs1->len > 1 && !strchr(",[{", gs1->str[gs1->len-1]))
			g_string_append_c(gs1, ',');
	}
	void append_int64 (GString *gs1, const char *k, gint64 v) {
		sep(gs1);
		g_string_append_printf(gs1, "\"%s\":%"G_GINT64_FORMAT, k, v);
	}
	void append_str(GString *gs1, const char *k, gchar *v) {
		sep(gs1);
		oio_str_gstring_append_json_pair(gs1, k, v);
		g_free(v);
	}

	gchar **properties = NULL;
	struct oio_url_s *url = sqlx_admin_get_url(sq3);
	GString *gs = oio_event__create_with_id(
			deleted ? META2_EVENTS_PREFIX ".container.deleted"
					: META2_EVENTS_PREFIX ".container.state",
			url, oio_ext_get_reqid());
	g_string_append_static(gs, ",\"data\":{");
	append_str(gs, "bucket", sqlx_admin_get_str(sq3, M2V2_ADMIN_BUCKET_NAME));
	append_str(gs, "policy", sqlx_admin_get_str(sq3, M2V2_ADMIN_STORAGE_POLICY));
	append_int64(gs, "ctime", m2db_get_ctime(sq3));
	// If the container is deleted while it contained objects,
	// send a consistent number of bytes
	append_int64(gs, "bytes-count", deleted ? 0 : m2db_get_size(sq3));
	properties = m2db_get_size_properties_by_policy(sq3);
	if (properties) {
		g_string_append_static(gs, ",\"bytes-details\":{");
		for (gchar **p=properties; *p && *(p+1) ;p+=2) {
			append_int64(gs, (*p) + sizeof(M2V2_ADMIN_SIZE".") - 1,
					g_ascii_strtoll(*(p+1), NULL, 10));
		}
		g_string_append_static(gs, "}");
		g_strfreev(properties);
	}
	// If the container is deleted while it contained objects,
	// send a consistent number of objects
	append_int64(gs, "object-count", deleted ? 0 : m2db_get_obj_count(sq3));
	properties = m2db_get_obj_count_properties_by_policy(sq3);
	if (properties) {
		g_string_append_static(gs, ",\"objects-details\":{");
		for (gchar **p=properties; *p && *(p+1) ;p+=2) {
			append_int64(gs, (*p) + sizeof(M2V2_ADMIN_OBJ_COUNT".") - 1,
					g_ascii_strtoll(*(p+1), NULL, 10));
		}
		g_string_append_static(gs, "}");
		g_strfreev(properties);
	}
	g_string_append_static(gs, "}}");

	oio_url_clean(url);
	return g_string_free(gs, FALSE);
}

static void
m2b_add_modified_container(struct meta2_backend_s *m2b,
		struct sqlx_sqlite3_s *sq3)
{
	EXTRA_ASSERT(m2b != NULL);
	if (m2b->notifier_container_state)
		oio_events_queue__send_overwritable(
				m2b->notifier_container_state,
				sqlx_admin_get_str(sq3, SQLX_ADMIN_BASENAME),
				_container_state(sq3, FALSE));

	gboolean has_peers = FALSE;
	NAME2CONST(n, sq3->name);
	GError *err = election_has_peers(sq3->manager, &n, FALSE, &has_peers);
	if (!err && !has_peers) {
		meta2_backend_change_callback(sq3, m2b);
	}
	g_clear_error(&err);
}

static void
m2b_flush_modified_container(struct meta2_backend_s *m2b,
		gchar *basename)
{
	EXTRA_ASSERT(m2b != NULL);
	if (m2b->notifier_container_state) {
		oio_events_queue__flush_overwritable(
				m2b->notifier_container_state,
				basename);
	} else {
		g_free(basename);
	}
}

static void
_sql_queries_pack(gpointer value, gpointer data) {
	GString *beanstalkd_job = data;
	if (!value)
		return;
	if (beanstalkd_job->str[beanstalkd_job->len - 1] != '[')
		g_string_append_c(beanstalkd_job, ',');
	oio_str_gstring_append_json_quote(beanstalkd_job, value);
}

static void
m2b_close(struct meta2_backend_s *m2b, struct sqlx_sqlite3_s *sq3,
		struct oio_url_s *url)
{
	EXTRA_ASSERT(m2b != NULL);

	if (!sq3)
		return;
	if (!sq3->sharding_queue || !sq3->update_queries)
		goto exit;

	GString *beanstalkd_job = g_string_new("{");
	oio_str_gstring_append_json_pair(beanstalkd_job, "path",
			url ? oio_url_get(url, OIOURL_PATH): NULL);
	g_string_append_c(beanstalkd_job, ',');
	oio_str_gstring_append_json_quote(beanstalkd_job, "queries");
	g_string_append(beanstalkd_job, ":[");
	g_list_foreach(sq3->update_queries, _sql_queries_pack, beanstalkd_job);
	g_string_append(beanstalkd_job, "]}");
	GError *err = beanstalkd_put_job(sq3->sharding_queue, beanstalkd_job->str,
			beanstalkd_job->len);
	g_string_free(beanstalkd_job, TRUE);
	if (err) {
		GRID_ERROR("Failed to put in sharding queue, "
				"aborting sharding...: (%d) %s", err->code, err->message);
		g_clear_error(&err);
		err = _meta2_abort_sharding(m2b, sq3, url);
		if (err) {
			GRID_ERROR("Failed to abort sharding: (%d) %s",
					err->code, err->message);
			g_clear_error(&err);
		}
		goto exit;
	}

exit:
	sqlx_repository_unlock_and_close_noerror(sq3);
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
m2b_open_with_args(struct meta2_backend_s *m2, struct oio_url_s *url,
		const char *suffix, struct m2_open_args_s *open_args,
		struct sqlx_sqlite3_s **result)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(result != NULL);
	EXTRA_ASSERT(m2 != NULL);
	EXTRA_ASSERT(m2->repo != NULL);

	struct sqlx_name_inline_s n0;
	sqlx_inline_name_fill(&n0, url, NAME_SRVTYPE_META2, 1, suffix);
	NAME2CONST(n,n0);
	enum m2v2_open_type_e how = open_args->how;
	gint64 deadline = open_args->deadline;
	if (deadline <= 0) {
		deadline = oio_ext_get_deadline();
	}

	err = sqlx_repository_timed_open_and_lock(m2->repo, &n, m2_to_sqlx(how),
		   open_args->peers, &sq3, NULL, deadline);
	if (err) {
		if (err->code == CODE_CONTAINER_NOTFOUND)
			err->domain = GQ();
		return err;
	}

	/* The kind of check we do depend of the kind of opening:
	 * - creation: init not done */
	const gboolean _create = (M2V2_OPEN_AUTOCREATE == (how & M2V2_OPEN_AUTOCREATE));
	if (_create && _is_container_initiated(sq3)) {
		sqlx_repository_unlock_and_close_noerror(sq3);
		return NEWERROR(CODE_CONTAINER_EXISTS,
				"container already initiated");
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

	gchar *root_hexid = sqlx_admin_get_str(sq3, M2V2_ADMIN_SHARDING_ROOT);
	if (root_hexid != NULL) {
		oio_url_set(url, OIOURL_ROOT_HEXID, root_hexid);
		g_free(root_hexid);
	} else {
		oio_url_unset(url, OIOURL_ROOT_HEXID);
	}

	*result = sq3;
	return NULL;
}

/** Do all necessary checks and create the queue which will save SQL queries
 * while a sharding operation is in progress. */
static GError *
m2b_check_sharding_queue(struct meta2_backend_s *m2,
		struct sqlx_sqlite3_s *sq3, struct oio_url_s *url)
{
	GError *err = NULL;
	gchar *sharding_master = NULL;
	gchar *sharding_queue = NULL;
	// EXISTING_SHARD_STATE_SAVING_WRITES
	// Check sharding properties
	gint64 sharding_timestamp = sqlx_admin_get_i64(sq3,
			M2V2_ADMIN_SHARDING_TIMESTAMP, 0);
	if (!sharding_timestamp) {
		// Should never happen
		GRID_ERROR("Missing sharding timestamp, aborting sharding...");
		err = _meta2_abort_sharding(m2, sq3, url);
		if (err) {
			GRID_ERROR("Failed to abort sharding: (%d) %s",
					err->code, err->message);
			g_clear_error(&err);
		}
		goto exit;
	}
	sharding_master = sqlx_admin_get_str(sq3, M2V2_ADMIN_SHARDING_MASTER);
	if (!sharding_master) {
		// Should never happen
		GRID_ERROR("Missing sharding master, aborting sharding...");
		err = _meta2_abort_sharding(m2, sq3, url);
		if (err) {
			GRID_ERROR("Failed to abort sharding: (%d) %s",
					err->code, err->message);
			g_clear_error(&err);
		}
		goto exit;
	}
	sharding_queue = sqlx_admin_get_str(sq3,
			M2V2_ADMIN_SHARDING_QUEUE);
	if (!sharding_queue) {
		// Should never happen
		GRID_ERROR("Missing sharding queue, aborting sharding...");
		err = _meta2_abort_sharding(m2, sq3, url);
		if (err) {
			GRID_ERROR("Failed to abort sharding: (%d) %s",
					err->code, err->message);
			g_clear_error(&err);
		}
		goto exit;
	}
	// Check if sharding timeout has not expired
	gint64 timestamp = oio_ext_real_time();
	if (timestamp - sharding_timestamp > meta2_sharding_timeout) {
		GRID_ERROR("After more than %"G_GINT64_FORMAT" seconds, "
				"sharding is still not complete, aborting sharding...",
				meta2_sharding_timeout);
		err = _meta2_abort_sharding(m2, sq3, url);
		if (err) {
			GRID_ERROR("Failed to abort sharding: (%d) %s",
					err->code, err->message);
			g_clear_error(&err);
		}
		goto exit;
	}
	// Check sharding master
	const gchar *master = sqlx_get_service_id();
	if (!master || !*master) {
		// Should never happen
		GRID_ERROR("No service ID, aborting sharding...");
		err = _meta2_abort_sharding(m2, sq3, url);
		if (err) {
			GRID_ERROR("Failed to abort sharding: (%d) %s",
					err->code, err->message);
			g_clear_error(&err);
		}
		goto exit;
	}
	if (g_strcmp0(master, sharding_master) != 0) {
		GRID_ERROR("Master has changed, aborting sharding...");
		err = _meta2_abort_sharding(m2, sq3, url);
		if (err) {
			GRID_ERROR("Failed to abort sharding: (%d) %s",
					err->code, err->message);
			g_clear_error(&err);
		}
		goto exit;
	}
	// Check sharding queue
	if (!sq3->sharding_queue) {
		struct beanstalkd_s *beanstalkd = NULL;
		err = _connect_to_sharding_queue(url,
				sharding_queue, sharding_timestamp, &beanstalkd);
		if (err) {
			GRID_ERROR("Failed to connect to sharding queue, "
					"aborting sharding...: (%d) %s", err->code, err->message);
			g_clear_error(&err);
			err = _meta2_abort_sharding(m2, sq3, url);
			if (err) {
				GRID_ERROR("Failed to abort sharding: (%d) %s",
						err->code, err->message);
				g_clear_error(&err);
			}
			goto exit;
		}
		sq3->sharding_queue = beanstalkd;
	}
	sq3->save_update_queries = 1;

exit:
	g_free(sharding_master);
	g_free(sharding_queue);
	return err;
}

static GError *
m2b_open(struct meta2_backend_s *m2, struct oio_url_s *url,
		enum m2v2_open_type_e how, struct sqlx_sqlite3_s **result)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct m2_open_args_s args = {how, NULL, 0};
	enum m2v2_open_type_e replimode = how & M2V2_OPEN_REPLIMODE;

reopen:
	err = m2b_open_with_args(m2, url, NULL, &args, &sq3);
	if (err)
		return err;

	if (replimode == M2V2_OPEN_LOCAL)
		goto exit;

	gint64 sharding_state = sqlx_admin_get_i64(sq3,
			M2V2_ADMIN_SHARDING_STATE, 0);
	if (sharding_state == EXISTING_SHARD_STATE_LOCKED) {
		sqlx_repository_unlock_and_close_noerror(sq3);
		sq3 = NULL;
		g_thread_yield();
		goto reopen;
	}

	if (replimode != M2V2_OPEN_MASTERONLY)
		goto exit;  // Nothing special to do, exit successfully

	if (sharding_state == EXISTING_SHARD_STATE_SAVING_WRITES) {
		err = m2b_check_sharding_queue(m2, sq3, url);
	} else {
		if (sq3->sharding_queue) {
			// Should never happen
			GRID_WARN("For sharding, "
					"a connection to the beanstalkd was left open");
			beanstalkd_destroy(sq3->sharding_queue);
			sq3->sharding_queue = NULL;
		}
	}

exit:
	if (err)
		m2b_close(m2, sq3, url);
	else
		*result = sq3;
	return err;
}

static GError *
_update_properties_with_root_container_properties(
		struct sqlx_sqlite3_s *sq3, struct oio_url_s *url)
{
	GError *err = NULL;
	gchar **shared_properties = oio_ext_get_shared_properties();
	if (shared_properties) {
		struct sqlx_repctx_s *repctx = NULL;
		gboolean changed = FALSE;
		for (gchar **p=shared_properties; *p && *(p+1); p+=2) {
			gchar *current_value = sqlx_admin_get_str(sq3, *p);
			gchar *new_value = *(p+1);
			if (!*new_value)
				new_value = NULL;
			if (g_strcmp0(current_value, new_value)) {
				if (!changed) {
					// First change, open the transaction
					err = _transaction_begin(sq3, url, &repctx);
					if (err) {
						return err;
					}
				}
				changed = TRUE;
				if (new_value) {
					GRID_DEBUG("Set %s property with %s "
							"to have the same as on the root container",
							*p, new_value);
					sqlx_admin_set_str(sq3, *p, new_value);
				} else {
					GRID_DEBUG("Delete %s property "
							"to have the same as on the root container",
							*p);
					sqlx_admin_del(sq3, *p);
				}
			}
			g_free(current_value);
		}
		if (changed) {
			m2db_increment_version(sq3);
			err = sqlx_transaction_end(repctx, err);
			if (err) {
				return err;
			}
		}
	}
	// Reset the shared properties so that these properties
	// aren't resent to the proxy server.
	oio_ext_set_shared_properties(NULL);
	return NULL;
}

static GError *
_check_shard_range(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		const gchar *path, gboolean read_only)
{
	GError *err = NULL;

	if (!sqlx_admin_has(sq3, M2V2_ADMIN_SHARDING_ROOT)) {
		err = SYSERR("Not a shard");
		goto end;
	}

	// It's a shard, check shard range
	err = m2db_check_shard_range(sq3, path);
	if (err) {
		goto end;
	}

	if (!read_only) {
		err = _update_properties_with_root_container_properties(sq3, url);
		if (err) {
			g_prefix_error(&err, "Failed to update properties in shard: ");
			goto end;
		}
	}

end:
	if (err) {
		g_prefix_error(&err, "Failed to check shard range: ");
	}
	return err;
}

static GError *
_redirect_to_shard(struct sqlx_sqlite3_s *sq3, const gchar *path)
{
	GError *err = NULL;

	if (!m2db_get_shard_count(sq3)) {
		// No sharding
		goto end;
	}

	// It's a root container, redirect to shard container
	struct bean_SHARD_RANGE_s *shard_range = NULL;
	err = m2db_get_shard_range(sq3, path, &shard_range);
	if (err) {
		goto fail;
	}

	// Redirect to shard
	GSList *redirect_shard = NULL;
	redirect_shard = g_slist_prepend(redirect_shard, shard_range);
	GString *redirect_message = g_string_new("{\"redirect\":");
	meta2_json_shard_ranges_only(redirect_message, redirect_shard, FALSE);
	g_string_append_static(redirect_message, "}");
	err = NEWERROR(CODE_REDIRECT_SHARD, "%s", redirect_message->str);
	g_string_free(redirect_message, TRUE);
	_bean_cleanl2(redirect_shard);

	// Share some properties with the shard
	GPtrArray *tmp = g_ptr_array_new();
	for (gchar **shared_key=SHARED_KEYS; *shared_key; shared_key+=1) {
		gchar *value = sqlx_admin_get_str(sq3, *shared_key);
		g_ptr_array_add(tmp, g_strdup(*shared_key));
		g_ptr_array_add(tmp, value ? value : g_strdup(""));
	}
	oio_ext_set_shared_properties(
			(gchar**) metautils_gpa_to_array(tmp, TRUE));

	goto end;

fail:
	g_prefix_error(&err, "Failed to redirect to shard: ");
end:
	return err;
}

static GError*
_connect_to_sharding_queue(struct oio_url_s *url,
		gchar *beanstalkd_endpoint, gint64 timestamp,
		struct beanstalkd_s **pbeanstalkd)
{
	GError *err = NULL;
	struct beanstalkd_s *beanstalkd = NULL;

	gchar *tube = g_strdup_printf("%s.sharding-%"G_GINT64_FORMAT,
			oio_url_get(url, OIOURL_HEXID), timestamp);
	err = beanstalkd_create(beanstalkd_endpoint, tube, &beanstalkd);
	g_free(tube);
	if (err)
		return err;

	err = beanstalkd_reconnect(beanstalkd);
	if (err)
		beanstalkd_destroy(beanstalkd);
	else
		*pbeanstalkd = beanstalkd;
	return err;
}

static GError *
m2b_open_for_object(struct meta2_backend_s *m2b, struct oio_url_s *url,
		enum m2v2_open_type_e how, struct sqlx_sqlite3_s **result)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	enum m2v2_open_type_e replimode = how & M2V2_OPEN_REPLIMODE;

	err = m2b_open(m2b, url, how, &sq3);
	if (err)
		return err;

	const gchar *path = oio_url_get(url, OIOURL_PATH);
	if (oio_ext_is_shard_redirection())
		err = _check_shard_range(sq3, url, path,
				replimode != M2V2_OPEN_MASTERONLY);
	else
		err = _redirect_to_shard(sq3, path);
	if (err)
		m2b_close(m2b, sq3, url);
	else
		*result = sq3;
	return err;
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

static GError *
_table_is_empty(struct sqlx_sqlite3_s *sq3, const gchar *table)
{
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;
	gint64 count = 0;
	gchar query[128] = {0};

	/* In case the table name is too long, sqlite3_prepare_v2 will report
	 * an invalid statement error (but won't crash). */
	g_snprintf(query, sizeof(query),
			"SELECT exists(SELECT 1 FROM %s LIMIT 1)", table);

	int rc = sqlite3_prepare_v2(sq3->db, query, -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		return NEWERROR(CODE_INTERNAL_ERROR, "SQLite error: (%d) %s",
				rc, sqlite3_errmsg(sq3->db));
	}

	while (SQLITE_ROW == (rc = sqlite3_step(stmt)))
		count = sqlite3_column_int64(stmt, 0);
	if (rc != SQLITE_OK && rc != SQLITE_DONE) {
		err = NEWERROR(CODE_INTERNAL_ERROR, "SQLite error: (%d) %s",
				rc, sqlite3_errmsg(sq3->db));
	}
	sqlx_sqlite3_finalize(sq3, stmt, err);

	if (!err && count > 0)
		err = NEWERROR(CODE_CONTAINER_NOTEMPTY, "Table '%s' not empty", table);

	return err;
}

static GError *
_check_if_container_empty(struct sqlx_sqlite3_s *sq3)
{
	EXTRA_ASSERT(sq3 != NULL && sq3->db != NULL);

	GError *err = NULL;

	// Check if the container contains data
	err = _table_is_empty(sq3, "aliases");

	if (!err) {
		/* Check if the container is sharded.
		 * If the container is sharded,
		 * then it probably still contains data in shards. */
		err = _table_is_empty(sq3, "shard_ranges");
	}

	if (!err) {
		/* Check for chunks, but do not fail.
		 * We have seen chunks being rebuilt while the object was deleted. */
		err = _table_is_empty(sq3, "chunks");
		if (err) {
			GRID_WARN("Database has no contents nor shards, "
					"but still contains chunks (reqid=%s)",
					oio_ext_get_reqid());
			g_clear_error(&err);
		}
	}

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
		m2b_close(m2, sq3, url);
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
		m2b_close(m2b, sq3, url);
	}

	return err;
}

static GError *
_init_container(struct sqlx_sqlite3_s *sq3,
		struct oio_url_s *url, struct m2v2_create_params_s *params)
{
	GError *err = NULL;
	struct sqlx_repctx_s *repctx = NULL;
	gboolean object_lock_enabled = FALSE;

	if (!params->local && (err = _transaction_begin(sq3, url, &repctx)))
		return err;

	if (!err) {
		m2db_set_ctime (sq3, oio_ext_real_time());
		m2db_set_size(sq3, 0);
		m2db_set_obj_count(sq3, 0);
		m2db_set_shard_count(sq3, 0);
		sqlx_admin_set_status(sq3, ADMIN_STATUS_ENABLED);
		sqlx_admin_init_i64(sq3, META2_INIT_FLAG, 1);
	}
	if (!err && params->properties) {
		for (gchar **p=params->properties; *p && *(p+1) ;p+=2) {
			sqlx_admin_set_str (sq3, *p, *(p+1));
			// During bucket creation
			if (g_strcmp0(*p, M2V2_ADMIN_BUCKET_OBJECT_LOCK_ENABLED) == 0)
			{
				err = m2db_create_triggers(sq3);
				if (err) {
					break;
				} else {
					object_lock_enabled = TRUE;
				}
			}
		}
	}
	if (!err && params->storage_policy)
		err = m2db_set_storage_policy(sq3, params->storage_policy, TRUE);
	if (!err && params->version_policy) {
		gint64 max = g_ascii_strtoll(params->version_policy, NULL, 10);
		m2db_set_max_versions(sq3, max);
	}
	if (!params->local) {
		if (object_lock_enabled) {
			/* Force copy database during creation to set up triggers */
			sqlx_transaction_notify_huge_changes(repctx);
		}
		err = sqlx_transaction_end(repctx, err);
	}
	return err;
}

static GError *
_get_meta2_peers(struct sqlx_sqlite3_s *sq3, struct meta2_backend_s *m2,
		GString *peers_array)
{
	GError *err = NULL;
	gchar **peers = NULL;

	NAME2CONST(name, sq3->name);

	EXTRA_ASSERT(peers_array != NULL);

	const enum election_status_e election_status = sq3->election;
	if (election_status == ELECTION_LEADER){
		err = sqlx_repository_get_peers(m2->repo, &name, &peers);
		if (err)
			return err;
	}

	const gchar *local_addr = sqlx_repository_get_local_addr(m2->repo);
	EXTRA_ASSERT(local_addr != NULL);

	g_string_append_static(peers_array, "\"peers\":[");
	oio_str_gstring_append_json_quote(peers_array, local_addr);

	// This is either a NULL terminated array of all the peers or a NULL ptr.
	// If there's no elections or no peers, then we find ourselves with
	// a NULL ptr.
	for (gchar **peer = peers; peers && *peer; peer++) {
		g_string_append_c(peers_array, ',');
		oio_str_gstring_append_json_quote(peers_array, *peer);
	}
	g_string_append(peers_array, "]");
	g_strfreev(peers);
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
	struct m2_open_args_s open_args = {0};
	open_args.how = M2V2_OPEN_AUTOCREATE |
		(params->local ? M2V2_OPEN_LOCAL : M2V2_OPEN_MASTERONLY);
	open_args.peers = params->peers;

	err = m2b_open_with_args(m2, url, NULL, &open_args, &sq3);
	EXTRA_ASSERT((sq3 != NULL) ^ (err != NULL));
	if (err) {
		if (err->code == CODE_CONTAINER_NOTFOUND) {
			// The container is being deleted
			err->code = CODE_UNAVAILABLE;
		}
		return err;
	}

	/* At this point the base exist and it has nt been initiated yet */
	err = _init_container(sq3, url, params);
	if (err) {
		m2b_destroy(sq3);
		return err;
	}

	/* Fire an event to notify the world this container exists */
	const enum election_status_e s = sq3->election;
	if (!params->local && m2->notifier_container_created
			&& (!s || s == ELECTION_LEADER)) {
		GString *peers_list = g_string_sized_new(1024);
		err = _get_meta2_peers(sq3, m2, peers_list);
		if (err != NULL){
			m2b_destroy(sq3);
			g_string_free(peers_list, TRUE);
			return err;
		}
		GString *gs = oio_event__create_with_id(
				META2_EVENTS_PREFIX".container.new", url, oio_ext_get_reqid());
		struct db_properties_s *db_properties = db_properties_new();
		if (params->properties) {
			for (gchar **p=params->properties; *p && *(p+1); p+=2) {
				db_properties_add(db_properties, *p, *(p+1));
			}
		}
		g_string_append_static(gs, ",\"data\":{");
		db_properties_to_json(db_properties, gs);
		db_properties_free(db_properties);
		g_string_append_c(gs, ',');
		g_string_append(gs, peers_list->str);
		g_string_free(peers_list, TRUE);
		gchar *bucket = sqlx_admin_get_str(sq3, M2V2_ADMIN_BUCKET_NAME);
		g_string_append_c(gs, ',');
		oio_str_gstring_append_json_pair(gs, "bucket", bucket);
		g_free(bucket);
		g_string_append_static(gs, "}}");
		oio_events_queue__send(m2->notifier_container_created, g_string_free (gs, FALSE));
	}

	/* Reload any cache maybe already associated with the container.
	 * It happens that the cache sometimes exists because created during a
	 * M2_PREP that occurred after a GETVERS (the meta1 is filled) but before
	 * the CREATE. */
	meta2_backend_change_callback(sq3, m2);
	m2b_close(m2, sq3, url);
	return err;
}

GError *
meta2_backend_destroy_container(struct meta2_backend_s *m2,
		struct oio_url_s *url, guint32 flags)
{
	gboolean send_event = BOOL(flags & M2V2_DESTROY_EVENT);
	gboolean force = BOOL(flags & M2V2_DESTROY_FORCE);
	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = NULL;

	err = m2b_open(m2, url, M2V2_OPEN_LOCAL|M2V2_OPEN_URGENT, &sq3);
	if (!err) {
		EXTRA_ASSERT(sq3 != NULL);

		if (!force)
			err = _check_if_container_empty (sq3);

		/* TODO(jfs): manage base's subtype */
		hc_decache_reference_service(m2->resolver, url, NAME_SRVTYPE_META2);

#ifdef HAVE_ENBUG
		if (send_event && !err) {
			gint32 random = oio_ext_rand_int_range(0,3);
			switch (random) {
				case 0:
					err = NEWERROR(CODE_BAD_REQUEST, "Fake error (meta2)");
					break;
				case 1:
					sleep(100);
					break;
			}
		}
#endif

		if (!err) {
			gchar *event_data = NULL;
			/* The event must be computed before destroying the DB. */
			if (m2->notifier_container_deleted && send_event) {
				event_data = _container_state(sq3, TRUE);
			}
			gchar *basename = sqlx_admin_get_str(sq3, SQLX_ADMIN_BASENAME);
			m2b_destroy(sq3);
			m2b_flush_modified_container(m2, basename);
			/* But we send it only after to avoid keeping locks too long. */
			if (m2->notifier_container_deleted && send_event) {
				oio_events_queue__send(
						m2->notifier_container_deleted, event_data);
			}
		} else {
			m2b_close(m2, sq3, url);
		}
	}

	return err;
}

GError *
meta2_backend_flush_container(struct meta2_backend_s *m2, struct oio_url_s *url,
		m2_onbean_cb cb, gpointer u0, gboolean *truncated)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	err = m2b_open(m2, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED
			|M2V2_OPEN_FROZEN, &sq3);
	if (!err) {
		EXTRA_ASSERT(sq3 != NULL);
		if (!(err = sqlx_transaction_begin(sq3, &repctx))) {
			err = m2db_flush_container(sq3, cb, u0, truncated);
			err = sqlx_transaction_end(repctx, err);
		}
		if (!err) {
			m2b_add_modified_container(m2, sq3);
			if (!(*truncated)) {
				int rc = sqlx_exec(sq3->db, "VACUUM");
				if (rc != SQLITE_OK)
					err = SQLITE_GERROR(sq3->db, rc);

				if (!err) {
					if (!(err = sqlx_transaction_begin(sq3, &repctx))) {
						if (!err)
							sqlx_transaction_notify_huge_changes(repctx);
						err = sqlx_transaction_end(repctx, err);
					}
				}
			}
		}
		m2b_close(m2, sq3, url);
	}

	return err;
}

GError *
meta2_backend_purge_container(struct meta2_backend_s *m2, struct oio_url_s *url,
	gint64 *pmaxvers, m2_onbean_cb cb, gpointer u0)
{
	GError *err;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	err = m2b_open(m2, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		EXTRA_ASSERT(sq3 != NULL);
		if (!(err = sqlx_transaction_begin(sq3, &repctx))) {
			gint64 maxvers;
			if (pmaxvers)
				maxvers = *pmaxvers;
			else
				maxvers = _maxvers(sq3);
			err = m2db_purge(sq3, maxvers, _retention_delay(sq3), NULL,
					cb, u0);
			err = sqlx_transaction_end(repctx, err);
		}
		if (!err)
			m2b_add_modified_container(m2, sq3);
		m2b_close(m2, sq3, url);
	}

	return err;
}

GError *
meta2_backend_drain_container(struct meta2_backend_s *m2, struct oio_url_s *url,
		gint64 limit, m2_onbean_cb cb, gpointer u0, gboolean *truncated)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	err = m2b_open(m2, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED
			|M2V2_OPEN_FROZEN, &sq3);
	if (!err) {
		EXTRA_ASSERT(sq3 != NULL);
		if (!(err = sqlx_transaction_begin(sq3, &repctx))) {
			gint64 sharding_state = sqlx_admin_get_i64(sq3,
					M2V2_ADMIN_SHARDING_STATE, 0);
			if (SHARDING_IN_PROGRESS(sharding_state)) {
				/* The drain uses a marker to know where it is.
				 * The sharding or shrinking will make that marker obsolete
				 * for the resulting shards. */
				err = BADREQ("Sharding is in progress");
			} else {
				err = m2db_drain_container(sq3, cb, u0, limit, truncated);
				err = sqlx_transaction_end(repctx, err);
			}
		}

		m2b_close(m2, sq3, url);
	}

	return err;
}

/* Contents --------------------------------------------------------------- */

GError*
meta2_backend_list_aliases(struct meta2_backend_s *m2b, struct oio_url_s *url,
		struct list_params_s *lp, GSList *headers,
		m2_onbean_cb cb, gpointer u0,
		void (*end_cb)(struct sqlx_sqlite3_s *sq3),
		gchar ***out_properties)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(lp != NULL);

	guint32 open_mode = lp->flag_local ? M2V2_FLAG_LOCAL: 0;
	err = m2b_open(m2b, url, _mode_readonly(open_mode), &sq3);
	if (!err) {
		/* Keep pointers to the request's parameters,
		 * because we will temporarily replace them. */
		const gchar *req_marker_start = lp->marker_start;
		const gchar *req_version_marker = lp->version_marker;
		const gchar *req_marker_end = lp->marker_end;

		/* The request has been redirected already, check if we can adapt
		 * the request's parameter to what's supposed to be in this shard. */
		if (oio_ext_is_shard_redirection()) {
			gchar *shard_lower = NULL;
			gchar *shard_upper = NULL;
			if (!sqlx_admin_has(sq3, M2V2_ADMIN_SHARDING_ROOT)) {
				err = SYSERR("Not a shard");
			}
			if (!err) {
				err = m2db_get_sharding_lower(sq3, &shard_lower);
			}
			if (!err) {
				err = m2db_get_sharding_upper(sq3, &shard_upper);
			}
			if (!err) {
				// Update the markers according to the shard range
				if (*shard_lower && (!lp->marker_start
						|| g_strcmp0(lp->marker_start, shard_lower) < 0)) {
					lp->marker_start = g_strdup(shard_lower);
					lp->version_marker = NULL;
				}
				if (*shard_upper && (!lp->marker_end
						|| g_strcmp0(lp->marker_end, shard_upper) >= 0)) {
					/* HACK: "\x01" is the (UTF-8 encoded) first unicode */
					lp->marker_end = g_strdup_printf("%s\x01", shard_upper);
				}
			}
			g_free(shard_lower);
			g_free(shard_upper);
		} else {
			/* The request has not been redirected. Build a routing key
			 * according to the request's parameters, and maybe redirect it. */
			gchar *routing_key = NULL;
			if (!(lp->prefix && *lp->prefix)
					&& !(lp->marker_start && *lp->marker_start)) {
				/* No prefix or marker, start at the beginning. */
				routing_key = g_strdup("");
			} else if (g_strcmp0(lp->prefix, lp->marker_start) > 0) {
				/* The prefix is after the marker, start at the prefix. */
				routing_key = g_strdup(lp->prefix);
			} else {
				/* HACK: build a routing key which is one character after
				 * the marker. "\x01" is the first valid unicode character. */
				routing_key = g_strdup_printf("%s\x01", lp->marker_start);
			}
			err = _redirect_to_shard(sq3, routing_key);
			g_free(routing_key);
		}
		if (!err) {
			err = m2db_list_aliases(sq3, lp, headers, cb, u0);
		}
		if (!err || err->code == CODE_REDIRECT_SHARD) {
			if (!oio_ext_is_shard_redirection() && out_properties)
				*out_properties = sqlx_admin_get_keyvalues(sq3, NULL);
		}
		if (!err) {
			if (end_cb)
				end_cb(sq3);
		}
		if (lp->marker_start != req_marker_start) {
			g_free((gchar *)lp->marker_start);
			lp->marker_start = req_marker_start;
		}
		if (lp->version_marker != req_version_marker) {
			g_free((gchar *)lp->version_marker);
			lp->version_marker = req_version_marker;
		}
		if (lp->marker_end != req_marker_end) {
			g_free((gchar *)lp->marker_end);
			lp->marker_end = req_marker_end;
		}
		m2b_close(m2b, sq3, url);
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

	err = m2b_open_for_object(m2b, url, _mode_readonly(flags), &sq3);
	if (!err) {
		err = m2db_get_alias(sq3, url, flags, cb, u0);
		m2b_close(m2b, sq3, url);
	}

	return err;
}

/* TODO(jfs): maybe is there a way to keep this in a cache */
GError*
meta2_backend_notify_container_state(struct meta2_backend_s *m2b,
		struct oio_url_s *url, gboolean recompute)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	if (!(err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY, &sq3))) {
		if (recompute) {
			struct sqlx_repctx_s *repctx = NULL;
			if (!(err = _transaction_begin(sq3, url, &repctx))) {
				m2db_recompute_container_size_and_obj_count(sq3, FALSE);
				gint64 shard_count = 0;
				m2db_get_container_shard_count(sq3, &shard_count);
				m2db_set_shard_count(sq3, shard_count);
				m2db_increment_version(sq3);
				err = sqlx_transaction_end(repctx, err);
			}
		}
		if (!err)
			m2b_add_modified_container(m2b, sq3);
		m2b_close(m2b, sq3, url);
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
	err = m2b_open_for_object(m2, url, M2V2_OPEN_MASTERONLY | M2V2_OPEN_ENABLED,
			&sq3);
	if (!err) {
		EXTRA_ASSERT(sq3 != NULL);
		if (!(err = sqlx_transaction_begin(sq3, &repctx))) {
			err = m2db_drain_content(sq3, url, cb, u0);
			err = sqlx_transaction_end(repctx, err);
		}
		m2b_close(m2, sq3, url);
	}
	return err;
}

GError*
meta2_backend_delete_alias(struct meta2_backend_s *m2b,
		struct oio_url_s *url, gboolean bypass_governance,
		gboolean create_delete_marker, gboolean dryrun,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	err = m2b_open_for_object(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED,
			&sq3);
	if (!err) {
		struct sqlx_repctx_s *repctx = NULL;
		gint64 max_versions = _maxvers(sq3);

		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (oio_ext_get_force_versioning()) {
				GRID_DEBUG("Updating max_version: %s", oio_ext_get_force_versioning());
				max_versions = atoi(oio_ext_get_force_versioning());
				m2db_set_max_versions(sq3, max_versions);
			}

			if (!(err = m2db_delete_alias(sq3, max_versions, bypass_governance,
					create_delete_marker, url, cb, u0))) {
				m2db_increment_version(sq3);
			}
			if (dryrun) {
				/* In case of dryrun, let's rollback the transaction.
				 * The deletion must not be effective */
				err = sqlx_transaction_rollback(repctx, err);
			} else {
				err = sqlx_transaction_end(repctx, err);
			}
		}
		if (!err && !dryrun) {
			m2b_add_modified_container(m2b, sq3);
		}
		m2b_close(m2b, sq3, url);
	}

	return err;
}

GError*
meta2_backend_put_alias(struct meta2_backend_s *m2b, struct oio_url_s *url,
		GSList *in, m2_onbean_cb cb_deleted, gpointer u0_deleted,
		m2_onbean_cb cb_added, gpointer u0_added)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);
	if (!in)
		return NEWERROR(CODE_BAD_REQUEST, "No bean");

	err = m2b_open_for_object(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED,
			&sq3);
	if (!err) {
		if (!oio_ext_is_shard_redirection()
				&& sqlx_admin_has(sq3, M2V2_ADMIN_SHARDING_ROOT)) {
			m2b_close(m2b, sq3, url);
			return NEWERROR(CODE_NOT_ALLOWED, "Creating an object directly on "
					"shard is not allowed. Please use the root container.");
		}
		struct m2db_put_args_s args;
		memset(&args, 0, sizeof(args));
		args.sq3 = sq3;
		args.url = url;
		args.ns_max_versions = meta2_max_versions;
		args.worm_mode = oio_ns_mode_worm && !oio_ext_is_admin();

		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (oio_ext_get_force_versioning()) {
				GRID_DEBUG("Updating max_version: %s", oio_ext_get_force_versioning());
				m2db_set_max_versions(sq3, atoi(oio_ext_get_force_versioning()));
			}
			if (!(err = m2db_put_alias(&args, in,
					cb_deleted, u0_deleted, cb_added, u0_added))) {
				m2db_increment_version(sq3);
			}
			err = sqlx_transaction_end(repctx, err);
			if (!err)
				m2b_add_modified_container(m2b, sq3);
		}
		m2b_close(m2b, sq3, url);
	}

	return err;
}

GError*
meta2_backend_change_alias_policy(struct meta2_backend_s *m2b,
		struct oio_url_s *url, GSList *in,
		m2_onbean_cb cb_deleted, gpointer u0_deleted,
		m2_onbean_cb cb_added, gpointer u0_added)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);
	if (!in)
		return NEWERROR(CODE_BAD_REQUEST, "No bean");

	err = m2b_open_for_object(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED,
			&sq3);
	if (!err) {
		if (!oio_ext_is_shard_redirection()
				&& sqlx_admin_has(sq3, M2V2_ADMIN_SHARDING_ROOT)) {
			m2b_close(m2b, sq3, url);
			return NEWERROR(CODE_NOT_ALLOWED, "Creating an object directly on "
					"shard is not allowed. Please use the root container.");
		}
		struct m2db_put_args_s args;
		memset(&args, 0, sizeof(args));
		args.sq3 = sq3;
		args.url = url;
		args.ns_max_versions = meta2_max_versions;
		args.worm_mode = oio_ns_mode_worm && !oio_ext_is_admin();

		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (!(err = m2db_change_alias_policy(&args, in,
					cb_deleted, u0_deleted, cb_added, u0_added))) {
				m2db_increment_version(sq3);
			}
			err = sqlx_transaction_end(repctx, err);
			if (!err)
				m2b_add_modified_container(m2b, sq3);
		}
		m2b_close(m2b, sq3, url);
	}

	return err;
}

GError*
meta2_backend_restore_drained(struct meta2_backend_s *m2b,
		struct oio_url_s *url, GSList *in,
		m2_onbean_cb cb_deleted, gpointer u0_deleted,
		m2_onbean_cb cb_added, gpointer u0_added)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);
	if (!in)
		return NEWERROR(CODE_BAD_REQUEST, "No bean");

	err = m2b_open_for_object(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED,
			&sq3);
	if (!err) {
		struct m2db_put_args_s args;
		memset(&args, 0, sizeof(args));
		args.sq3 = sq3;
		args.url = url;
		args.worm_mode = oio_ns_mode_worm && !oio_ext_is_admin();

		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (!(err = m2db_restore_drained(&args, in,
					cb_deleted, u0_deleted, cb_added, u0_added))) {
				m2db_increment_version(sq3);
			}
			err = sqlx_transaction_end(repctx, err);
			if (!err)
				m2b_add_modified_container(m2b, sq3);
		}
		m2b_close(m2b, sq3, url);
	}

	return err;
}

GError *
meta2_backend_update_content(struct meta2_backend_s *m2b, struct oio_url_s *url,
		GSList *in, m2_onbean_cb cb_deleted, gpointer u0_deleted,
		m2_onbean_cb cb_added, gpointer u0_added)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);
	if (!in)
		return NEWERROR(CODE_BAD_REQUEST, "No bean");
	else if (oio_ns_mode_worm && !oio_ext_is_admin())
		return NEWERROR(CODE_METHOD_NOTALLOWED,
				"NS wormed! Cannot modify object.");

	err = m2b_open_for_object(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED,
			&sq3);
	if (!err) {
		if (!oio_ext_is_shard_redirection()
				&& sqlx_admin_has(sq3, M2V2_ADMIN_SHARDING_ROOT)) {
			m2b_close(m2b, sq3, url);
			return NEWERROR(CODE_NOT_ALLOWED, "Creating an object directly on "
					"shard is not allowed. Please use the root container.");
		}
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (!(err = m2db_update_content(sq3, url, in,
					cb_deleted, u0_deleted, cb_added, u0_added))) {
				m2db_increment_version(sq3);
			}
			err = sqlx_transaction_end(repctx, err);
			if (!err)
				m2b_add_modified_container(m2b, sq3);
		}
		m2b_close(m2b, sq3, url);
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

	err = m2b_open_for_object(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED,
			&sq3);
	if (!err) {
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (!(err = m2db_truncate_content(sq3, url, truncate_size,
						out_deleted, out_added))) {
				m2db_increment_version(sq3);
			}
			err = sqlx_transaction_end(repctx, err);
			if (!err)
				m2b_add_modified_container(m2b, sq3);
		}
		m2b_close(m2b, sq3, url);
	}

	return err;
}

GError*
meta2_backend_force_alias(struct meta2_backend_s *m2b, struct oio_url_s *url,
		GSList *in, m2_onbean_cb cb_deleted, gpointer u0_deleted,
		m2_onbean_cb cb_added, gpointer u0_added)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(cb_deleted != NULL);
	EXTRA_ASSERT(cb_added != NULL);

	err = m2b_open_for_object(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED,
			&sq3);
	if (!err) {
		if (!oio_ext_is_shard_redirection()
				&& sqlx_admin_has(sq3, M2V2_ADMIN_SHARDING_ROOT)) {
			m2b_close(m2b, sq3, url);
			return NEWERROR(CODE_NOT_ALLOWED, "Creating an object directly on "
					"shard is not allowed. Please use the root container.");
		}
		struct m2db_put_args_s args;
		memset(&args, 0, sizeof(args));
		args.sq3 = sq3;
		args.url = url;
		args.ns_max_versions = meta2_max_versions;
		args.worm_mode = oio_ns_mode_worm && !oio_ext_is_admin();

		if (!(err = _transaction_begin(sq3,url, &repctx))) {
			if (!(err = m2db_force_alias(&args, in,
					cb_deleted, u0_deleted, cb_added, u0_added))) {
				m2db_increment_version(sq3);
			}
			err = sqlx_transaction_end(repctx, err);
		}
		if (!err)
			m2b_add_modified_container(m2b, sq3);

		m2b_close(m2b, sq3, url);
	}

	return err;
}

GError *
meta2_backend_purge_alias(struct meta2_backend_s *m2, struct oio_url_s *url,
	gint64 *pmaxvers, m2_onbean_cb cb, gpointer u0)
{
	GError *err;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	EXTRA_ASSERT(m2 != NULL);
	EXTRA_ASSERT(url != NULL);

	if (!oio_url_has(url, OIOURL_PATH))
		return BADREQ("Missing path");

	err = m2b_open_for_object(m2, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED,
			&sq3);
	if (!err) {
		EXTRA_ASSERT(sq3 != NULL);
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			gint64 maxvers;
			if (pmaxvers)
				maxvers = *pmaxvers;
			else
				maxvers = _maxvers(sq3);
			if (!(err = m2db_purge(sq3, maxvers, _retention_delay(sq3),
					oio_url_get(url, OIOURL_PATH), cb, u0))) {
				m2db_increment_version(sq3);
			}
			err = sqlx_transaction_end(repctx, err);
		}
		if (!err)
			m2b_add_modified_container(m2, sq3);
		m2b_close(m2, sq3, url);
	}

	return err;
}

GError*
meta2_backend_insert_beans(struct meta2_backend_s *m2b,
		struct oio_url_s *url, GSList *beans, gboolean frozen, gboolean force)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;
	int error_already = 0;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	// TODO(FVE): to migrate from old URLs to new URLs we need to try
	// with unmodified URLs first.
	m2v2_shorten_chunk_ids(beans);

	gint flags = M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED;
	if (frozen)
		flags |= M2V2_OPEN_FROZEN;
	err = m2b_open_for_object(m2b, url, flags, &sq3);
	if (!err) {
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (force)
				err = _db_save_beans_list(sq3, beans);
			else
				err = _db_insert_beans_list(sq3, beans);
			if (!err) {
				m2db_increment_version(sq3);
			} else {
				/* A constraint error is usually raised by an actual constraint
				 * violation in the DB (inside the transaction) or also by a
				 * failure of the commit hook (on the final COMMIT). */
				error_already |= (err->code == SQLITE_CONSTRAINT);
			}
			err = sqlx_transaction_end(repctx, err);
		}
		if (!err)
			m2b_add_modified_container(m2b, sq3);
		m2b_close(m2b, sq3, url);
	}

	if (error_already) {
		EXTRA_ASSERT(err != NULL);
		g_clear_error(&err);
		err = NEWERROR(CODE_CONTENT_EXISTS, "Bean already present");
	}

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

	// TODO(FVE): to migrate from old URLs to new URLs we need to try
	// with unmodified URLs first.
	m2v2_shorten_chunk_ids(beans);

	err = m2b_open_for_object(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED,
			&sq3);
	if (!err) {
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			for (; !err && beans; beans = beans->next) {
				if (unlikely(NULL == beans->data))
					continue;
				err = _db_delete_bean(sq3, beans->data);
			}
			if (!err)
				m2db_increment_version(sq3);
			err = sqlx_transaction_end(repctx, err);
		}
		m2b_close(m2b, sq3, url);
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

	// TODO(FVE): to migrate from old URLs to new URLs we need to try
	// with unmodified URLs first.
	m2v2_shorten_chunk_ids(old_chunks);
	m2v2_shorten_chunk_ids(new_chunks);

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);
	gint flags = M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED;
	if (frozen)
		flags |= M2V2_OPEN_FROZEN;
	err = m2b_open_for_object(m2b, url, flags, &sq3);
	if (!err) {
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			for (GSList *l0=old_chunks, *l1=new_chunks;
					!err && l0 && l1 ; l0=l0->next,l1=l1->next)
				err = _db_substitute_bean(sq3, l0->data, l1->data);
			if (!err)
				m2db_increment_version(sq3);
			err = sqlx_transaction_end(repctx, err);
		}
		m2b_close(m2b, sq3, url);
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
	GError *err = m2b_open_for_object(m2b, url, _mode_readonly(0), &sq3);
	if (!err) {
		err = m2db_get_alias_version(sq3, url, version);
		m2b_close(m2b, sq3, url);
	}
	return err;
}

GError*
meta2_backend_append_to_alias(struct meta2_backend_s *m2b,
		struct oio_url_s *url, GSList *beans, m2_onbean_cb cb, gpointer u0)
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

	err = m2b_open_for_object(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED,
			&sq3);
	if (!err) {
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (!(err = m2db_append_to_alias(sq3, url, beans, cb, u0))) {
				m2db_increment_version(sq3);
			}
			err = sqlx_transaction_end(repctx, err);
		}
		if (!err)
			m2b_add_modified_container(m2b, sq3);
		m2b_close(m2b, sq3, url);
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
	GError *err = m2b_open_for_object(m2b, url, _mode_readonly(flags), &sq3);
	if (!err) {
		err = m2db_get_properties(sq3, url, cb, u0);
		m2b_close(m2b, sq3, url);
	}
	return err;
}

GError*
meta2_backend_del_properties(struct meta2_backend_s *m2b,
		struct oio_url_s *url, gchar **propv, GSList **out)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	err = m2b_open_for_object(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED,
			&sq3);
	if (!err) {
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (!(err = m2db_del_properties(sq3, url, propv, out)))
				m2db_increment_version(sq3);
			err = sqlx_transaction_end(repctx, err);
		}
		m2b_close(m2b, sq3, url);
	}

	return err;
}

GError*
meta2_backend_set_properties(struct meta2_backend_s *m2b, struct oio_url_s *url,
		gboolean flush, GSList *beans, GSList **out)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	GRID_TRACE("M2 PROPSET(%s)", oio_url_get(url, OIOURL_WHOLE));
	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	err = m2b_open_for_object(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED,
			&sq3);
	if (!err) {
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (!(err = m2db_set_properties(sq3, url, flush, beans, out)))
				m2db_increment_version(sq3);
			err = sqlx_transaction_end(repctx, err);
		}
		m2b_close(m2b, sq3, url);
	}

	return err;
}


/* Beans generation --------------------------------------------------------- */

/* Create, save in cache, and possibly return m2_prepare_data.
 * If container is disabled or frozen, decache m2_prepare_data
 * and return nothing. */
static void
_meta2_backend_force_prepare_data_unlocked(struct meta2_backend_s *m2b,
		const gchar *key, struct m2_prepare_data *pdata_out,
		struct sqlx_sqlite3_s *sq3)
{

	struct m2_prepare_data *pdata = g_hash_table_lookup(
			m2b->prepare_data_cache, key);

	gint64 status = sqlx_admin_get_status(sq3);
	if (status != ADMIN_STATUS_ENABLED) {
		GRID_DEBUG("Decaching M2_PREP data for %s", key);
		g_hash_table_remove(m2b->prepare_data_cache, key);
		return;
	}
	GRID_DEBUG("Forcing M2_PREP data for %s", key);
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
 * Update the data structure allowing to answer M2_PREP requests
 * without taking the lock on the database file. If the container
 * is frozen or disabled, decache this data.
 */
static void UNUSED
_meta2_backend_force_prepare_data(struct meta2_backend_s *m2b,
		const gchar *key, struct sqlx_sqlite3_s *sq3)
{
	g_rw_lock_writer_lock(&(m2b->prepare_data_lock));
	_meta2_backend_force_prepare_data_unlocked(m2b, key, NULL, sq3);
	g_rw_lock_writer_unlock(&(m2b->prepare_data_lock));
}


GError *
meta2_backend_open_callback(struct sqlx_sqlite3_s *sq3,
		struct meta2_backend_s *m2b UNUSED, enum sqlx_open_type_e open_mode)
{
	/* beware that LOCAL is maybe == 0 */
	const gboolean _local = (SQLX_OPEN_LOCAL == (open_mode & SQLX_OPEN_REPLIMODE));
	const gboolean _create = (SQLX_OPEN_CREATE == (open_mode & SQLX_OPEN_CREATE));

	sq3->no_peers = _local;

	/* The kind of check we do depend of the kind of opening:
	 * - admin access : no check
	 * - creation : no check
	 * - local access : no check
	 * - replicated access : init done */
	if (!oio_ext_is_admin() && !_create && !_local
			&& !_is_container_initiated(sq3)) {
		return NEWERROR(CODE_CONTAINER_NOTFOUND,
				"container created but not initiated");
	}

	return NULL;
}

void
meta2_backend_close_callback(struct sqlx_sqlite3_s *sq3,
		struct meta2_backend_s *m2b)
{
	gint64 seq = 1;
	EXTRA_ASSERT(sq3 != NULL);

	if (!sq3->deleted)
		return;

	struct oio_url_s *url = oio_url_empty ();
	oio_url_set(url, OIOURL_NS, m2b->ns_name);
	NAME2CONST(n, sq3->name);

	GError *err = sqlx_name_extract(&n, url, NAME_SRVTYPE_META2, &seq);
	if (err) {
		GRID_WARN("Invalid base name [%s]: %s", sq3->name.base, err->message);
		g_clear_error(&err);
	} else {
		hc_decache_reference_service(m2b->resolver, url, NAME_SRVTYPE_META2);
	}

	/* This request handler is local, it will be called on each
	* service hosting the base. We must only signal our own
	* address; the other peers will do the same. */
	if (m2b->notifier_meta2_deleted) {
		gchar *account = sqlx_admin_get_str(sq3, SQLX_ADMIN_ACCOUNT);
		gchar *user = sqlx_admin_get_str(sq3, SQLX_ADMIN_USERNAME);
		if (!account || !user) {
			GRID_WARN("Missing "SQLX_ADMIN_ACCOUNT" or "SQLX_ADMIN_USERNAME
					" in database %s (reqid=%s)", sq3->path_inline,
					oio_ext_get_reqid());
		} else {
			oio_url_set(url, OIOURL_ACCOUNT, account);
			oio_url_set(url, OIOURL_USER, user);

			const gchar *me = meta2_backend_get_local_addr(m2b);
			GString *gs = oio_event__create_with_id(
					META2_EVENTS_PREFIX ".meta2.deleted", url,
					oio_ext_get_reqid());
			g_string_append_printf(
					gs, ",\"data\":{\"peer\":\"%s\"}}", me);
			oio_events_queue__send(
					m2b->notifier_meta2_deleted, g_string_free(gs, FALSE));
		}
		g_free(user);
		g_free(account);
	}

	oio_url_clean(url);
}

void
meta2_backend_change_callback(struct sqlx_sqlite3_s *sq3,
		struct meta2_backend_s *m2b UNUSED)
{
	gchar *account = sqlx_admin_get_str(sq3, SQLX_ADMIN_ACCOUNT);
	gchar *user = sqlx_admin_get_str(sq3, SQLX_ADMIN_USERNAME);
	if (!account || !user) {
		GRID_WARN("Missing "SQLX_ADMIN_ACCOUNT" or "SQLX_ADMIN_USERNAME
				" in database %s (reqid=%s)", sq3->path_inline,
				oio_ext_get_reqid());
	} else {
		/* There used to be a code calling _meta2_backend_force_prepare_data()
		 * here. But the "prepare data" is only used by some tests of the
		 * meta2 backend, not by production requests, thus we do not need
		 * to compute it anymore. */
	}
	g_free(user);
	g_free(account);
}

void
meta2_backend_db_properties_change_callback(struct sqlx_sqlite3_s *sq3,
		struct meta2_backend_s *m2b, struct oio_url_s *url,
		struct db_properties_s *db_properties, gboolean propagate_to_shards UNUSED)
{
	if (m2b->notifier_container_updated) {
		GString *event = oio_event__create_with_id(
				META2_EVENTS_PREFIX ".container.update", url,
				oio_ext_get_reqid());
		g_string_append_static(event, ",\"data\":{");
		db_properties_to_json(db_properties, event);
		gchar *bucket = sqlx_admin_get_str(sq3, M2V2_ADMIN_BUCKET_NAME);
		g_string_append_c(event, ',');
		oio_str_gstring_append_json_pair(event, "bucket", bucket);
		g_free(bucket);
		g_string_append_static(event, "}}");
		oio_events_queue__send(m2b->notifier_container_updated,
				g_string_free(event, FALSE));
	}

	if (!m2db_get_shard_count(sq3)) {
		return;
	}

	GPtrArray *tmp = g_ptr_array_new();

	if (db_properties_has_system_property(db_properties, SHARED_KEYS)) {
		// Share some properties with the shard
		for (gchar **shared_key=SHARED_KEYS; *shared_key; shared_key+=1) {
			gchar *value = sqlx_admin_get_str(sq3, *shared_key);
			g_ptr_array_add(tmp, g_strdup(*shared_key));
			g_ptr_array_add(tmp, value ? value : g_strdup(""));
		}
	}

	/* If <propagate_to_shards> is True, user explicitly wants to propagate
	 * the properties to the shards */
	if (propagate_to_shards) {
		tmp = db_properties_system_to_gpa(db_properties, tmp);
	}

	if (tmp->len > 0) {
		oio_ext_set_shared_properties(
				(gchar**) metautils_gpa_to_array(tmp, TRUE));
	} else {
		g_ptr_array_free(tmp, TRUE);
	}
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
		/* Prepare data is not available. Open the base, take the writer lock
		 * and check again, in case another thread did the job while we were
		 * waiting for the base or the writer lock.
		 * The base must not be frozen or disabled
		 * (we must refuse "prepare" operation in such cases). */
		err = m2b_open(m2b, url, _mode_masterslave(0)|M2V2_OPEN_ENABLED, sq3);
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

static gint
_prop_is_not_prefixed(gpointer a, gpointer b)
{
	if (DESCR(a) != &descr_struct_PROPERTIES)
		return 1;
	struct bean_PROPERTIES_s *prop = a;
	const gchar *prefix = b;
	return prefix != NULL &&
		!g_str_has_prefix(PROPERTIES_get_key(prop)->str, prefix);
}

static void
_patch_url_with_version(struct oio_url_s *url, GSList *beans)
{
	EXTRA_ASSERT(url != NULL);
	gint64 version = find_alias_version(beans);
	gchar str_version[24] = {0};
	g_snprintf(str_version, sizeof(str_version),
			"%"G_GINT64_FORMAT, version);
	oio_url_set(url, OIOURL_VERSION, str_version);
}

GError *
meta2_backend_check_content(struct meta2_backend_s *m2b, struct oio_url_s *url,
		GSList **beans, meta2_send_event_cb send_event, gboolean is_update)
{
	GError *err = NULL, *err2 = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct namespace_info_s *nsinfo = NULL;
	if (!(nsinfo = meta2_backend_get_nsinfo(m2b)))
		return NEWERROR(CODE_INTERNAL_ERROR, "NS not ready");

	struct m2v2_sorted_content_s *sorted = NULL;
	m2v2_sort_content(*beans, &sorted);
	struct checked_content_s *checked_content = NULL;
	err = m2db_check_content(sorted, nsinfo, &checked_content, is_update);
	if (send_event) {
		if (err && err->code == CODE_CONTENT_UNCOMPLETE) {
			/* Ensure the root CID is loaded so that the event emitted
			 * contains the correct CID (not the shard's). */
			err2 = m2b_open_for_object(m2b, url,
					M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
			if (err2 != NULL) {
				goto end;
			}
			m2b_close(m2b, sq3, url);
			/* Ensure there is a version in the URL used to create the
			 * event. We cannot patch the input URL because m2db_put_alias
			 * checks there is NO version in the URL. */
			struct oio_url_s *url2 = oio_url_dup(url);
			_patch_url_with_version(url2, sorted->aliases);
			GString *event = oio_event__create_with_id(
					"storage.content.broken", url2, oio_ext_get_reqid());
			g_string_append(event, ",\"data\":{");
			checked_content_append_json_string(checked_content, event);
			g_string_append(event, "}}");
			send_event(g_string_free(event, FALSE), NULL);
			oio_url_clean(url2);
		}
		if ((!err || err->code == CODE_CONTENT_UNCOMPLETE)) {
			GSList *chunk_meta = NULL;
			// Extract qualities from properties (necessary for the C Client)
			*beans = gslist_extract(*beans, &chunk_meta,
					(GCompareFunc)_prop_is_not_prefixed, OIO_CHUNK_SYSMETA_PREFIX);
			_bean_cleanl2(chunk_meta);
		}
	}

end:
	m2v2_sorted_content_free(sorted);
	if (checked_content)
		checked_content_free(checked_content);
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
	err = m2b_get_prepare_data(m2b, url, &pdata, &sq3);
	if (err)
		goto end;

	gboolean must_check_alias = m2b->flag_precheck_on_generate && (
			 VERSIONS_DISABLED(pdata.max_versions) ||
			(VERSIONS_SUSPENDED(pdata.max_versions) &&
			 oio_ns_mode_worm &&
			 !oio_ext_is_admin()));
	if (must_check_alias) {
		err = m2b_open_if_needed(m2b, url,
				_mode_masterslave(0)|M2V2_OPEN_ENABLED, &sq3);
		if (!err) {
			/* If the versioning is not supported, or the namespace is
			 * is WORM mode, we check the content is not present */
			err = check_alias_doesnt_exist2(sq3, url);
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

	m2b_close(m2b, sq3, url);

	/* Let's continue to generate the beans, no need for an open container for the moment */
	if (!err) {
		err = m2_generate_beans(url, size, oio_ns_chunk_size,
				policy, m2b->lb, cb, cb_data);
	}

end:
	namespace_info_free(nsinfo);
	storage_policy_clean(policy);
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

	err = m2b_open_for_object(m2b, url, _mode_readonly(0), &sq3);
	if (!err) {
		GVariant *params[2] = {NULL, NULL};
		params[0] = g_variant_new_string(chunk_id);
		err = CONTENTS_HEADERS_load(sq3, " id IN"
				" (SELECT DISTINCT content FROM chunks "
				"  WHERE id = ?) LIMIT 1", params, cb, u0);
		metautils_gvariant_unrefv(params);
		if (!err) {
			/* TODO follow the FK to the aliases */
		}
		m2b_close(m2b, sq3, url);
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

	err = m2b_open_for_object(m2b, url, _mode_readonly(0), &sq3);
	if (!err) {
		GVariant *params[2] = {NULL, NULL};
		params[0] = _gb_to_gvariant(h);
		err = CONTENTS_HEADERS_load(sq3, " hash = ?", params, cb, u0);
		metautils_gvariant_unrefv(params);
		if (!err) {
			/* TODO follow the FK to the aliases */
		}
		m2b_close(m2b, sq3, url);
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

	err = m2b_open_for_object(m2b, url, _mode_readonly(0), &sq3);
	if (!err) {
		GVariant *params[2] = {NULL, NULL};
		params[0] = _gb_to_gvariant(h);
		err = CONTENTS_HEADERS_load(sq3, " id = ?", params, cb, u0);
		metautils_gvariant_unrefv(params);
		if (!err) {
			/* TODO follow the FK to the aliases */
		}
		m2b_close(m2b, sq3, url);
	}

	return err;
}

/* Sharding ----------------------------------------------------------------- */

GError*
meta2_backend_find_shards_with_partition(struct meta2_backend_s *m2b,
		struct oio_url_s *url, json_object *jstrategy_params,
		m2_onbean_cb cb, gpointer u0, gchar ***out_properties)
{
	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	guint partition_len = 0;
	gdouble *partition = NULL;
	gdouble total = 0;
	gint64 threshold = 0;

	if (!jstrategy_params) {
		err = BADREQ("Missing strategy parameters");
		goto end;
	}

	struct json_object *jpartition = NULL, *jthreshold = NULL;
	struct oio_ext_json_mapping_s m[] = {
		{"partition", &jpartition, json_type_array, 1},
		{"threshold", &jthreshold, json_type_int,   0},
		{NULL, NULL, 0, 0}
	};
	err = oio_ext_extract_json(jstrategy_params, m);
	if (err) {
		err = BADREQ("Invalid strategy parameters: (%d) %s",
				err->code, err->message);
		goto end;
	}
	partition_len = json_object_array_length(jpartition);
	partition = g_malloc0(sizeof(gdouble) * partition_len);
	for (guint i = 0; i < partition_len; i++) {
		struct json_object *jitem = json_object_array_get_idx(jpartition, i);
		gdouble item = 0;

		if (json_object_is_type(jitem, json_type_int)) {
			item = json_object_get_int(jitem);
		} else if (json_object_is_type(jitem, json_type_double)) {
			item = json_object_get_double(jitem);
		} else {
			err = BADREQ("Invalid partition: expected integers or floats");
			goto end;
		}

		if (item <= 0) {
			err = BADREQ("Invalid partition: expected positive float");
			goto end;
		}
		total += item;
		partition[i] = item;
	}
	if (100 > total || total > 100) {
		err = BADREQ("Invalid partition: total must be exactly 100 (not %lf)",
				total);
		goto end;
	}
	if (jthreshold) {
		threshold = json_object_get_int64(jthreshold);
		if (threshold < 0) {
			err = BADREQ("Invalid threshold: expected positive integer");
			goto end;
		}
	}

	GError* get_shard_size(gint64 obj_count, guint index, gint64 *pshard_size) {
		if (index >= partition_len) {
			return SYSERR("Partition is too small");
		}
		gint64 shard_size = ceil(partition[index] / 100 * obj_count);
		if (shard_size <= 0)
			shard_size = 1;
		*pshard_size = shard_size;
		return NULL;
	}

	struct m2_open_args_s open_args = {
			_mode_readonly(M2V2_FLAG_MASTER)|M2V2_OPEN_URGENT,
			NULL,
			0
		};
	err = m2b_open_with_args(m2b, url, NULL, &open_args, &sq3);
	if (!err) {
		if (m2db_get_shard_count(sq3)) {
			err = BADREQ("Container is a root container");
		}
		if (!err) {
			err = m2db_find_shard_ranges(sq3,
					threshold, get_shard_size, cb, u0);
		}
		if (!err && out_properties) {
			*out_properties = sqlx_admin_get_keyvalues(sq3, NULL);
		}
		sqlx_repository_unlock_and_close_noerror(sq3);
	}
end:
	g_free(partition);
	return err;
}

GError*
meta2_backend_find_shards_with_size(struct meta2_backend_s *m2b,
		struct oio_url_s *url, json_object *jstrategy_params,
		m2_onbean_cb cb, gpointer u0, gchar ***out_properties)
{
	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	gint64 shard_size = 0;
	gint64 first_shard_size = 0;

	if (!jstrategy_params) {
		err = BADREQ("Missing strategy parameters");
		goto end;
	}

	struct json_object *jshard_size = NULL, *jfirst_shard_size = NULL;
	struct oio_ext_json_mapping_s m[] = {
		{"shard_size",       &jshard_size,       json_type_int, 1},
		{"first_shard_size", &jfirst_shard_size, json_type_int, 0},
		{NULL, NULL, 0, 0}
	};
	err = oio_ext_extract_json(jstrategy_params, m);
	if (err) {
		err = BADREQ("Invalid strategy parameters: (%d) %s",
				err->code, err->message);
		goto end;
	}
	shard_size = json_object_get_int64(jshard_size);
	if (shard_size <= 0) {
		err = BADREQ("Invalid shard size: expected strictly positive integer");
		goto end;
	}
	if (jfirst_shard_size) {
		first_shard_size = json_object_get_int64(jfirst_shard_size);
		if (first_shard_size < 0) {
			err = BADREQ("Invalid first shard size: expected positive integer");
			goto end;
		}
	}

	GError* get_shard_size(gint64 obj_count UNUSED, guint index,
			gint64 *pshard_size) {
		if (index == 0 && first_shard_size > 0) {
			*pshard_size = first_shard_size;
		} else {
			*pshard_size = shard_size;
		}
		return NULL;
	}

	struct m2_open_args_s open_args = {
			_mode_readonly(M2V2_FLAG_MASTER)|M2V2_OPEN_URGENT,
			NULL,
			0
		};
	err = m2b_open_with_args(m2b, url, NULL, &open_args, &sq3);
	if (!err) {
		if (m2db_get_shard_count(sq3)) {
			err = BADREQ("Container is a root container");
		}
		if (!err) {
			err = m2db_find_shard_ranges(sq3, 0, get_shard_size, cb, u0);
		}
		if (!err && out_properties) {
			*out_properties = sqlx_admin_get_keyvalues(sq3, NULL);
		}
		sqlx_repository_unlock_and_close_noerror(sq3);
	}
end:
	return err;
}

static GError*
_extract_sharding_indices(GSList *beans, GSList **indices, GString *indices_prop)
{
	EXTRA_ASSERT(indices != NULL);
	EXTRA_ASSERT(indices_prop != NULL);

	GError *err = NULL;
	json_object *jbody = NULL;
	struct json_object *jindex = NULL;
	struct oio_ext_json_mapping_s mapping[] = {
		{"index", &jindex, json_type_int, 1},
		{NULL,    NULL,    0,             0}
	};

	if (!beans) {
		err = BADREQ("No shard");
		goto end;
	}
	for (GSList *l = beans; l; l = l->next) {
		if (DESCR(l->data) != &descr_struct_SHARD_RANGE) {
			err = BADREQ("Invalid type: not a shard range");
			goto end;
		}
		GString *metadata = SHARD_RANGE_get_metadata(l->data);
		if (!metadata) {
			err = BADREQ("No timestamp to find the shard's copy");
			goto end;
		}
		err = JSON_parse_buffer((guint8 *) metadata->str, metadata->len, &jbody);
		if (err) {
			goto end;
		}
		err = oio_ext_extract_json(jbody, mapping);
		if (err) {
			err = BADREQ("Missing shard metadata: (%d) %s",
					err->code, err->message);
			goto end;
		}
		gchar *index = g_strdup(json_object_get_string(jindex));
		*indices = g_slist_prepend(*indices, index);
		if (indices_prop->len > 0) {
			g_string_append_c(indices_prop, ',');
		}
		g_string_append(indices_prop, index);
		if (jbody) {
			json_object_put(jbody);
			jbody = NULL;
		}
	}
end:
	if (jbody) {
		json_object_put(jbody);
	}
	return err;
}

static gboolean
_has_sharding_prefix(const gchar *k) {
	return g_str_has_prefix(k, M2V2_ADMIN_PREFIX_SHARDING);
}

GError*
meta2_backend_prepare_sharding(struct meta2_backend_s *m2b,
		struct oio_url_s *url, GSList *beans, gchar ***out_properties)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	const gchar *master = sqlx_get_service_id();
	gchar *queue_url = NULL;
	GSList *indexes = NULL;
	GString *indexes_property = g_string_sized_new(4);

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(master && *master);

	if ((err = _extract_sharding_indices(beans, &indexes, indexes_property))) {
		goto end;
	}

	gchar *cfg = oio_cfg_get_eventagent(m2b->nsinfo->name);
	if (!cfg) {
		err = SYSERR("Missing queue URL");
		goto end;
	}
	STRING_STACKIFY(cfg);
	gchar **eventagent_urls = g_strsplit(cfg, OIO_CSV_SEP2, -1);
	for (gchar **eventagent_url = eventagent_urls; *eventagent_url && !err;
			++eventagent_url) {
		if (g_str_has_prefix(*eventagent_url, BEANSTALKD_PREFIX))
			queue_url = g_strdup(*eventagent_url);
	}
	g_strfreev(eventagent_urls);
	if (!queue_url) {
		err = SYSERR("Missing beanstalkd URL");
		goto end;
	}

	struct m2_open_args_s open_args = {
			M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN|M2V2_OPEN_URGENT,
			NULL,
			0
		};
	err = m2b_open_with_args(m2b, url, NULL, &open_args, &sq3);
	if (!err) {
		gint64 timestamp = oio_ext_real_time();
		gchar *copy_path = NULL;
		struct beanstalkd_s *beanstalkd = NULL;

		if (!sqlx_admin_has(sq3, M2V2_ADMIN_SHARDING_ROOT)
				&& m2db_get_shard_count(sq3)) {
			err = BADREQ("Container is a root container");
			goto rollback;
		}

		gint64 sharding_state = sqlx_admin_get_i64(sq3,
				M2V2_ADMIN_SHARDING_STATE, 0);
		if (SHARDING_IN_PROGRESS(sharding_state)) {
			err = BADREQ("Sharding is already in progress");
			goto rollback;
		}

		if (sqlx_admin_has(sq3, M2V2_ADMIN_DRAINING_STATE)) {
			/* The drain uses a marker to know where it is.
			 * The sharding or shrinking will make that marker obsolete
			 * for the resulting shards. */
			err = BADREQ("Draining is in progress");
			goto rollback;
		}

		// Create a copy for each new shards
		for (GSList *l = indexes; l; l = l->next) {
			gchar *index = l->data;
			copy_path = g_strdup_printf(
				"%s.sharding-%"G_GINT64_FORMAT"-%s",
				sq3->path_inline, timestamp, index);
			err = metautils_syscall_copy_file(sq3->path_inline, copy_path);
			if (err) {
				g_prefix_error(&err, "Failed to copy %s to %s: ",
						sq3->path_inline, copy_path);
				g_free(copy_path);
				goto rollback;
			}
			g_free(copy_path);
		}
		err = _connect_to_sharding_queue(url, queue_url, timestamp,
				&beanstalkd);
		if (err) {
			g_prefix_error(&err, "Failed to connect to beanstalkd: ");
			goto rollback;
		}
		if (sq3->sharding_queue) {
			// Should never happen
			GRID_WARN("For sharding, a connection to beanstalkd %s "
					"was left open", sq3->sharding_queue->endpoint);
			beanstalkd_destroy(sq3->sharding_queue);
		}
		sq3->sharding_queue = beanstalkd;

		struct sqlx_repctx_s *repctx = NULL;
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			sqlx_admin_set_i64(sq3, M2V2_ADMIN_SHARDING_STATE,
					EXISTING_SHARD_STATE_SAVING_WRITES);
			sqlx_admin_set_i64(sq3, M2V2_ADMIN_SHARDING_TIMESTAMP, timestamp);
			sqlx_admin_set_str(sq3, M2V2_ADMIN_SHARDING_MASTER, master);
			sqlx_admin_set_str(sq3, M2V2_ADMIN_SHARDING_QUEUE, queue_url);
			sqlx_admin_set_str(sq3, M2V2_ADMIN_SHARDING_COPIES,
					indexes_property->str);
			m2db_increment_version(sq3);
			err = sqlx_transaction_end(repctx, err);
		}

		if (!err && out_properties) {
			*out_properties = \
					sqlx_admin_get_keyvalues(sq3, _has_sharding_prefix);
		}

rollback:
		if (err) {
			// Try to remove each copy
			for (GSList *l = indexes; l; l = l->next) {
				gchar *index = l->data;
				copy_path = g_strdup_printf(
					"%s.sharding-%"G_GINT64_FORMAT"-%s",
					sq3->path_inline, timestamp, index);
				if (remove(copy_path)) {
					GRID_WARN("Failed to remove file %s: (%d) %s", copy_path,
							errno, strerror(errno));
				}
				g_free(copy_path);
			}

			if (beanstalkd) {
				if (beanstalkd != sq3->sharding_queue) {
					// Should never happen
					GRID_WARN("For sharding, "
							"a connection to the beanstalkd was left open");
					beanstalkd_destroy(sq3->sharding_queue);
				}
				beanstalkd_destroy(beanstalkd);
				sq3->sharding_queue = NULL;
			}
		}

		sqlx_repository_unlock_and_close_noerror(sq3);
	}
end:
	g_free(queue_url);
	g_slist_free_full(indexes, g_free);
	g_string_free(indexes_property, TRUE);
	return err;
}

GError*
meta2_backend_prepare_shrinking(struct meta2_backend_s *m2b,
		struct oio_url_s *url, gchar ***out_properties)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	const gchar *master = sqlx_get_service_id();

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	if (!master || !*master) {
		return SYSERR("No service ID");
	}

	struct m2_open_args_s open_args = {
			M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN|M2V2_OPEN_URGENT,
			NULL,
			0
		};
	err = m2b_open_with_args(m2b, url, NULL, &open_args, &sq3);
	if (!err) {
		gint64 timestamp = oio_ext_real_time();

		if (!sqlx_admin_has(sq3, M2V2_ADMIN_SHARDING_ROOT)) {
			gint64 shard_count = m2db_get_shard_count(sq3);
			if (shard_count == 0) {
				err = BADREQ("Neither shard nor root");
				goto rollback;
			}
			if (shard_count != 1) {
				err = BADREQ("Root containers must only contain one shard");
				goto rollback;
			}
		}

		gint64 sharding_state = sqlx_admin_get_i64(sq3,
				M2V2_ADMIN_SHARDING_STATE, 0);
		if (SHARDING_IN_PROGRESS(sharding_state)) {
			err = BADREQ("Sharding is already in progress");
			goto rollback;
		}

		if (sqlx_admin_has(sq3, M2V2_ADMIN_DRAINING_STATE)) {
			/* The drain uses a marker to know where it is.
			 * The sharding or shrinking will make that marker obsolete
			 * for the resulting shards. */
			err = BADREQ("Draining is in progress");
			goto rollback;
		}

		struct sqlx_repctx_s *repctx = NULL;
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			sqlx_admin_set_i64(sq3, M2V2_ADMIN_SHARDING_STATE,
					EXISTING_SHARD_STATE_WAITING_MERGE);
			sqlx_admin_set_i64(sq3, M2V2_ADMIN_SHARDING_TIMESTAMP, timestamp);
			sqlx_admin_set_str(sq3, M2V2_ADMIN_SHARDING_MASTER, master);
			m2db_increment_version(sq3);
			err = sqlx_transaction_end(repctx, err);
		}

		if (!err && out_properties) {
			*out_properties = \
					sqlx_admin_get_keyvalues(sq3, _has_sharding_prefix);
		}

rollback:
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	return err;
}

static GError*
_get_shard_url_and_suffix(const gchar *namespace,
		struct bean_SHARD_RANGE_s *shard, struct oio_url_s **result_url,
		gchar **result_suffix)
{
	EXTRA_ASSERT(shard != NULL);

	GError *err = NULL;
	struct oio_url_s *url = NULL;
	json_object *jbody = NULL;
	struct json_object *jindex = NULL, *jtimestamp = NULL;

	if (result_url) {
		url = oio_url_empty();
		oio_url_set(url, OIOURL_NS, namespace);
		gchar *cid = g_string_free(metautils_gba_to_hexgstr(NULL,
				SHARD_RANGE_get_cid(shard)), FALSE);
		oio_url_set(url, OIOURL_HEXID, cid);
		g_free(cid);
	}

	if (result_suffix) {
		GString *metadata = SHARD_RANGE_get_metadata(shard);
		if (!metadata) {
			err = BADREQ("No timestamp to find the shard's copy");
			goto end;
		}
		err = JSON_parse_buffer((guint8 *) metadata->str, metadata->len, &jbody);
		if (err) {
			goto end;
		}
		struct oio_ext_json_mapping_s mapping[] = {
			{"index",     &jindex,     json_type_int, 1},
			{"timestamp", &jtimestamp, json_type_int, 1},
			{NULL,        NULL,        0,             0}
		};
		err = oio_ext_extract_json(jbody, mapping);
		if (err) {
			goto end;
		}
	}
end:
	if (err) {
		oio_url_clean(url);
	} else {
		if (result_url) {
			*result_url = url;
		}
		if (result_suffix) {
			*result_suffix = g_strdup_printf("sharding-%s-%s",
					json_object_get_string(jtimestamp),
					json_object_get_string(jindex));
		}
	}
	if (jbody) {
		json_object_put(jbody);
	}
	return err;
}

static GError*
_m2b_open_shard_local_copy(struct meta2_backend_s *m2, struct oio_url_s *url,
		const char *suffix, const char *expected_lower,
		const char *expected_upper, struct sqlx_sqlite3_s **result)
{
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(result != NULL);
	EXTRA_ASSERT(suffix != NULL);
	EXTRA_ASSERT(m2 != NULL);
	EXTRA_ASSERT(m2->repo != NULL);

	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	gchar *lower = NULL, *upper = NULL;

	struct m2_open_args_s args = {
			M2V2_OPEN_LOCAL|M2V2_OPEN_NOREFCHECK|M2V2_OPEN_URGENT,
			NULL,
			0
		};
	err = m2b_open_with_args(m2, url, suffix, &args, &sq3);
	if (err) {
		return err;
	}
	err = m2db_get_sharding_lower(sq3, &lower);
	if (err) {
		goto end;
	}
	err = m2db_get_sharding_upper(sq3, &upper);
	if (err) {
		goto end;
	}
	if (strcmp(expected_lower, lower) != 0) {
		err = BADREQ("Copy's lower mismatch");
		goto end;
	}
	if (strcmp(expected_upper, upper) != 0) {
		err = BADREQ("Copy's upper mismatch");
		goto end;
	}

end:
	if (err) {
		sqlx_repository_unlock_and_close_noerror(sq3);
	} else {
		*result = sq3;
	}
	g_free(lower);
	g_free(upper);
	return err;
}

GError*
meta2_backend_merge_sharding(struct meta2_backend_s *m2b,
		struct oio_url_s *url, GSList *beans, gboolean *truncated)
{
	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	GError *err = NULL;
	struct oio_url_s *to_merge_url = NULL;
	gchar *to_merge_suffix = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL, *to_merge_sq3 = NULL;
	gchar *shard_lower = NULL, *shard_upper = NULL;

	if (g_slist_length(beans) != 1) {
		err = BADREQ("No shard");
		goto end;
	}
	if (DESCR(beans->data) != &descr_struct_SHARD_RANGE) {
		err = BADREQ("Invalid type: not a shard range");
		goto end;
	}
	err = _get_shard_url_and_suffix(oio_url_get(url, OIOURL_NS), beans->data,
			&to_merge_url, &to_merge_suffix);
	if (err) {
		g_prefix_error(&err, "Failed to find the copy's suffix: ");
		goto end;
	}
	shard_lower = SHARD_RANGE_get_lower(beans->data)->str;
	shard_upper = SHARD_RANGE_get_upper(beans->data)->str;

	// Open the meta2 database ignoring the sharding lock
	struct m2_open_args_s open_args = {
			M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN,
			NULL,
			0
		};
	err = m2b_open_with_args(m2b, url, NULL, &open_args, &sq3);
	if (!err) {
		gint64 sharding_state = sqlx_admin_get_i64(sq3,
				M2V2_ADMIN_SHARDING_STATE, 0);
		if (sharding_state != EXISTING_SHARD_STATE_WAITING_MERGE
				&& sharding_state != EXISTING_SHARD_STATE_MERGING) {
			err = BADREQ(
					"Root container isn't ready to merge the shards "
					"(current state: %"G_GINT64_FORMAT")", sharding_state);
			goto close;
		}

		err = _m2b_open_shard_local_copy(m2b, to_merge_url, to_merge_suffix,
				shard_lower, shard_upper, &to_merge_sq3);
		if (err) {
			g_prefix_error(&err, "Failed to open the copy: ");
			goto close;
		}

		gint64 timestamp = oio_ext_real_time();
		struct sqlx_repctx_s *repctx = NULL, *to_merge_repctx = NULL;
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			err = m2db_merge_shards(sq3, to_merge_sq3, truncated);
			if (!err) {
				// Update the state
				if (*truncated) {
					sqlx_admin_set_i64(sq3, M2V2_ADMIN_SHARDING_STATE,
							EXISTING_SHARD_STATE_MERGING);
				} else {
					sqlx_admin_set_i64(sq3, M2V2_ADMIN_SHARDING_STATE,
							NEW_SHARD_STATE_APPLYING_SAVED_WRITES);
					// Clean up information that is no longer useful
					sqlx_admin_del(sq3, M2V2_ADMIN_SHARDING_MASTER);
				}
				sqlx_admin_set_i64(sq3, M2V2_ADMIN_SHARDING_TIMESTAMP,
						timestamp);
				m2db_increment_version(sq3);
			}
			err = sqlx_transaction_end(repctx, err);
			/* Commit/rollback before detaching the database toMerge,
			 * otherwise the database is locked. */
			GError *err2 = _db_execute(sq3, "DETACH DATABASE 'toMerge'",
					-1, NULL);
			if (err2) {
				GRID_WARN("Failed to detach database %s: (%d) %s",
						to_merge_sq3->path_inline, err2->code, err2->message);
				g_error_free(err2);
			}
		}
		if (err) {
			g_prefix_error(&err, "Failed to merge shards: ");
			goto close;
		}

		/* Remove the merged entries to simplify the SQL query
		   to merge the remaining entries. */
		if (!(err = _transaction_begin(to_merge_sq3, to_merge_url,
				&to_merge_repctx))) {
			if (!(err = m2db_enable_triggers(to_merge_sq3, FALSE)))
				err = m2db_remove_merged_entries(to_merge_sq3);
			if (!err)
				err = m2db_enable_triggers(to_merge_sq3, TRUE);
			err = sqlx_transaction_end(to_merge_repctx, err);
		}
		if (err) {
			g_prefix_error(&err, "Failed to remove merged entries: ");
			goto close;
		}
close:
		if (to_merge_sq3) {
			sqlx_repository_unlock_and_close_noerror(to_merge_sq3);
		}
		sqlx_repository_unlock_and_close_noerror(sq3);
	}
end:
	oio_url_clean(to_merge_url);
	g_free(to_merge_suffix);
	return err;
}

GError*
meta2_backend_update_shard(struct meta2_backend_s *m2b,
		struct oio_url_s *url, gchar **queries)
{
	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	if (!queries || !*queries)
		return BADREQ("No query");

	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	struct m2_open_args_s open_args = {
			M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN|M2V2_OPEN_URGENT,
			NULL,
			0
		};
	err = m2b_open_with_args(m2b, url, NULL, &open_args, &sq3);
	if (!err) {
		gint64 sharding_state = sqlx_admin_get_i64(sq3,
				M2V2_ADMIN_SHARDING_STATE, 0);
		if (sharding_state != NEW_SHARD_STATE_APPLYING_SAVED_WRITES) {
			err = BADREQ("Container is not a new shard");
		}
		if (!err) {
			gint64 timestamp = oio_ext_real_time();
			struct sqlx_repctx_s *repctx = NULL;
			if (!(err = _transaction_begin(sq3, url, &repctx))) {
				for (gchar **query = queries; *query; query++) {
					err = _db_execute(sq3, *query, strlen(*query), NULL);
					if (err)
						break;
				}
				if (!err) {
					sqlx_admin_set_i64(sq3, M2V2_ADMIN_SHARDING_TIMESTAMP,
							timestamp);
					m2db_increment_version(sq3);
				}
				err = sqlx_transaction_end(repctx, err);
			}
		}
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	return err;
}

static void
_m2b_delete_shard_copies(struct meta2_backend_s *m2b,
		struct oio_url_s *url, gint64 sharding_timestamp, gchar **indexes)
{
	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	if (!sharding_timestamp || !indexes) {
		return;
	}

	GError *err = NULL;
	for (gchar **index=indexes; *index; index++) {
		struct sqlx_sqlite3_s *sq3 = NULL;
		struct oio_url_s *copy_url = oio_url_dup(url);
		gchar *suffix = g_strdup_printf(
			"sharding-%"G_GINT64_FORMAT"-%s", sharding_timestamp, *index);
		/* Deleting local copies should not block the master */
		gint64 deadline = MIN(
			oio_ext_monotonic_time() + (500 * G_TIME_SPAN_MILLISECOND),
			oio_ext_get_deadline());
		struct m2_open_args_s open_args = {
				M2V2_OPEN_LOCAL|M2V2_OPEN_NOREFCHECK,
				NULL,
				deadline
			};
		err = m2b_open_with_args(m2b, copy_url, suffix, &open_args, &sq3);
		if (err) {
			GRID_WARN(
				"Failed to remove a shard copy %s: (%d) %s",
				suffix, err->code, err->message);
			g_error_free(err);
		} else {
			m2b_destroy(sq3);
		}
		oio_url_clean(copy_url);
		g_free(suffix);
	}
}

GError*
meta2_backend_lock_sharding(struct meta2_backend_s *m2b,
		struct oio_url_s *url)
{
	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	struct m2_open_args_s open_args = {
			M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN|M2V2_OPEN_URGENT,
			NULL,
			0
		};
	err = m2b_open_with_args(m2b, url, NULL, &open_args, &sq3);
	if (!err) {
		gint64 sharding_state = sqlx_admin_get_i64(sq3,
				M2V2_ADMIN_SHARDING_STATE, 0);
		if (sharding_state != EXISTING_SHARD_STATE_SAVING_WRITES) {
			err = BADREQ("Container isn't being sharded");
		}
		if (!err) {
			gint64 timestamp = oio_ext_real_time();
			gint64 sharding_timestamp = sqlx_admin_get_i64(sq3,
						M2V2_ADMIN_SHARDING_TIMESTAMP, 0);
			gchar *sharding_copies = sqlx_admin_get_str(sq3,
					M2V2_ADMIN_SHARDING_COPIES);
			gchar **indexes = NULL;
			if (sharding_copies) {
				indexes = g_strsplit(sharding_copies, ",", -1);
				g_free(sharding_copies);
			}

			struct sqlx_repctx_s *repctx = NULL;
			if (!(err = _transaction_begin(sq3, url, &repctx))) {
				sqlx_admin_set_i64(sq3, M2V2_ADMIN_SHARDING_STATE,
						EXISTING_SHARD_STATE_LOCKED);
				sqlx_admin_set_i64(sq3, M2V2_ADMIN_SHARDING_TIMESTAMP,
						timestamp);
				sqlx_admin_del(sq3, M2V2_ADMIN_SHARDING_MASTER);
				sqlx_admin_del(sq3, M2V2_ADMIN_SHARDING_QUEUE);
				sqlx_admin_del(sq3, M2V2_ADMIN_SHARDING_COPIES);
				m2db_increment_version(sq3);
				err = sqlx_transaction_end(repctx, err);
			}
			if (!err) {
				_m2b_delete_shard_copies(m2b, url, sharding_timestamp,
						indexes);
				if (sq3->sharding_queue) {
					beanstalkd_destroy(sq3->sharding_queue);
					sq3->sharding_queue = NULL;
				}
			}
			g_strfreev(indexes);
		}
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	return err;
}

GError*
meta2_backend_replace_sharding(struct meta2_backend_s *m2b,
		struct oio_url_s *url, GSList *beans)
{
	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	// Open the meta2 database ignoring the sharding lock
	struct m2_open_args_s open_args = {
			M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN|M2V2_OPEN_URGENT,
			NULL,
			0
		};
	err = m2b_open_with_args(m2b, url, NULL, &open_args, &sq3);
	if (!err) {
		if (sqlx_admin_has(sq3, M2V2_ADMIN_SHARDING_ROOT)) {
			err = BADREQ("Container is a shard");
		} else {
			gint64 sharding_state = sqlx_admin_get_i64(sq3,
					M2V2_ADMIN_SHARDING_STATE, 0);
			if (SHARDING_IN_PROGRESS(sharding_state)
					&& sharding_state != EXISTING_SHARD_STATE_LOCKED
					&& sharding_state != NEW_SHARD_STATE_APPLYING_SAVED_WRITES)
			{
				err = BADREQ(
						"Root container isn't ready to replace the shards "
						"(current state: %"G_GINT64_FORMAT")", sharding_state);
			}
		}
		if (!err) {
			gint64 timestamp = oio_ext_real_time();
			struct sqlx_repctx_s *repctx = NULL;
			if (!(err = _transaction_begin(sq3, url, &repctx))) {
				err = m2db_replace_shard_ranges(sq3, url, beans);
				if (!err) {
					// Reset these counter
					// even if the root container has not yet been cleaned.
					m2db_set_size(sq3, 0);
					m2db_set_obj_count(sq3, 0);
					sqlx_admin_set_i64(sq3, M2V2_ADMIN_SHARDING_STATE,
							EXISTING_SHARD_STATE_SHARDED);
					sqlx_admin_set_i64(sq3, M2V2_ADMIN_SHARDING_TIMESTAMP,
							timestamp);
					m2db_increment_version(sq3);
				}
				err = sqlx_transaction_end(repctx, err);
				if (!err)
					m2b_add_modified_container(m2b, sq3);
			}
		}
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	return err;
}

GError*
meta2_backend_clean_locally_sharding(struct meta2_backend_s *m2b,
		struct oio_url_s *url, GSList * beans, gboolean *truncated)
{
	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;
	gchar *suffix = NULL;
	gchar *shard_lower = NULL, *shard_upper = NULL;

	if (beans) {
		if (g_slist_length(beans) != 1) {
			err = BADREQ("No shard");
			goto end;
		}
		if (DESCR(beans->data) != &descr_struct_SHARD_RANGE) {
			err = BADREQ("Invalid type: not a shard range");
			goto end;
		}
		err = _get_shard_url_and_suffix(oio_url_get(url, OIOURL_NS),
				beans->data, NULL, &suffix);
		if (err) {
			g_prefix_error(&err, "Failed to find the copy's suffix: ");
			goto end;
		}

		shard_lower = SHARD_RANGE_get_lower(beans->data)->str;
		shard_upper = SHARD_RANGE_get_upper(beans->data)->str;
	}

	struct m2_open_args_s open_args = {
			M2V2_OPEN_LOCAL|M2V2_OPEN_NOREFCHECK,
			NULL,
			0
		};
	err = m2b_open_with_args(m2b, url, suffix, &open_args, &sq3);
	if (err) {
		goto end;
	}

	if (!suffix) {
		// It's not a local shard copy
		gint64 sharding_state = sqlx_admin_get_i64(sq3,
				M2V2_ADMIN_SHARDING_STATE, 0);
		if (!sharding_state) {
			err = BADREQ(
					"Container has never participated in a sharding operation");
			goto close;
		}
		if (SHARDING_IN_PROGRESS(sharding_state)
				&& sharding_state != NEW_SHARD_STATE_APPLYING_SAVED_WRITES
				&& sharding_state != NEW_SHARD_STATE_CLEANING_UP) {
			err = BADREQ("Container isn't ready to be cleaned "
					"(current state: %"G_GINT64_FORMAT")", sharding_state);
			goto close;
		}
	}
	err = sqlx_transaction_begin(sq3, &repctx);
	if (err) {
		goto close;
	}
	gint64 timestamp = oio_ext_real_time();
	if (suffix || sqlx_admin_has(sq3, M2V2_ADMIN_SHARDING_ROOT)) {
		// Local shard copy or shard, allow to clean until deadline (-1)
		err = m2db_clean_shard(sq3, TRUE, -1, shard_lower, shard_upper,
				truncated);
	} else if (m2db_get_shard_count(sq3)) {
		// Root, allow to clean until deadline (-1)
		err = m2db_clean_root_container(sq3, TRUE, -1, truncated);
	} else {  // Switch back to a container without shards, so recompute stats
		m2db_recompute_container_size_and_obj_count(sq3, FALSE);
		*truncated = FALSE;
	}
	if (!err) {
		if (*truncated) {
			sqlx_admin_set_i64(sq3, M2V2_ADMIN_SHARDING_STATE,
					NEW_SHARD_STATE_CLEANING_UP);
		} else {
			sqlx_admin_del(sq3, M2V2_ADMIN_SHARDING_PREVIOUS_LOWER);
			sqlx_admin_del(sq3, M2V2_ADMIN_SHARDING_PREVIOUS_UPPER);
			sqlx_admin_del(sq3, M2V2_ADMIN_SHARDING_MASTER);
			sqlx_admin_del(sq3, M2V2_ADMIN_SHARDING_QUEUE);
			sqlx_admin_del(sq3, M2V2_ADMIN_SHARDING_COPIES);
			sqlx_admin_set_i64(sq3, M2V2_ADMIN_SHARDING_STATE,
					NEW_SHARD_STATE_CLEANED_UP);
		}
		sqlx_admin_set_i64(sq3, M2V2_ADMIN_SHARDING_TIMESTAMP, timestamp);
		m2db_increment_version(sq3);
		sqlx_transaction_notify_huge_changes(repctx);
	}
	err = sqlx_transaction_end(repctx, err);

close:
	sqlx_repository_unlock_and_close_noerror(sq3);
end:
	g_free(suffix);
	return err;
}

GError*
meta2_backend_clean_sharding(struct meta2_backend_s *m2b,
		struct oio_url_s *url, gboolean urgent, gboolean *truncated)
{
	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	struct m2_open_args_s open_args = {
			M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN
			|(urgent ? M2V2_OPEN_URGENT : 0),
			NULL,
			0
		};
	err = m2b_open_with_args(m2b, url, NULL, &open_args, &sq3);
	if (err) {
		return err;
	}

	gint64 sharding_state = sqlx_admin_get_i64(sq3,
			M2V2_ADMIN_SHARDING_STATE, 0);
	if (!sharding_state) {
		err = BADREQ(
				"Container has never participated in a sharding operation");
		goto close;
	}
	if (SHARDING_IN_PROGRESS(sharding_state)
			&& sharding_state != NEW_SHARD_STATE_APPLYING_SAVED_WRITES
			&& sharding_state != NEW_SHARD_STATE_CLEANING_UP) {
		err = BADREQ("Container isn't ready to be cleaned "
				"(current state: %"G_GINT64_FORMAT")", sharding_state);
		goto close;
	}

	err = sqlx_transaction_begin(sq3, &repctx);
	if (err) {
		goto close;
	}
	gint64 timestamp = oio_ext_real_time();
	if (sqlx_admin_has(sq3, M2V2_ADMIN_SHARDING_ROOT)) {  // Shard
		err = m2db_clean_shard(sq3, FALSE, meta2_sharding_max_entries_cleaned,
				NULL, NULL, truncated);
	} else if (m2db_get_shard_count(sq3)) {  // Root
		err = m2db_clean_root_container(sq3, FALSE,
				meta2_sharding_max_entries_cleaned, truncated);
	} else {  // Switch back to a container without shards, so recompute stats
		m2db_recompute_container_size_and_obj_count(sq3, FALSE);
		*truncated = FALSE;
	}
	if (!err) {
		if (*truncated) {
			sqlx_admin_set_i64(sq3, M2V2_ADMIN_SHARDING_STATE,
					NEW_SHARD_STATE_CLEANING_UP);
		} else {
			sqlx_admin_del(sq3, M2V2_ADMIN_SHARDING_PREVIOUS_LOWER);
			sqlx_admin_del(sq3, M2V2_ADMIN_SHARDING_PREVIOUS_UPPER);
			sqlx_admin_del(sq3, M2V2_ADMIN_SHARDING_MASTER);
			sqlx_admin_del(sq3, M2V2_ADMIN_SHARDING_QUEUE);
			sqlx_admin_del(sq3, M2V2_ADMIN_SHARDING_COPIES);
			sqlx_admin_set_i64(sq3, M2V2_ADMIN_SHARDING_STATE,
					NEW_SHARD_STATE_CLEANED_UP);
		}
		sqlx_admin_set_i64(sq3, M2V2_ADMIN_SHARDING_TIMESTAMP, timestamp);
		m2db_increment_version(sq3);
	}
	err = sqlx_transaction_end(repctx, err);

close:
	if (!err && !(*truncated)) {
		m2b_add_modified_container(m2b, sq3);
	}
	sqlx_repository_unlock_and_close_noerror(sq3);
	return err;
}

GError*
meta2_backend_show_sharding(struct meta2_backend_s *m2b, struct oio_url_s *url,
		struct list_params_s *lp, m2_onbean_cb cb, gpointer u0,
		gchar ***out_properties)
{
	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(lp != NULL);

	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	guint32 open_mode = lp->flag_local ? M2V2_FLAG_LOCAL: 0;
	struct m2_open_args_s open_args = {
			_mode_readonly(open_mode),
			NULL,
			0
		};
	err = m2b_open_with_args(m2b, url, NULL, &open_args, &sq3);
	if (!err) {
		if (sqlx_admin_has(sq3, M2V2_ADMIN_SHARDING_ROOT)) {
			err = BADREQ("Container is a shard");
		}
		if (!err) {
			err = m2db_list_shard_ranges(sq3, lp, cb, u0);
		}
		if (!err && out_properties) {
			*out_properties = sqlx_admin_get_keyvalues(sq3, NULL);
		}
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	return err;
}

static GError*
_meta2_abort_sharding(struct meta2_backend_s *m2b, struct sqlx_sqlite3_s *sq3,
		struct oio_url_s *url)
{
	GError *err = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	EXTRA_ASSERT(sq3 != NULL);
	EXTRA_ASSERT(url != NULL);

	// Safety check
	const enum election_status_e election_status = sq3->election;
	if (election_status && election_status != ELECTION_LEADER) {
		return SYSERR("Not master");
	}

	gint64 sharding_state = sqlx_admin_get_i64(sq3,
			M2V2_ADMIN_SHARDING_STATE, 0);
	if (!SHARDING_IN_PROGRESS(sharding_state)) {
		return BADREQ("No sharding in progress");
	}
	if (sharding_state == NEW_SHARD_STATE_CLEANING_UP) {
		return BADREQ("Cleaning in progress");
	}

	gint64 current_timestamp = sqlx_admin_get_i64(
			sq3, M2V2_ADMIN_SHARDING_TIMESTAMP, 0);
	gchar *sharding_copies = sqlx_admin_get_str(sq3,
			M2V2_ADMIN_SHARDING_COPIES);
	gchar **indexes = NULL;
	if (sharding_copies) {
		indexes = g_strsplit(sharding_copies, ",", -1);
		g_free(sharding_copies);
	}
	gint64 new_timestamp = oio_ext_real_time();
	if (!(err = _transaction_begin(sq3, url, &repctx))) {
		if (sharding_state == NEW_SHARD_STATE_APPLYING_SAVED_WRITES) {
			gchar *previous_lower = sqlx_admin_get_str(sq3,
					M2V2_ADMIN_SHARDING_PREVIOUS_LOWER);
			if (previous_lower) {
				sqlx_admin_set_str(sq3, M2V2_ADMIN_SHARDING_LOWER,
						previous_lower);
				g_free(previous_lower);
			}
			gchar *previous_upper = sqlx_admin_get_str(sq3,
					M2V2_ADMIN_SHARDING_PREVIOUS_UPPER);
			if (previous_upper) {
				sqlx_admin_set_str(sq3, M2V2_ADMIN_SHARDING_UPPER,
						previous_upper);
				g_free(previous_upper);
			}
		}
		sqlx_admin_del(sq3, M2V2_ADMIN_SHARDING_PREVIOUS_LOWER);
		sqlx_admin_del(sq3, M2V2_ADMIN_SHARDING_PREVIOUS_UPPER);
		sqlx_admin_del(sq3, M2V2_ADMIN_SHARDING_MASTER);
		sqlx_admin_del(sq3, M2V2_ADMIN_SHARDING_QUEUE);
		sqlx_admin_del(sq3, M2V2_ADMIN_SHARDING_COPIES);
		sqlx_admin_set_i64(sq3, M2V2_ADMIN_SHARDING_STATE,
				EXISTING_SHARD_STATE_ABORTED);
		sqlx_admin_set_i64(sq3, M2V2_ADMIN_SHARDING_TIMESTAMP, new_timestamp);
		m2db_increment_version(sq3);
		err = sqlx_transaction_end(repctx, err);
	}
	if (err) {
		g_strfreev(indexes);
		return err;
	}

	if (sharding_state == EXISTING_SHARD_STATE_SAVING_WRITES) {
		sq3->save_update_queries = 0;
		g_list_free_full(sq3->transaction_update_queries, g_free);
		sq3->transaction_update_queries = NULL;
		g_list_free_full(sq3->update_queries, g_free);
		sq3->update_queries = NULL;
		if (sq3->sharding_queue) {
			beanstalkd_destroy(sq3->sharding_queue);
			sq3->sharding_queue = NULL;
		}
		_m2b_delete_shard_copies(m2b, url, current_timestamp, indexes);
	}
	g_strfreev(indexes);
	return err;
}

GError*
meta2_backend_abort_sharding(struct meta2_backend_s *m2b, struct oio_url_s *url)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	// Open the meta2 database ignoring the sharding lock
	struct m2_open_args_s open_args = {
			M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN|M2V2_OPEN_URGENT,
			NULL,
			0
		};
	err = m2b_open_with_args(m2b, url, NULL, &open_args, &sq3);
	if (!err) {
		err = _meta2_abort_sharding(m2b, sq3, url);
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	return err;
}
