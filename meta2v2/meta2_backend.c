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

#include <glib.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>

#include <sqliterepo/sqlite_utils.h>
#include <sqliterepo/sqliterepo.h>
#include <sqliterepo/election.h>

#include <meta0v2/meta0_remote.h>
#include <meta0v2/meta0_utils.h>

#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>
#include <meta2v2/meta2v2_remote.h>
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

static void
_append_url (GString *gs, struct oio_url_s *url)
{
	void _append (const char *n, const char *v) {
		if (v)
			g_string_append_printf (gs, "\"%s\":\"%s\"", n, v);
		else
			g_string_append_printf (gs, "\"%s\":null", n);
	}
	_append ("ns", oio_url_get(url, OIOURL_NS));
	g_string_append_c (gs, ',');
	_append ("account", oio_url_get(url, OIOURL_ACCOUNT));
	g_string_append_c (gs, ',');
	_append ("user", oio_url_get(url, OIOURL_USER));
	g_string_append_c (gs, ',');
	_append ("type", oio_url_get(url, OIOURL_TYPE));
	g_string_append_c (gs, ',');
	_append ("id", oio_url_get(url, OIOURL_HEXID));
}

static gint64
_quota(struct sqlx_sqlite3_s *sq3, struct meta2_backend_s *m2b)
{
	gint64 quota = 0;

	g_mutex_lock (&m2b->nsinfo_lock);
	quota = namespace_container_max_size(m2b->nsinfo);
	g_mutex_unlock (&m2b->nsinfo_lock);

	return m2db_get_quota(sq3, quota);
}

static gint64
m2b_max_versions(struct meta2_backend_s *m2b)
{
	gint64 max_versions = -1;

	g_mutex_lock (&m2b->nsinfo_lock);
	max_versions = gridcluster_get_container_max_versions(m2b->nsinfo);
	g_mutex_unlock (&m2b->nsinfo_lock);

	return max_versions;
}

static gint64
m2b_keep_deleted_delay(struct meta2_backend_s *m2b)
{
	gint64 delay = -1;

	g_mutex_lock (&m2b->nsinfo_lock);
	delay = gridcluster_get_keep_deleted_delay(m2b->nsinfo);
	g_mutex_unlock (&m2b->nsinfo_lock);

	return delay;
}

static gint64
_maxvers(struct sqlx_sqlite3_s *sq3, struct meta2_backend_s *m2b)
{
	return m2db_get_max_versions(sq3, m2b_max_versions(m2b));
}

static gint64
_retention_delay(struct sqlx_sqlite3_s *sq3, struct meta2_backend_s *m2b)
{
	return m2db_get_keep_deleted_delay(sq3, m2b_keep_deleted_delay(m2b));
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
	return sqlx_repository_get_local_addr(m2->backend.repo);
}

GError *
meta2_backend_init(struct meta2_backend_s **result,
		struct sqlx_repository_s *repo, const gchar *ns,
		struct grid_lbpool_s *glp, struct hc_resolver_s *resolver)
{
	GError *err = NULL;
	struct meta2_backend_s *m2 = NULL;
	gsize s;

	EXTRA_ASSERT(result != NULL);
	EXTRA_ASSERT(glp != NULL);
	EXTRA_ASSERT(repo != NULL);
	EXTRA_ASSERT(resolver != NULL);

	m2 = g_malloc0(sizeof(struct meta2_backend_s));
	s = metautils_strlcpy_physical_ns(m2->backend.ns_name, ns,
			sizeof(m2->backend.ns_name));
	if (sizeof(m2->backend.ns_name) <= s) {
		g_free(m2);
		return NEWERROR(CODE_BAD_REQUEST, "Namespace too long");
	}

	m2->backend.type = NAME_SRVTYPE_META2;
	m2->backend.repo = repo;
	m2->backend.lb = glp;
	m2->policies = service_update_policies_create();
	g_mutex_init(&m2->nsinfo_lock);

	m2->flag_precheck_on_generate = TRUE;

	err = sqlx_repository_configure_type(m2->backend.repo, NAME_SRVTYPE_META2,
			NULL, schema);
	if (NULL != err) {
		meta2_backend_clean(m2);
		g_prefix_error(&err, "Backend init error: ");
		return err;
	}

	m2->resolver = resolver;

	GRID_DEBUG("M2V2 backend created for NS[%s] and repo[%p]",
			m2->backend.ns_name, m2->backend.repo);

	*result = m2;
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

GError*
meta2_backend_poll_service(struct meta2_backend_s *m2,
		const gchar *type, struct service_info_s **si)
{
	struct grid_lb_iterator_s *iter;

	EXTRA_ASSERT(m2 != NULL);
	EXTRA_ASSERT(type != NULL);
	EXTRA_ASSERT(si != NULL);

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
m2b_open(struct meta2_backend_s *m2, struct oio_url_s *url,
		enum m2v2_open_type_e how, struct sqlx_sqlite3_s **result)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(result != NULL);
	EXTRA_ASSERT(m2 != NULL);
	EXTRA_ASSERT(m2->backend.repo != NULL);

	/* TODO */
	gboolean no_peers = FALSE;
	if (no_peers) {
		how &= ~M2V2_OPEN_REPLIMODE;
		how |= M2V2_OPEN_LOCAL|M2V2_OPEN_NOREFCHECK;
	}

	struct sqlx_name_mutable_s n;
	sqlx_name_fill (&n, url, NAME_SRVTYPE_META2, 1);
	err = sqlx_repository_open_and_lock(m2->backend.repo,
			sqlx_name_mutable_to_const(&n), m2_to_sqlx(how), &sq3, NULL);
	sqlx_name_clean (&n);

	if (NULL != err) {
		if (err->code == CODE_CONTAINER_NOTFOUND)
			err->domain = GQ();
		return err;
	}

	sq3->no_peers = how & (M2V2_OPEN_LOCAL|M2V2_OPEN_NOREFCHECK);

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
meta2_backend_has_master_container(struct meta2_backend_s *m2,
		struct oio_url_s *url)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	GRID_DEBUG("HAS(%s)", oio_url_get(url, OIOURL_WHOLE));
	err = m2b_open(m2, url, M2V2_OPEN_MASTERONLY
			|M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN, &sq3);
	if (sq3) {
		sqlx_repository_unlock_and_close_noerror(sq3);
	}
	return err;
}

GError *
meta2_backend_has_container(struct meta2_backend_s *m2,
		struct oio_url_s *url)
{
	GError *err = NULL;

	EXTRA_ASSERT(m2 != NULL);
	EXTRA_ASSERT(url != NULL);
	GRID_DEBUG("HAS(%s)", oio_url_get(url, OIOURL_WHOLE));

	struct sqlx_name_mutable_s n;
	sqlx_name_fill (&n, url, NAME_SRVTYPE_META2, 1);
	err = sqlx_repository_has_base(m2->backend.repo, sqlx_name_mutable_to_const(&n));
	sqlx_name_clean (&n);

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

GError*
meta2_backend_get_max_versions(struct meta2_backend_s *m2b,
		struct oio_url_s *url, gint64 *result)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(result != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERSLAVE
			|M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN, &sq3);
	if (!err) {
		*result = _maxvers(sq3, m2b);
		m2b_close(sq3);
	}

	return err;
}

static GError *
_create_container_init_phase(struct sqlx_sqlite3_s *sq3,
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
	enum m2v2_open_type_e open_mode = 0;
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
			if (!params->local && sq3->election == ELECTION_LEADER && m2->notify.hook) {
				GString *gs = g_string_new ("{");
				g_string_append (gs, "\"event\":\""NAME_SRVTYPE_META2".container.create\"");
				g_string_append_printf (gs, ",\"when\":%"G_GINT64_FORMAT, oio_ext_real_time());
				g_string_append (gs, ",\"data\":{");
				g_string_append (gs, "\"url\":{");
				_append_url (gs, url);
				g_string_append (gs, "}}}");
				m2->notify.hook (m2->notify.udata, g_string_free (gs, FALSE));
			}
		}
		m2b_close(sq3);
	}
	return err;
}

GError *
meta2_backend_destroy_container(struct meta2_backend_s *m2,
		struct oio_url_s *url, guint32 flags)
{
	GError *err = NULL;
	gboolean local = flags & M2V2_DESTROY_LOCAL;
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

	GRID_DEBUG("DESTROY(%s)%s", oio_url_get(url, OIOURL_WHOLE),
			local? " (local)" : "");
	err = m2b_open(m2, url, local? M2V2_OPEN_LOCAL : M2V2_OPEN_MASTERONLY,
			&sq3);
	if (!err) {
		EXTRA_ASSERT(sq3 != NULL);

		// Performs checks only if client did not ask for a local destroy
		if (!local) { do {
			err = m2db_list_aliases(sq3, &lp, NULL, counter_cb, NULL);
			if (err)
				break;

			if (counter > 0 && !(flags & (M2V2_DESTROY_FORCE|M2V2_DESTROY_FLUSH))) {
				err = NEWERROR(CODE_CONTAINER_NOTEMPTY,
						"%d elements still in container", counter);
				break;
			}

			if (counter > 0 && flags & M2V2_DESTROY_FLUSH) {
				err = m2db_flush_container(sq3->db);
				if (err != NULL) {
					GRID_WARN("Error flushing container: %s", err->message);
					g_clear_error(&err);
				}
			}

			gchar **peers = NULL;
			struct sqlx_name_mutable_s n;
			sqlx_name_fill (&n, url, NAME_SRVTYPE_META2, 1);
			err = sqlx_config_get_peers(election_manager_get_config(
						sqlx_repository_get_elections_manager(m2->backend.repo)),
					sqlx_name_mutable_to_const(&n), &peers);
			sqlx_name_clean (&n);

			// peers may be NULL if no zookeeper URL is configured
			if (!err && peers != NULL && g_strv_length(peers) > 0)
				err = m2v2_remote_execute_DESTROY_many(peers, url, flags);
			if (peers)
				g_strfreev(peers);
			peers = NULL;
		} while (0); }

		hc_decache_reference_service(m2->resolver, url, NAME_SRVTYPE_META2);
		if (!err) {
			GString *gs = g_string_new ("{");
			g_string_append (gs, "\"event\":\"" NAME_SRVTYPE_META2 ".container.destroy\"");
			g_string_append_printf (gs, ",\"when\":%"G_GINT64_FORMAT, oio_ext_real_time());
			g_string_append (gs, ",\"data\":{");
			g_string_append (gs, "\"url\":{");
			_append_url (gs, url);
			g_string_append (gs, "}}}");
			int master = sq3->election == ELECTION_LEADER;
			m2b_destroy(sq3);
			if (!local && master && m2->notify.hook)
				m2->notify.hook (m2->notify.udata, g_string_free (gs, FALSE));
			else
				g_string_free (gs, TRUE);
		} else {
			m2b_close(sq3);
		}
	}

	return err;
}

GError *
meta2_backend_flush_container(struct meta2_backend_s *m2,
		struct oio_url_s *url)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	err = m2b_open(m2, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		EXTRA_ASSERT(sq3 != NULL);
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
		struct oio_url_s *url, guint32 flags, m2_onbean_cb cb, gpointer u0)
{
	GError *err;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	err = m2b_open(m2, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		EXTRA_ASSERT(sq3 != NULL);
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
meta2_backend_list_aliases(struct meta2_backend_s *m2b, struct oio_url_s *url,
		struct list_params_s *lp, GSList *headers,
		m2_onbean_cb cb, gpointer u0, gchar ***out_properties)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(lp != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERSLAVE
			|M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN, &sq3);
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

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERSLAVE
			|M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN, &sq3);
	if (!err) {
		err = m2db_get_alias(sq3, url, flags, cb, u0);
		m2b_close(sq3);
	}

	return err;
}

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
		if (v)
			g_string_append_printf (gs, "\"%s\":\"%s\"", k, v);
		else
			g_string_append_printf (gs, "\"%s\":null", k);
	}
	void append (GString *gs, const char *k, gchar *v) {
		append_const (gs, k, v);
		g_free0 (v);
	}

	GString *gs = g_string_new("{");
	append_const (gs, "event", NAME_SRVTYPE_META2 ".container.state");
	append_int64 (gs, "when", oio_ext_real_time());
	g_string_append (gs, ",\"url\":{");
	append (gs, "ns", sqlx_admin_get_str(sq3, SQLX_ADMIN_NAMESPACE));
	append (gs, "account", sqlx_admin_get_str(sq3, SQLX_ADMIN_ACCOUNT));
	append (gs, "user", sqlx_admin_get_str(sq3, SQLX_ADMIN_USERNAME));
	append_const (gs, "type", sq3->name.type);
	g_string_append (gs, "}, \"data\":{");

	append_const (gs, "policy", sqlx_admin_get_str(sq3, M2V2_ADMIN_STORAGE_POLICY));
	append_int64 (gs, "ctime", m2db_get_ctime(sq3));
	append_int64 (gs, "bytes-count", m2db_get_size(sq3));
	append_int64 (gs, "object-count", 0);
	g_string_append (gs, "}}");

	return g_string_free(gs, FALSE);
}

static void
meta2_backend_add_modified_container(struct meta2_backend_s *m2b,
		struct sqlx_sqlite3_s *sq3)
{
	EXTRA_ASSERT(m2b != NULL);
	if (m2b->notify.hook)
		m2b->notify.hook(m2b->notify.udata, _container_state (sq3));
}

GError*
meta2_backend_refresh_container_size(struct meta2_backend_s *m2b,
		struct oio_url_s *url, gboolean bRecalc)
{
    GError *err = NULL;
    struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	if (!(err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY, &sq3))) {
		if (bRecalc)
			m2db_set_size(sq3, m2db_get_container_size(sq3->db, FALSE));
		meta2_backend_add_modified_container(m2b, sq3);
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
	gint64 max_versions;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		struct sqlx_repctx_s *repctx = NULL;
		max_versions = _maxvers(sq3, m2b);
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (!(err = m2db_delete_alias(sq3, max_versions, url, cb, u0))) {
				m2db_increment_version(sq3);
			}
			err = sqlx_transaction_end(repctx, err);
		}
		if (!err)
			meta2_backend_add_modified_container(m2b, sq3);
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
		args.max_versions = _maxvers(sq3, m2b);
		args.nsinfo = meta2_backend_get_nsinfo(m2b);
		args.lbpool = m2b->backend.lb;

		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (!(err = m2db_put_alias(&args, in, out_deleted, out_added)))
				m2db_increment_version(sq3);
			err = sqlx_transaction_end(repctx, err);
			if (!err)
				meta2_backend_add_modified_container(m2b, sq3);
		}
		m2b_close(sq3);

		namespace_info_free(args.nsinfo);
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
		args.max_versions = _maxvers(sq3, m2b);
		args.nsinfo = meta2_backend_get_nsinfo(m2b);
		args.lbpool = m2b->backend.lb;

		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (!(err = m2db_copy_alias(&args, src)))
				m2db_increment_version(sq3);
			err = sqlx_transaction_end(repctx, err);
		}
		m2b_close(sq3);

		namespace_info_free(args.nsinfo);
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
		args.max_versions = _maxvers(sq3, m2b);
		args.nsinfo = meta2_backend_get_nsinfo(m2b);
		args.lbpool = m2b->backend.lb;

		if (!(err = _transaction_begin(sq3,url, &repctx))) {
			if (!(err = m2db_force_alias(&args, in, out_deleted, out_added)))
				m2db_increment_version(sq3);
			err = sqlx_transaction_end(repctx, err);
		}
		if (!err)
			meta2_backend_add_modified_container(m2b, sq3);
		namespace_info_free(args.nsinfo);

		m2b_close(sq3);
	}

	return err;
}

GError*
meta2_backend_insert_beans(struct meta2_backend_s *m2b,
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

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

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
							"UPDATE chunks SET id = '%s' WHERE id = '%s'",
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

GError*
meta2_backend_get_alias_version(struct meta2_backend_s *m2b,
		struct oio_url_s *url, gint64 *version)
{
	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

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
		struct oio_url_s *url, GSList *beans,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;
	struct namespace_info_s *nsinfo = NULL;
	gint64 max_versions;

	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);
	if (!beans)
		return NEWERROR(CODE_BAD_REQUEST, "No bean");
	if (!(nsinfo = meta2_backend_get_nsinfo (m2b)))
		return NEWERROR(CODE_INTERNAL_ERROR, "NS not ready");

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		max_versions = _maxvers(sq3, m2b);
		if (!(err = _transaction_begin(sq3, url, &repctx))) {
			if (!(err = m2db_append_to_alias(sq3, nsinfo, max_versions, url, beans, cb, u0)))
				m2db_increment_version(sq3);
			err = sqlx_transaction_end(repctx, err);
		}
		if (!err)
			meta2_backend_add_modified_container(m2b, sq3);
		m2b_close(sq3);
	}

	namespace_info_free (nsinfo);
	return err;
}

GError*
meta2_backend_get_properties(struct meta2_backend_s *m2b,
		struct oio_url_s *url, m2_onbean_cb cb, gpointer u0)
{
	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

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
meta2_backend_deduplicate_contents(struct meta2_backend_s *m2b,
		struct oio_url_s *url, guint32 flags, GString **status_message)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;
	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERONLY|M2V2_OPEN_ENABLED, &sq3);
	if (!err) {
		GRID_INFO("Starting content deduplication on %s",
				oio_url_get(url, OIOURL_WHOLE));
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

GError*
meta2_backend_generate_beans(struct meta2_backend_s *m2b,
		struct oio_url_s *url, gint64 size, const gchar *polname, gboolean append, 
		m2_onbean_cb cb, gpointer cb_data)
{
	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = NULL;
	struct namespace_info_s *nsinfo;
	struct storage_policy_s *policy = NULL;
	struct grid_lb_iterator_s *iter = NULL;

	GRID_TRACE("BEANS(%s,%"G_GINT64_FORMAT",%s)", oio_url_get(url, OIOURL_WHOLE),
			size, polname);
	EXTRA_ASSERT(m2b != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(cb != NULL);

	if (!(nsinfo = meta2_backend_get_nsinfo(m2b)))
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
							"not found", oio_url_get(url, OIOURL_PATH));
				}
			}
		}

		/* Now check the storage policy */
		if (!err) {
			if (polname) {
				if (!(policy = storage_policy_init(nsinfo, polname)))
					err = NEWERROR(CODE_POLICY_NOT_SUPPORTED,
							"Invalid policy [%s]", polname);
			} else {
				err = m2db_get_storage_policy(sq3, url, nsinfo, append, &policy);
				if (err || !policy) {
					gchar *def = namespace_storage_policy(nsinfo, oio_url_get(url, OIOURL_NS));
					if (NULL != def) {
						if (!(policy = storage_policy_init(nsinfo, def)))
							err = NEWERROR(CODE_POLICY_NOT_SUPPORTED, "Invalid policy [%s]", def);
						g_free(def);
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
			err = m2_generate_beans(url, size,
					namespace_chunk_size(nsinfo, oio_url_get(url, OIOURL_NS)),
					policy, iter, cb, cb_data);
	}

	namespace_info_free(nsinfo);
	storage_policy_clean(policy);
	return err;
}

// TODO FIXME too many arguments
// TODO 'url' seems only useful for logging purposes
GError*
meta2_backend_get_conditionned_spare_chunks(struct meta2_backend_s *m2b,
		struct oio_url_s *url, gint64 count, gint64 dist, const char *notin,
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
			oio_url_get(url, OIOURL_WHOLE),
			count,
			dist,
			notin,
			broken);

	notin2 = srvinfo_from_piped_chunkid(notin);
	broken2 = srvinfo_from_piped_chunkid(broken);

	// FIXME: storage class should come as parameter
	stgpol = storage_policy_init(m2b->nsinfo, NULL);

	err = get_conditioned_spare_chunks(m2b->backend.lb, count, dist,
			storage_policy_get_storage_class(stgpol), notin2, broken2, result,
			answer_beans);

	g_slist_free_full(notin2, (GDestroyNotify) service_info_gclean);
	g_slist_free_full(broken2, (GDestroyNotify) service_info_gclean);
	storage_policy_clean(stgpol);

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
				gchar *def = namespace_storage_policy(nsinfo, oio_url_get(url, OIOURL_NS));
				if (NULL != def) {
					if (!(*pol = storage_policy_init(nsinfo, def)))
						err = NEWERROR(CODE_POLICY_NOT_SUPPORTED,
								"Invalid policy [%s]", def);
					g_free(def);
				}
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
meta2_backend_get_spare_chunks(struct meta2_backend_s *m2b, struct oio_url_s *url,
		const char *polname, GSList **result, gboolean use_beans)
{
	struct storage_policy_s *pol = NULL;
	GError *err = NULL;

	GRID_TRACE("SPARE(%s,%s)", oio_url_get(url, OIOURL_WHOLE), polname);
	EXTRA_ASSERT(m2b != NULL);

	err = _load_storage_policy(m2b, url, polname, &pol);

	if (!err) {
		err = get_spare_chunks(m2b->backend.lb, pol, result, use_beans);
	}

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

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERSLAVE|
			M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN, &sq3);
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

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERSLAVE|
			M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN, &sq3);
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

	err = m2b_open(m2b, url, M2V2_OPEN_MASTERSLAVE|
			M2V2_OPEN_ENABLED|M2V2_OPEN_FROZEN, &sq3);
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

