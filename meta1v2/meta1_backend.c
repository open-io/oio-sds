#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.meta1.backend"
#endif

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include <sqlite3.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <sqliterepo/sqliterepo.h>
#include <meta2/remote/meta2_remote.h>

#include "./internals.h"
#include "./internals_sqlite.h"
#include "./meta1_prefixes.h"
#include "./meta1_backend.h"
#include "./meta1_backend_internals.h"

struct meta1_backend_s *
meta1_backend_init(const gchar *ns, struct sqlx_repository_s *repo,
		struct grid_lbpool_s *glp)
{
	struct meta1_backend_s *m1;

	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(*ns != '\0');
	EXTRA_ASSERT(glp != NULL);
	EXTRA_ASSERT(repo != NULL);

	m1 = g_malloc0(sizeof(*m1));
	metautils_strlcpy_physical_ns(m1->ns_name, ns, sizeof(m1->ns_name));
	g_static_rw_lock_init(&m1->rwlock_ns_policies);
	m1->lb = glp;
	m1->repository = repo;
	m1->prefixes = meta1_prefixes_init();
	m1->ns_policies = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, (GDestroyNotify) service_update_policies_destroy);

	return m1;
}

void
meta1_backend_clean(struct meta1_backend_s *m1)
{
	if (!m1)
		return;

	if (m1->prefixes) {
		meta1_prefixes_clean(m1->prefixes);
	}

	if (m1->ns_policies) {
		g_hash_table_destroy(m1->ns_policies);
	}

	g_static_rw_lock_free(&m1->rwlock_ns_policies);
	memset(m1, 0, sizeof(*m1));
	g_free(m1);
}

struct service_update_policies_s*
meta1_backend_get_svcupdate(struct meta1_backend_s *m1, const char *ns_name)
{
	struct service_update_policies_s* pol;

	if(!m1)
		return NULL;
	g_static_rw_lock_writer_lock(&m1->rwlock_ns_policies);
	if(!(pol = g_hash_table_lookup(m1->ns_policies, ns_name))) {
		/* lazy init */
		pol = service_update_policies_create();
		g_hash_table_insert(m1->ns_policies, g_strdup(ns_name), pol);
	}
	g_static_rw_lock_writer_unlock(&m1->rwlock_ns_policies);
	return pol;
}

struct meta1_prefixes_set_s*
meta1_backend_get_prefixes(struct meta1_backend_s *m1)
{
	EXTRA_ASSERT(m1 != NULL);
	return m1->prefixes;
}

GError*
meta1_backend_open_base(struct meta1_backend_s *m1, const container_id_t cid,
		enum m1v2_open_type_e how, struct sqlx_sqlite3_s **sq3)
{
	return _open_and_lock(m1, cid, how, sq3);
}

gboolean
meta1_backend_base_already_created(struct meta1_backend_s *m1, const guint8 *prefix)
{
	gchar base[5] = {0,0,0,0,0};
	GError *err;

	g_snprintf(base, sizeof(base), "%02X%02X", prefix[0], prefix[1]);
	err = sqlx_repository_has_base(m1->repository, META1_TYPE_NAME, base);
	if (!err)
		return TRUE;
	g_clear_error(&err);
	return FALSE;
}

gchar *
meta1_backend_get_ns_name(const struct meta1_backend_s *m1)
{
	return g_strdup(m1->ns_name);
}

