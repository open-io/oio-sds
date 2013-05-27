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

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.meta1.backend"
#endif

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include <glib.h>
#include <sqlite3.h>

#include "../metautils/lib/metacomm.h"
#include "../metautils/lib/resolv.h"
#include "../metautils/lib/lb.h"
#include "../metautils/lib/svc_policy.h"
#include "../sqliterepo/sqliterepo.h"

#include "./internals.h"
#include "./internals_sqlite.h"
#include "./meta1_prefixes.h"
#include "./meta1_backend.h"
#include "./meta1_backend_internals.h"

#include <meta2_remote.h>

GError *
meta1_backend_init(struct meta1_backend_s **result,
		const gchar *ns_name, const gchar *id, const gchar *basedir)
{
	GError *err = NULL;
	struct sqlx_repo_config_s cfg;
	struct meta1_backend_s *m1;

	if (!m1b_gquark_log)
		m1b_gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	META1_ASSERT(ns_name != NULL);
	META1_ASSERT(*ns_name != '\0');

	m1 = g_malloc0(sizeof(*m1));
	META1_ASSERT(m1 != NULL);

	m1->tree_lb = g_tree_new_full(hashstr_quick_cmpdata, NULL, g_free, NULL);
	META1_ASSERT(m1->tree_lb != NULL);

	m1->lock = g_mutex_new();
	META1_ASSERT(m1->lock != NULL);

	m1->prefixes = meta1_prefixes_init();
	META1_ASSERT(m1->prefixes != NULL);

	g_strlcpy(m1->ns_name, ns_name, sizeof(m1->ns_name)-1);

	m1->policies = service_update_policies_create();

	cfg.flags = SQLX_REPO_AUTOCREATE;
	cfg.lock.ns = ns_name;
	cfg.lock.type = META1_TYPE_NAME;
	cfg.lock.srv = id;
	err = sqlx_repository_init(basedir, &cfg, &(m1->repository));

	if (NULL != err) {
		g_prefix_error(&err, "sqlx error: ");
		meta1_backend_clean(m1);
		return err;
	}

	err = sqlx_repository_configure_type(m1->repository,
			META1_TYPE_NAME, NULL, META1_SCHEMA);
	if (err != NULL) {
		g_prefix_error(&err, "sqlx schema error: ");
		meta1_backend_clean(m1);
		return err;
	}

	*result = m1;
	return NULL;
}

void
meta1_backend_clean(struct meta1_backend_s *m1)
{
	if (!m1)
		return;

	if (m1->lock) {
		g_mutex_lock(m1->lock);
		g_mutex_unlock(m1->lock);
		g_mutex_free(m1->lock);
	}

	if (m1->repository) {
		sqlx_repository_clean(m1->repository);
	}

	if (m1->tree_lb) {
		g_tree_destroy(m1->tree_lb);
	}

	if (m1->prefixes) {
		meta1_prefixes_clean(m1->prefixes);
	}

	if (m1->policies) {
		service_update_policies_destroy(m1->policies);
	}

	memset(m1, 0, sizeof(*m1));
	g_free(m1);
}

struct sqlx_repository_s*
meta1_backend_get_repository(struct meta1_backend_s *m1)
{
	return m1 ? m1->repository : NULL;
}

struct service_update_policies_s*
meta1_backend_get_svcupdate(struct meta1_backend_s *m1)
{
	return m1 ? m1->policies : NULL;
}

void
meta1_configure_type(struct meta1_backend_s *m1,
		const gchar *type, struct grid_lb_iterator_s *iter)
{
	hashstr_t *htype;

	if (!m1 || !m1->tree_lb)
		return ;

	htype = hashstr_create(type);

	g_mutex_lock(m1->lock);
	if (iter)
		g_tree_insert(m1->tree_lb, htype, iter);
	else {
		g_tree_remove(m1->tree_lb, htype);
		g_free(htype);
	}
	g_mutex_unlock(m1->lock);
}

struct meta1_prefixes_set_s*
meta1_backend_get_prefixes(struct meta1_backend_s *m1)
{
	META1_ASSERT(m1 != NULL);
	return m1->prefixes;
}

GError*
meta1_backend_open_base(struct meta1_backend_s *m1, const container_id_t cid,
		enum m1v2_open_type_e how, struct sqlx_sqlite3_s **sq3)
{
	return _open_and_lock(m1, cid, how, sq3);
}


