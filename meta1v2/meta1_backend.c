/*
OpenIO SDS meta1v2
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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include <sqlite3.h>

#include <metautils/lib/metautils.h>
#include <sqliterepo/sqliterepo.h>
#include <sqliterepo/election.h>

#include "./internals.h"
#include "./meta1_prefixes.h"
#include "./meta1_backend.h"
#include "./meta1_backend_internals.h"

GError *
meta1_backend_init(struct meta1_backend_s **out, const char *ns,
		struct sqlx_repository_s *repo, struct grid_lbpool_s *glp)
{
	EXTRA_ASSERT(out != NULL);
	EXTRA_ASSERT(repo != NULL);
	EXTRA_ASSERT(glp != NULL);

	if (!*ns || strlen(ns) >= LIMIT_LENGTH_NSNAME)
		return BADREQ("Invalid namespace name");

	struct meta1_backend_s *m1 = g_malloc0(sizeof(*m1));
	g_strlcpy (m1->ns_name, ns, sizeof(m1->ns_name));
	m1->type = NAME_SRVTYPE_META1;
	m1->lb = glp;
	m1->repo = repo;
	m1->prefixes = meta1_prefixes_init();
	m1->svcupdate = service_update_policies_create();
	*out = m1;
	return NULL;
}

void
meta1_backend_clean(struct meta1_backend_s *m1)
{
	if (!m1)
		return;

	if (m1->prefixes) {
		meta1_prefixes_clean(m1->prefixes);
		m1->prefixes = NULL;
	}

	if (m1->svcupdate) {
		service_update_policies_destroy (m1->svcupdate);
		m1->svcupdate = NULL;
	}

	memset(m1, 0, sizeof(*m1));
	g_free(m1);
}

struct service_update_policies_s*
meta1_backend_get_svcupdate(struct meta1_backend_s *m1)
{
	EXTRA_ASSERT(m1 != NULL);
	return m1 ? m1->svcupdate : NULL;
}

struct meta1_prefixes_set_s*
meta1_backend_get_prefixes(struct meta1_backend_s *m1)
{
	EXTRA_ASSERT(m1 != NULL);
	return m1 ? m1->prefixes : NULL;
}

GError*
meta1_backend_open_base(struct meta1_backend_s *m1, struct oio_url_s *url,
		enum m1v2_open_type_e how, struct sqlx_sqlite3_s **sq3)
{
	return _open_and_lock(m1, url, how, sq3);
}

gboolean
meta1_backend_base_already_created(struct meta1_backend_s *m1, const guint8 *prefix)
{
	gchar base[5] = {0,0,0,0,0};
	GError *err = NULL;

	g_snprintf(base, sizeof(base), "%02X%02X", prefix[0], prefix[1]);
	struct sqlx_name_s n = {.base=base, .type=NAME_SRVTYPE_META1, .ns=m1->ns_name};
	err = sqlx_repository_has_base(m1->repo, &n);
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

const gchar*
meta1_backend_get_local_addr(struct meta1_backend_s *m1)
{
	return sqlx_repository_get_local_addr(m1->repo);
}

