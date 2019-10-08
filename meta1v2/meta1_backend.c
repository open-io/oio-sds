/*
OpenIO SDS meta1v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS

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

#include <core/oiocfg.h>
#include <metautils/lib/metautils.h>
#include <metautils/lib/common_variables.h>
#include <sqliterepo/sqliterepo.h>
#include <sqliterepo/election.h>
#include <events/events_variables.h>

#include "./internals.h"
#include "./meta1_prefixes.h"
#include "./meta1_backend.h"
#include "./meta1_backend_internals.h"

const char * meta1_backend_basename(struct meta1_backend_s *m1,
		const guint8 *bin, gchar *dst, gsize len)
{
	oio_str_bin2hex(bin, 2, dst, len);

	guint nb_digits = MIN(m1->nb_digits, 4);
	g_assert(m1->nb_digits == nb_digits);
	for (guint i=nb_digits; i<4 ;i++)
		dst[i] = '0';

	return dst;
}

static GError *
_init_notifiers(struct meta1_backend_s *m1, const char *ns)
{
#define INIT(Out,Tube) if (!err) { \
	err = oio_events_queue_factory__create(url, (Tube), &(Out)); \
	g_assert((err != NULL) ^ ((Out) != NULL)); \
	if (!err) { \
		err = oio_events_queue__start((Out)); \
	} \
}
	gchar *url = oio_cfg_get_eventagent (ns);
	if (!url)
		return NULL;
	STRING_STACKIFY(url);

	GError *err = NULL;
	INIT(m1->notifier_srv, oio_meta1_tube_services);
	INIT(m1->notifier_ref, oio_meta1_tube_references);
	return err;
}

GError *
meta1_backend_init(struct meta1_backend_s **result,
		struct sqlx_repository_s *repo, const char *ns,
		struct oio_lb_s *lb)
{
	EXTRA_ASSERT(result != NULL);
	EXTRA_ASSERT(repo != NULL);
	EXTRA_ASSERT(lb != NULL);

	if (!*ns || strlen(ns) >= LIMIT_LENGTH_NSNAME)
		return BADREQ("Invalid namespace name");

	if (oio_ns_meta1_digits > 4)
		return ERRPTF("Misconfigured number of meta1 digits: "
				"out of range [0,4]");

	struct meta1_backend_s *m1 = g_malloc0(sizeof(*m1));
	g_strlcpy (m1->ns_name, ns, sizeof(m1->ns_name));
	m1->type = NAME_SRVTYPE_META1;
	m1->lb = lb;
	m1->repo = repo;
	m1->prefixes = meta1_prefixes_init();
	m1->svcupdate = service_update_policies_create();
	m1->nb_digits = oio_ns_meta1_digits;

	GError *err;

	err = _init_notifiers(m1, ns);
	if (err) {
		GRID_WARN("Events queue startup failed: (%d) %s",
				err->code, err->message);
		goto exit;
	}

	*result = m1;

	GRID_DEBUG("M1V2 backend created for NS[%s] and repo[%p]",
			m1->ns_name, m1->repo);
	return NULL;
exit:
	meta1_backend_clean(m1);
	g_prefix_error(&err, "Backend init error: ");
	return err;
}

#define CLEAN(N) if (N) { oio_events_queue__destroy(N); N = NULL; }

void
meta1_backend_clean(struct meta1_backend_s *m1)
{
	if (!m1)
		return;

	CLEAN(m1->notifier_srv);
	CLEAN(m1->notifier_ref);

	if (m1->prefixes) {
		meta1_prefixes_clean(m1->prefixes);
		m1->prefixes = NULL;
	}

	if (m1->svcupdate) {
		service_update_policies_destroy(m1->svcupdate);
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
