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

#include <core/oiocfg.h>
#include <metautils/lib/metautils.h>
#include <sqliterepo/sqliterepo.h>
#include <sqliterepo/election.h>

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

GError *
meta1_backend_init(struct meta1_backend_s **out, const char *ns,
		struct sqlx_repository_s *repo, struct oio_lb_s *lb)
{
	EXTRA_ASSERT(out != NULL);
	EXTRA_ASSERT(repo != NULL);

	if (!*ns || strlen(ns) >= LIMIT_LENGTH_NSNAME)
		return BADREQ("Invalid namespace name");

	guint digits = OIO_META1_DIGITS_DEFAULT;
	gchar *str_digits = oio_cfg_get_value(ns, OIO_META1_DIGITS_KEY);
	if (str_digits) {
		STRING_STACKIFY(str_digits);
		gchar *end = NULL;
		gint64 i64 = g_ascii_strtoll(str_digits, &end, 10);
		if (0 == i64 && end == str_digits)
			return ERRPTF("Misconfigured '%s' in system configuration: %s",
					OIO_META1_DIGITS_KEY, "not an integer");
		if (end && *end)
			return ERRPTF("Misconfigured '%s' in system configuration: %s",
					OIO_META1_DIGITS_KEY, "trailing characters");
		if (i64 < 0 || i64 > 4)
			return ERRPTF("Misconfigured '%s' in system configuration: %s",
					OIO_META1_DIGITS_KEY, "value out of range [0,4]");
		digits = i64;
	}

	struct meta1_backend_s *m1 = g_malloc0(sizeof(*m1));
	g_strlcpy (m1->ns_name, ns, sizeof(m1->ns_name));
	m1->type = NAME_SRVTYPE_META1;
	m1->lb = lb;
	m1->repo = repo;
	m1->prefixes = meta1_prefixes_init();
	m1->svcupdate = service_update_policies_create();
	m1->nb_digits = digits;

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

