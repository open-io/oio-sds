/*
OpenIO SDS cache
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#include <cache/cache.h>

static void
test_found (struct oio_cache_s *c, const char *k, const char *v)
{
	gchar *value = NULL;
	enum oio_cache_status_e rc = oio_cache_get (c, k, &value);
	g_assert_cmpint (rc, ==, OIO_CACHE_OK);
	g_assert_nonnull (value);
	g_assert_cmpstr (value, ==, v);
	g_free (value);
}

static void
test_not_found (struct oio_cache_s *c, const char *k)
{
	enum oio_cache_status_e rc;
	gchar *value = NULL;

	rc = oio_cache_get (c, k, &value);
	g_assert_null (value);
	g_assert_cmpint (rc, ==, OIO_CACHE_NOTFOUND);
}

static void
test_cache_cycle (struct oio_cache_s *c)
{
	const char *k = "NOTFOUND";
	const char *v = "plop";

	g_assert_nonnull (c);
	test_not_found (c, k);

	enum oio_cache_status_e rc = oio_cache_put (c, k, v);
	if (rc == OIO_CACHE_OK) {
		test_found (c, k, v);
		rc = oio_cache_del (c, k);
		g_assert_cmpint (rc, ==, OIO_CACHE_OK);
	} else {
		g_assert_cmpint (rc, ==, OIO_CACHE_DISCONNECTED);
	}

	test_not_found (c, k);
}

