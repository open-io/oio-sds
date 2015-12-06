/*
OpenIO SDS sqlx
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

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

#include <core/oio_core.h>
#include <core/oiodir.h>

static void
_test_init_round (void)
{
	struct oio_directory_s *dir = oio_directory__create_proxy ("NS");
	g_assert_nonnull (dir);
	oio_directory__destroy (dir);
}

static void
test_init (void)
{
	for (int i=0; i<64 ;++i)
		_test_init_round ();
}

static void
_test_reference_cycle_round (void)
{
	GError *err = NULL;

	struct oio_url_s *url = oio_url_empty ();
	oio_url_set (url, OIOURL_NS, "NS");
	oio_url_set (url, OIOURL_ACCOUNT, "ACCT");
	oio_url_set (url, OIOURL_USER, "JFS");

	struct oio_directory_s *dir = oio_directory__create_proxy ("NS");
	g_assert_nonnull (dir);

	/* create */

	/* link */

	/* list */
	gchar **dirtab = NULL, **srvtab = NULL;
	err = oio_directory__list (dir, url, "meta2", &dirtab, &srvtab);
	g_assert_no_error (err);
	g_assert_nonnull (dirtab);
	g_assert_nonnull (srvtab);
	g_strfreev (dirtab);
	g_strfreev (srvtab);

	oio_url_pclean (&url);
	oio_directory__destroy (dir);
}

static void
test_reference_cycle (void)
{
	for (int i=0; i<64 ;++i)
		_test_reference_cycle_round ();
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);
	oio_ext_set_random_reqid ();
	oio_log_lazy_init ();
	oio_log_init_level (GRID_LOGLVL_INFO);
	g_log_set_default_handler (oio_log_stderr, NULL);

	g_test_add_func ("/core/directory/init", test_init);
	g_test_add_func ("/core/directory/references", test_reference_cycle);
	return g_test_run ();
}

