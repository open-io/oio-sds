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

#include <unistd.h>

#include <glib.h>

#include <core/oio_core.h>
#include <core/oiodir.h>
#include <core/internals.h>

#undef GQ
#define GQ() g_quark_from_static_string("oio.core")

/* TODO factorize this with meta2v2/meta2_utils.c */
#define RANDOM_UID(uid,uid_size) \
	struct { guint64 now; guint32 r; guint16 pid; guint16 th; } uid; \
	uid.now = oio_ext_real_time (); \
	uid.r = g_random_int(); \
	uid.pid = getpid(); \
	uid.th = oio_log_current_thread_id(); \
	gsize uid_size = sizeof(uid);

static void
_random_string (gchar *d, gsize dlen)
{
	RANDOM_UID (uid,uidlen);
	oio_str_bin2hex ((void*)&uid, uidlen, d, dlen);
}

static void
_random_url (struct oio_url_s *url)
{
	gchar buf[65];

	oio_url_set (url, OIOURL_NS, "NS");

	_random_string (buf, sizeof(buf));
	oio_url_set (url, OIOURL_ACCOUNT, buf);
	_random_string (buf, sizeof(buf));
	oio_url_set (url, OIOURL_USER, buf);
}

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
	for (int i=0; i<16 ;++i)
		_test_init_round ();
}

static void
_test_reference_cycle_round (void)
{
	GError *err = NULL;

	struct oio_url_s *url = oio_url_empty ();
	_random_url (url);

	struct oio_directory_s *dir = oio_directory__create_proxy ("NS");
	g_assert_nonnull (dir);

	/* link with no reference */
	gchar **srvtab = NULL;
	err = oio_directory__link (dir, url, "meta2", FALSE, &srvtab);
	g_assert_error (err, GQ(), CODE_USER_NOTFOUND);
	g_assert_null (srvtab);
	g_clear_error (&err);

	/* create */
	err = oio_directory__create (dir, url);
	g_assert_no_error (err);

	/* link with a reference */
	err = oio_directory__link (dir, url, "meta2", FALSE, &srvtab);
	g_assert_no_error (err);
	g_assert_nonnull (srvtab);
	g_strfreev (srvtab);

	/* list */
	gchar **dirtab = NULL;
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

