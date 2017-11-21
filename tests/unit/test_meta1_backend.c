/*
OpenIO SDS unit tests
Copyright (C) 2017 OpenIO SAS, as part of OpenIO SDS

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#include <string.h>
#include <unistd.h>

#include <glib.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/common_variables.h>
#include <meta1v2/meta1_backend.h>
#include <meta1v2/meta1_prefixes.h>
#include <sqliterepo/sqliterepo.h>

#define DEADBEEF ((void*)0xDEADBEEF)

#define MAXITER 32

#undef GQ
#define GQ() g_quark_from_static_string("oio.m1v2")

typedef void (*repo_test_f) (struct meta1_backend_s *m2);

typedef void (*container_test_f) (struct meta1_backend_s *m2,
		struct oio_url_s *url);

static guint64 container_counter = 0;
static volatile gint64 CLOCK_START = 0;
static volatile gint64 CLOCK = 0;

static struct oio_lb_world_s *lb_world = NULL;

static gint64 _get_monotonic (void) { return CLOCK; }

static gint64 _get_real (void) { return CLOCK; }

static struct namespace_info_s *
_init_nsinfo(const gchar *ns)
{
	struct namespace_info_s *nsinfo = g_malloc0 (sizeof(*nsinfo));
	namespace_info_init (nsinfo);
	g_strlcpy (nsinfo->name, ns, sizeof(nsinfo->name));

	g_hash_table_insert(nsinfo->storage_policy, g_strdup("classic"),
			metautils_gba_from_string("NONE:DUPONETWO"));
	g_hash_table_insert(nsinfo->storage_policy, g_strdup("polcheck"),
			metautils_gba_from_string("NONE:DUPONETHREE"));
	g_hash_table_insert(nsinfo->storage_policy, g_strdup("secure"),
			metautils_gba_from_string("NONE:DUP_SECURE"));
	g_hash_table_insert(nsinfo->storage_policy, g_strdup("THREECOPIES"),
			metautils_gba_from_string("rawx3:DUPONETHREE"));
	g_hash_table_insert(nsinfo->storage_policy, g_strdup("TWOCOPIES"),
			metautils_gba_from_string("rawx2:DUPONETWO"));
	g_hash_table_insert(nsinfo->storage_policy, g_strdup("EC"),
			metautils_gba_from_string("EC:EC"));

	g_hash_table_insert(nsinfo->data_security, g_strdup("DUPONETWO"),
			metautils_gba_from_string("plain/distance=1,nb_copy=2"));
	g_hash_table_insert(nsinfo->data_security, g_strdup("DUPONETHREE"),
			metautils_gba_from_string("plain/distance=1,nb_copy=3"));
	g_hash_table_insert(nsinfo->data_security, g_strdup("DUP_SECURE"),
			metautils_gba_from_string("plain/distance=4,nb_copy=2"));
	g_hash_table_insert(nsinfo->data_security, g_strdup("EC"),
			metautils_gba_from_string("ec/k=6,m=3,algo=liberasurecode_rs_vand,distance=1"));

	return nsinfo;
}

static struct oio_lb_s *
_init_lb(int nb_services)
{
	if (lb_world)
		oio_lb_world__destroy(lb_world);

	lb_world = oio_lb_local__create_world();
	oio_lb_world__create_slot (lb_world, "*");
	struct oio_lb_item_s *item = g_alloca(sizeof(*item) + LIMIT_LENGTH_SRVID);
	for (int i = 0; i < nb_services; i++) {
		item->location = 65536 + 6000 + i;
		item->weight = 50;
		g_snprintf(item->id, LIMIT_LENGTH_SRVID, "127.0.0.1:%d", 6000+i);
		oio_lb_world__feed_slot(lb_world, "*", item);
	}
	//oio_lb_world__debug(lb_world);

	struct oio_lb_pool_s *pool = oio_lb_world__create_pool(lb_world,
			NAME_SRVTYPE_META2);
	oio_lb_world__add_pool_target(pool, "*");
	struct oio_lb_s *lb = oio_lb__create();
	oio_lb__force_pool(lb, pool);
	return lb;
}

static void
_repo_wrapper(const gchar *ns, repo_test_f fr)
{
	gchar repodir[512];
	GError *err = NULL;

	g_assert(ns != NULL);

	struct namespace_info_s *nsinfo = _init_nsinfo(ns);
	g_assert_nonnull (nsinfo);

	g_snprintf(repodir, sizeof(repodir), "%s/.oio/sds/data/test-%d",
			g_get_home_dir(), getpid());
	g_mkdir_with_parents(repodir, 0755);

	struct oio_lb_s *lb = _init_lb(9);
	g_assert_nonnull(lb);

	struct sqlx_repo_config_s cfg = {0};
	struct sqlx_repository_s *repository = NULL;
	cfg.sync_solo = SQLX_SYNC_OFF;
	cfg.sync_repli = SQLX_SYNC_OFF;
	err = sqlx_repository_init(repodir, &cfg, &repository);
	g_assert_no_error(err);

	err = sqlx_repository_configure_type(repository,
			NAME_SRVTYPE_META1, META1_SCHEMA);
	g_assert_no_error(err);

	struct meta1_backend_s *m1 = NULL;
	err = meta1_backend_init(&m1, ns, repository, lb);
	g_assert_no_error(err);

	meta1_prefixes_manage_all(meta1_backend_get_prefixes(m1));

	if (fr)
		fr(m1);

	meta1_backend_clean(m1);
	sqlx_repository_clean(repository);
	namespace_info_free (nsinfo);
	oio_lb__clear(&lb);
}

static void
_container_wraper(const char *ns, container_test_f cf)
{
	void test(struct meta1_backend_s *m1) {

		gchar *strurl = g_strdup_printf(
				"/%s/account/container-%"G_GUINT64_FORMAT"//content-%"G_GINT64_FORMAT,
				ns, ++container_counter, oio_ext_monotonic_time());
		struct oio_url_s *url = oio_url_init(strurl);
		g_free(strurl);

		if (cf)
			cf(m1, url);

		oio_url_pclean(&url);
	}

	_repo_wrapper(ns, test);
}

#define CHECK_ARRAY_LEN(len,out) do { \
		g_assert_nonnull(out); \
		g_assert_cmpint(len, ==, g_strv_length(out)); \
		g_strfreev(out); \
		out = NULL; \
} while (0)

static void
test_backend_cycle(void)
{
	for (guint i=0; i<8 ;i++)
		_repo_wrapper("NS", NULL);
}

/**
 * All the invalid parameters should be tested with assertions, at the
 * beginning of the functions.
 */
static void
test_invalid_parameters(void)
{
#define TEST_ABORTING_INIT(Call) do { \
		if (g_test_subprocess ()) { \
			struct meta1_backend_s *_m1 = NULL; \
			struct sqlx_repository_s *repo = DEADBEEF; \
			struct oio_lb_s *lb = DEADBEEF; \
			do { Call; } while (0); \
			(void) _m1, (void) repo, (void) lb; \
			return; \
		} \
		g_test_trap_subprocess (NULL, 0, 0); \
		g_test_trap_assert_failed (); \
} while (0)
	void _init(struct meta1_backend_s *m1 UNUSED, struct oio_url_s *url UNUSED) {
		TEST_ABORTING_INIT(meta1_backend_init(NULL, "NS", repo, lb));
		TEST_ABORTING_INIT(meta1_backend_init(&_m1, NULL, repo, lb));
		TEST_ABORTING_INIT(meta1_backend_init(&_m1, "NS", NULL, lb));
		TEST_ABORTING_INIT(meta1_backend_init(&_m1, "NS", repo, NULL));
	}

#define TEST_ABORTING_LIST(Call) do { \
		if (g_test_subprocess ()) { \
			gchar **out = NULL; \
			do { Call; } while (0); \
			(void) out; \
			return; \
		} \
		g_test_trap_subprocess (NULL, 0, 0); \
		g_test_trap_assert_failed (); \
} while (0)
	void _create(struct meta1_backend_s *m1, struct oio_url_s *url) {
		gchar **props = DEADBEEF;
		TEST_ABORTING_LIST(meta1_backend_user_create(NULL, url, props));
		TEST_ABORTING_LIST(meta1_backend_user_create(m1, NULL, props));
		TEST_ABORTING_LIST(meta1_backend_user_create(m1, url, NULL));
	}
	void _destroy(struct meta1_backend_s *m1, struct oio_url_s *url) {
		TEST_ABORTING_LIST(meta1_backend_user_create(NULL, url, FALSE));
		TEST_ABORTING_LIST(meta1_backend_user_create(m1, NULL, FALSE));
	}
	void _info(struct meta1_backend_s *m1, struct oio_url_s *url) {
		TEST_ABORTING_LIST(meta1_backend_user_info(NULL, url, &out));
		TEST_ABORTING_LIST(meta1_backend_user_info(m1, NULL, &out));
		TEST_ABORTING_LIST(meta1_backend_user_info(m1, url, NULL));
	}
	void _list(struct meta1_backend_s *m1, struct oio_url_s *url) {
		TEST_ABORTING_LIST(meta1_backend_services_list(NULL, url, NAME_SRVTYPE_META2, &out, oio_ext_monotonic_time() + G_TIME_SPAN_SECOND));
		TEST_ABORTING_LIST(meta1_backend_services_list(m1, NULL, NAME_SRVTYPE_META2, &out, oio_ext_monotonic_time() + G_TIME_SPAN_SECOND));
		TEST_ABORTING_LIST(meta1_backend_services_list(m1, url, NULL, &out, oio_ext_monotonic_time() + G_TIME_SPAN_SECOND));
		TEST_ABORTING_LIST(meta1_backend_services_list(m1, url, NAME_SRVTYPE_META2, NULL, oio_ext_monotonic_time() + G_TIME_SPAN_SECOND));
	}
	void _link(struct meta1_backend_s *m1, struct oio_url_s *url) {
		TEST_ABORTING_LIST(meta1_backend_services_link(NULL, url, NAME_SRVTYPE_META2, NULL, FALSE, &out));
		TEST_ABORTING_LIST(meta1_backend_services_link(m1, NULL, NAME_SRVTYPE_META2, NULL, FALSE, &out));
		TEST_ABORTING_LIST(meta1_backend_services_link(m1, url, NULL, NULL, FALSE, &out));
		TEST_ABORTING_LIST(meta1_backend_services_link(m1, url, NAME_SRVTYPE_META2, NULL, FALSE, NULL));
	}
	void _renew(struct meta1_backend_s *m1, struct oio_url_s *url) {
		TEST_ABORTING_LIST(meta1_backend_services_renew(NULL, url, NAME_SRVTYPE_META2, NULL, FALSE, &out));
		TEST_ABORTING_LIST(meta1_backend_services_renew(m1, NULL, NAME_SRVTYPE_META2, NULL, FALSE, &out));
		TEST_ABORTING_LIST(meta1_backend_services_renew(m1, url, NULL, NULL, FALSE, &out));
		TEST_ABORTING_LIST(meta1_backend_services_renew(m1, url, NAME_SRVTYPE_META2, NULL, FALSE, NULL));
	}
	void _unlink(struct meta1_backend_s *m1, struct oio_url_s *url) {
		gchar **in = DEADBEEF;
		TEST_ABORTING_LIST(meta1_backend_services_unlink(NULL, url, NAME_SRVTYPE_META2, in));
		TEST_ABORTING_LIST(meta1_backend_services_unlink(m1, NULL, NAME_SRVTYPE_META2, in));
		TEST_ABORTING_LIST(meta1_backend_services_unlink(m1, url, NULL, in));
		TEST_ABORTING_LIST(meta1_backend_services_unlink(m1, url, NAME_SRVTYPE_META2, NULL));
	}

	_container_wraper("NS", _init);
	_container_wraper("NS", _create);
	_container_wraper("NS", _destroy);
	_container_wraper("NS", _info);
	_container_wraper("NS", _list);
	_container_wraper("NS", _link);
	_container_wraper("NS", _renew);
	_container_wraper("NS", _unlink);
}

static void
test_user_cycle(void)
{
	void _test(struct meta1_backend_s *m1, struct oio_url_s *url) {
		GError *err = NULL;

		err = meta1_backend_user_create(m1, url, NULL);
		g_assert_no_error(err);

		for (guint i=0; i<MAXITER ; ++i) {
			err = meta1_backend_user_info(m1, url, NULL);
			g_assert_no_error(err);

			gchar **allurl = NULL;
			err = meta1_backend_user_info(m1, url, &allurl);
			g_assert_no_error(err);
			CHECK_ARRAY_LEN(1, allurl);

			err = meta1_backend_user_create(m1, url, NULL);
			/* TODO(jfs): should have CODE_USER_EXISTS */
			g_assert_error(err, GQ(), CODE_CONTAINER_EXISTS);
			g_clear_error(&err);
		}

		err = meta1_backend_user_destroy(m1, url, FALSE);
		g_assert_no_error(err);

		for (guint i=0; i<MAXITER ; ++i) {
			err = meta1_backend_user_info(m1, url, NULL);
			g_assert_error(err, GQ(), CODE_USER_NOTFOUND);
			g_clear_error(&err);

			err = meta1_backend_user_destroy(m1, url, FALSE);
			g_assert_error(err, GQ(), CODE_USER_NOTFOUND);
			g_clear_error(&err);
		}
	}

	for (guint i=0; i<4 ;i++)
		_container_wraper("NS", _test);
}

static guint
_count_services(struct meta1_backend_s *m1, struct oio_url_s *url, const char *srvtype)
{
	gchar **out = NULL;
	GError *err = meta1_backend_services_list(m1, url, srvtype, &out,
			oio_ext_monotonic_time() + 30 * G_TIME_SPAN_SECOND);
	g_assert_no_error(err);
	g_assert_nonnull(out);
	guint count = g_strv_length(out);
	g_strfreev(out);
	out = NULL;
	return count;
}

static void
test_services_cycle_nolast(void)
{
	void _test(struct meta1_backend_s *m1, struct oio_url_s *url) {
		GError *err = NULL;
		gchar **out = NULL;

		err = meta1_backend_user_create(m1, url, NULL);
		g_assert_no_error(err);

		for (guint i=0; i<MAXITER ;++i) {
			g_assert_cmpuint(0, ==, _count_services(m1, url, "Mkmlkmjnhj"));
		}

		/* Subsequent LINK do not alter the sequence returned */
		for (guint i=0; i<MAXITER ;++i) {
			err = meta1_backend_services_link(
					m1, url, NAME_SRVTYPE_META2, NULL, FALSE, &out);
			g_assert_no_error(err);
			CHECK_ARRAY_LEN(1, out);

			g_assert_cmpuint(1, ==, _count_services(m1, url, NAME_SRVTYPE_META2));
		}

		/* Renew the services with no 'last' known */
		err = meta1_backend_services_renew(
				m1, url, NAME_SRVTYPE_META2, NULL, FALSE, &out);
		g_assert_no_error(err);
		CHECK_ARRAY_LEN(2, out);

		g_assert_cmpuint(2, ==, _count_services(m1, url, NAME_SRVTYPE_META2));

		/* Renew the services with the 'last' actually wrong ("1" passed
		 * instead of "2,1" */
		err = meta1_backend_services_renew(m1, url, NAME_SRVTYPE_META2,
				"1", FALSE, &out);
		g_assert_error(err, GQ(), CODE_SHARD_CHANGE);
		g_clear_error(&err);

		g_assert_cmpuint(2, ==, _count_services(m1, url, NAME_SRVTYPE_META2));

		/* Renew the services with the 'last' actually wrong ("1,2" passed
		 * instead of "2,1" */
		err = meta1_backend_services_renew(m1, url, NAME_SRVTYPE_META2,
				"1,2", FALSE, &out);
		g_assert_error(err, GQ(), CODE_SHARD_CHANGE);
		g_clear_error(&err);

		g_assert_cmpuint(2, ==, _count_services(m1, url, NAME_SRVTYPE_META2));

		/* Renew the services with the 'last' actually OK... */
		err = meta1_backend_services_renew(m1, url, NAME_SRVTYPE_META2,
				"2,1", FALSE, &out);
		g_assert_no_error(err);
		CHECK_ARRAY_LEN(3, out);

		g_assert_cmpuint(3, ==, _count_services(m1, url, NAME_SRVTYPE_META2));

		/* ... and let's retry */
		err = meta1_backend_services_renew(m1, url, NAME_SRVTYPE_META2,
				"3,2,1", FALSE, &out);
		g_assert_no_error(err);
		CHECK_ARRAY_LEN(4, out);

		g_assert_cmpuint(4, ==, _count_services(m1, url, NAME_SRVTYPE_META2));

		/* try (and fail) to delete an user with services */
		for (guint i=0; i<MAXITER ;++i) {
			err = meta1_backend_user_destroy(m1, url, FALSE);
			g_assert_error(err, GQ(), CODE_USER_INUSE);
			g_clear_error(&err);
		}

		/* delete all the services */
		for (guint i=0; i<MAXITER ;++i) {
			err = meta1_backend_services_unlink(m1, url, NAME_SRVTYPE_META2, NULL);
			g_assert_no_error(err);
		}

		/* delete the user */
		err = meta1_backend_user_destroy(m1, url, FALSE);
		g_assert_no_error(err);
	}

	_container_wraper("NS", _test);
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);

	oio_time_monotonic = _get_monotonic;
	oio_time_real = _get_real;
	container_counter = random();

	g_test_add_func("/meta1/backend/invalid", test_invalid_parameters);
	g_test_add_func("/meta1/backend/cycle", test_backend_cycle);
	g_test_add_func("/meta1/user/cycle", test_user_cycle);
	g_test_add_func("/meta1/services/cycle/nolast", test_services_cycle_nolast);

	return g_test_run();
}

