/*
OpenIO SDS unit tests
Copyright (C) 2014 Worldline, as part of Redcurrant
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

#include <string.h>
#include <glib.h>

#include <metautils/lib/common_variables.h>
#include <meta2v2/meta2_macros.h>
#include <meta2v2/meta2_variables.h>
#include <meta2v2/meta2_utils.h>
#include <meta2v2/meta2_backend_internals.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>
#include <resolver/hc_resolver.h>

#undef GQ
#define GQ() g_quark_from_static_string("oio.m2v2")

typedef void (*repo_test_f) (struct meta2_backend_s *m2);

typedef void (*container_test_f) (struct meta2_backend_s *m2,
		struct oio_url_s *url);

static guint64 container_counter = 0;
static gint64 chunks_count = 3;
static volatile gint64 CLOCK_START = 0;
static volatile gint64 CLOCK = 0;

static struct oio_lb_world_s *lb_world = NULL;

#define CHECK_ALIAS_VERSION(m2,u,v) do {\
	gint64 _v = 0, _v0 = (v); \
	err = meta2_backend_get_alias_version(m2, u, &_v); \
	GRID_DEBUG("err=%d version=%"G_GINT64_FORMAT" expected=%"G_GINT64_FORMAT,\
			err?err->code:0, _v, _v0); \
	g_assert_no_error(err); \
	g_assert(_v0 == _v); \
} while (0);

#define DECLARE_M2OP(u) struct m2op_target_s op = { \
		.url = u, .seq = 1, .flag_local = 0, .flag_last_base = 1 }

static gint64 _get_monotonic (void) { return CLOCK; }

static gint64 _get_real (void) { return CLOCK; }

static gint64
_version(struct meta2_backend_s *m2, struct oio_url_s *u)
{
	gint64 v = 0;
	DECLARE_M2OP(u);
	GError *err = meta2_backend_get_max_versions(m2, &op, &v);
	g_assert_no_error(err);
	return v;
}

static GSList *
_props_generate(struct oio_url_s *url, gint64 v, guint count)
{
	GSList *result = NULL;
	while (count-- > 0) {
		gchar name[32];
		g_snprintf(name, sizeof(name), "prop-%u", count);
		struct bean_PROPERTIES_s *p = _bean_create(&descr_struct_PROPERTIES);
		PROPERTIES_set2_alias(p, oio_url_get(url, OIOURL_PATH));
		PROPERTIES_set_version(p, v);
		PROPERTIES_set2_key(p, name);
		PROPERTIES_set2_value(p, (guint8*)"value", sizeof("value"));
		result = g_slist_prepend(result, p);
	}

	return result;
}

static gint
_bean_compare_custom (gconstpointer b0, gconstpointer b1)
{
	if (!b0 && !b1)
		return 0;

	const int cmp = _bean_compare_kind(b0, b1);
	if (cmp != 0)
		return cmp;

	if (DESCR(b0) != &descr_struct_CHUNKS)
		return 0;

	const int p0 = atoi(CHUNKS_get_position_const(b0)->str);
	const int p1 = atoi(CHUNKS_get_position_const(b1)->str);
	return (p0 == p1) ? 0 : ((p0 < p1) ? -1 : 1);
}

static GSList*
_create_alias_ec(struct meta2_backend_s *m2b, struct oio_url_s *url,
		const gchar *polname, int k, int m)
{
	void _onbean(gpointer u, gpointer bean) {
		*((GSList**)u) = g_slist_prepend(*((GSList**)u), bean);
	}

	g_assert(chunks_count > 1);
	DECLARE_M2OP(url);
	GSList *beans = NULL;
	const gint64 metachunk_size = k * oio_ns_chunk_size;
	const gint64 content_size = 1 + metachunk_size * (chunks_count - 1);
	GError *err = meta2_backend_generate_beans(m2b, &op,
			content_size, polname, FALSE, _onbean, &beans);
	g_assert_no_error(err);
	beans = g_slist_sort(beans, _bean_compare_custom);
	_bean_debugl2("> ", beans);
	g_assert_cmpint(g_slist_length(beans), ==,
			2 + (k + m) * (1 + (content_size / metachunk_size)));
	return beans;
}

static GSList*
_create_alias_replicated(struct meta2_backend_s *m2b, struct oio_url_s *url,
		const gchar *polname, int repli)
{
	void _onbean(gpointer u, gpointer bean) {
		*((GSList**)u) = g_slist_prepend(*((GSList**)u), bean);
	}

	g_assert(chunks_count > 1);
	DECLARE_M2OP(url);
	GSList *beans = NULL;
	const gint64 metachunk_size = oio_ns_chunk_size;
	const gint64 content_size = 1 + metachunk_size * (chunks_count - 1);
	GError *err = meta2_backend_generate_beans(m2b, &op,
			content_size, polname, FALSE, _onbean, &beans);
	g_assert_no_error(err);
	beans = g_slist_sort(beans, _bean_compare_custom);
	_bean_debugl2("> ", beans);
	g_assert_cmpint(g_slist_length(beans), ==,
			2 + repli * (1 + (content_size / metachunk_size)));
	return beans;
}

static void
check_list_count(struct meta2_backend_s *m2, struct oio_url_s *url,
		guint expected)
{
	guint counter = 0;

	void _count (gpointer u, gpointer bean) {
		(void) u, (void) bean;
		counter ++;
		_bean_clean(bean);
	}

	DECLARE_M2OP(url);
	op.flag_local = 1;
	struct list_params_s lp = {0};
	lp.flags.allversion = 1;

	GError *err = meta2_backend_list_aliases(m2, &op, &lp, NULL, _count, NULL, NULL);
	g_assert_no_error(err);
	GRID_DEBUG("TEST list_aliases counter=%u expected=%u", counter, expected);
	g_assert(counter == expected);
}

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
	oio_lb_world__purge_old_generations(lb_world);
	//oio_lb_world__debug(lb_world);

	struct oio_lb_pool_s *pool = oio_lb_world__create_pool(lb_world,
			NAME_SRVTYPE_RAWX);
	oio_lb_world__add_pool_target(pool, "*");
	struct oio_lb_s *lb = oio_lb__create();
	oio_lb__force_pool(lb, pool);
	return lb;
}

static void
_init_pool_ec_2cpy_3cpy(struct meta2_backend_s *m2)
{
	struct oio_lb_pool_s *rawx3 = oio_lb_world__create_pool(lb_world, "rawx3");
	oio_lb_world__add_pool_targets(rawx3, "3,*");
	oio_lb__force_pool(m2->lb, rawx3);

	struct oio_lb_pool_s *rawx2 = oio_lb_world__create_pool(lb_world, "rawx2");
	oio_lb_world__add_pool_targets(rawx2, "2,*");
	oio_lb__force_pool(m2->lb, rawx2);

	struct oio_lb_pool_s *ec = oio_lb_world__create_pool(lb_world, "EC");
	oio_lb_world__add_pool_targets(ec, "9,*");
	oio_lb__force_pool(m2->lb, ec);
}
static void
_repo_wrapper(const gchar *ns, repo_test_f fr)
{
	gchar repodir[512];
	GError *err = NULL;
	struct oio_lb_s *lb = NULL;
	struct meta2_backend_s *backend = NULL;
	struct sqlx_repository_s *repository = NULL;
	struct hc_resolver_s *resolver = NULL;
	struct namespace_info_s *nsinfo = NULL;
	struct sqlx_repo_config_s cfg = {0};

	g_assert(ns != NULL);

	nsinfo = _init_nsinfo(ns);
	g_assert_nonnull (nsinfo);

	g_snprintf(repodir, sizeof(repodir), "%s/.oio/sds/data/test-%d",
			g_get_home_dir(), getpid());
	g_mkdir_with_parents(repodir, 0755);

	lb = _init_lb(9);
	g_assert_nonnull(lb);

	resolver = hc_resolver_create();
	g_assert_nonnull(resolver);

	cfg.flags = SQLX_REPO_DELETEON;
	cfg.sync_solo = SQLX_SYNC_OFF;
	cfg.sync_repli = SQLX_SYNC_OFF;
	err = sqlx_repository_init(repodir, &cfg, &repository);
	g_assert_no_error(err);

	err = meta2_backend_init(&backend, repository, ns, lb, resolver);
	g_assert_no_error(err);
	meta2_backend_configure_nsinfo(backend, nsinfo);

	if (fr)
		fr(backend);

	meta2_backend_clean(backend);
	sqlx_repository_clean(repository);
	hc_resolver_destroy(resolver);
	namespace_info_free (nsinfo);
	oio_lb__clear(&lb);
}

static void
_repo_failure(const gchar *ns)
{
	gchar repodir[512];
	GError *err = NULL;
	struct meta2_backend_s *backend = NULL;
	struct sqlx_repository_s *repository = NULL;
	struct hc_resolver_s *resolver = NULL;
	struct oio_lb_s *lb = NULL;
	struct sqlx_repo_config_s cfg = {0};

	g_assert(ns != NULL);

	g_snprintf(repodir, sizeof(repodir), "%s/.oio/sds/data/test-%d",
			g_get_home_dir(), getpid());
	g_mkdir_with_parents(repodir, 0755);

	lb = _init_lb(6);
	g_assert_nonnull(lb);

	resolver = hc_resolver_create();
	g_assert_nonnull(resolver);

	cfg.flags = SQLX_REPO_DELETEON;
	err = sqlx_repository_init(repodir, &cfg, &repository);
	g_assert_no_error(err);
	err = meta2_backend_init(&backend, repository, ns, lb, resolver);
	g_assert_error(err, GQ(), CODE_BAD_REQUEST);
	g_clear_error (&err);

	meta2_backend_clean(backend);
	sqlx_repository_clean(repository);
	hc_resolver_destroy(resolver);
	oio_lb__clear(&lb);
}

static void
_container_wraper(const char *ns, container_test_f cf)
{
	void test(struct meta2_backend_s *m2) {
		gchar *strurl = g_strdup_printf(
				"/%s/account/container-%"G_GUINT64_FORMAT"//content-%"G_GINT64_FORMAT,
				ns, ++container_counter, oio_ext_monotonic_time());
		struct oio_url_s *url = oio_url_init(strurl);
		g_free(strurl);

		DECLARE_M2OP(url);
		op.flag_local = 0;

		struct m2v2_create_params_s cp = {NULL, NULL, NULL};
		GError *err = meta2_backend_create_container(m2, &op, &cp);
		g_assert_no_error(err);

		if (cf)
			cf(m2, url);

		op.flag_local = 1;
		struct m2v2_destroy_params_s dp = {0};
		dp.flag_force = 1;
		dp.flag_flush = 1;
		err = meta2_backend_destroy_container (m2, &op, &dp);
		g_assert_no_error (err);

		oio_url_pclean(&url);
	}

	GRID_INFO("--- %"G_GINT64_FORMAT" %s ------------------------------------"
			"-----------------", meta2_max_versions, ns);
	_repo_wrapper(ns, test);
}

static void
_container_wraper_allversions (const char *ns, container_test_f cf)
{
	meta2_max_versions = -1;
	_container_wraper (ns, cf);
	meta2_max_versions = 0;
	_container_wraper (ns, cf);
	meta2_max_versions = 1;
	_container_wraper (ns, cf);
	meta2_max_versions = 2;
	_container_wraper (ns, cf);
}

static void
test_backend_create_destroy(void)
{
	meta2_max_versions = 1;
	_repo_wrapper("NS", NULL);
}

static void
test_backend_strange_ns(void)
{
	char ns[LIMIT_LENGTH_NSNAME+2];

	void test(struct meta2_backend_s *m2) {
		g_assert_cmpstr(m2->ns_name, ==, ns);
	}

	/* empty NS is an error */
	memset(ns, 0, sizeof(ns));
	_repo_failure (ns);

	for (guint len=1; len<LIMIT_LENGTH_NSNAME ;len++) {
		memset(ns, 0, sizeof(ns));
		memset(ns, 'x', len);
		meta2_max_versions = 1;
		_repo_wrapper(ns, test);
	}

	/* too long NS is an error */
	memset(ns, 0, sizeof(ns));
	memset(ns, 'x', sizeof(ns)-1);
	_repo_failure(ns);
}

static void
test_container_create_destroy(void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u) {
		g_assert_cmpint(meta2_max_versions, ==, _version(m2, u));
	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_delete_not_found(void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u) {
		DECLARE_M2OP(u);
		GError *err = meta2_backend_delete_alias(m2, &op, _bean_ignore, NULL);
		g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
		g_clear_error(&err);
	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_put_no_beans(void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u) {
		DECLARE_M2OP(u);
		GError *err = meta2_backend_put_alias(m2, &op, NULL, NULL, NULL);
		g_assert_error(err, GQ(), CODE_BAD_REQUEST);
		g_clear_error(&err);
	}
	_container_wraper_allversions("NS", test);
}

static void
_remove_bean(GSList **beans, guint nb, gchar *pos)
{
	for (guint i = 0; i < nb ; i++) {
		for (GSList *l = *beans; l; l = l->next) {
			gpointer bean = l->data;
			if (DESCR(bean) == &descr_struct_CHUNKS) {
				if (pos) {
					GString *pos_bean = CHUNKS_get_position(bean);
					if (!g_strcmp0(pos_bean->str, pos)) {
						*beans = g_slist_remove(*beans, bean);
						_bean_clean(bean);
						break;
					}
				} else  {
					*beans = g_slist_remove(*beans, bean);
					_bean_clean(bean);
					break;
				}
			}
		}
	}
}

static void
test_content_check_all_beans_correct(void)
{
	void test(struct meta2_backend_s * m2, struct oio_url_s * u) {
		_init_pool_ec_2cpy_3cpy(m2);
		GError *err;
		GSList *beans_3cpy = _create_alias_replicated(m2, u, "THREECOPIES", 3);
		GString *message = g_string_new("");
		err = meta2_backend_check_content(m2, beans_3cpy, message, FALSE);
		g_string_free(message, TRUE);
		_bean_cleanl2(beans_3cpy);
		g_assert_no_error(err);

		GSList *beans_2cpy = _create_alias_replicated(m2, u, "TWOCOPIES", 2);
		message = g_string_new("");
		err = meta2_backend_check_content(m2, beans_2cpy, message, FALSE);
		g_string_free(message, TRUE);
		_bean_cleanl2(beans_2cpy);
		g_assert_no_error(err);

		message = g_string_new("");
		GSList *beans_ec = _create_alias_ec(m2, u, "EC", 6, 3);
		err = meta2_backend_check_content(m2, beans_ec, message, FALSE);
		g_string_free(message, TRUE);
		_bean_cleanl2(beans_ec);
		g_assert_no_error(err);

	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_check_1_missing_bean_plain_irreparable(void)
{
	void test(struct meta2_backend_s * m2, struct oio_url_s * u) {
		GError *err;
		GSList *beans = _create_alias_replicated(m2, u, NULL, 1);
		GRID_DEBUG("TEST nb_beans=%u", g_slist_length(beans));
		for (GSList *l = beans; l; l = l->next) {
			gpointer bean = l->data;
			if(DESCR(bean) == &descr_struct_CHUNKS) {
				beans = g_slist_remove(beans, bean);
				_bean_clean(bean);
				break;
			}
		}
		GRID_DEBUG("TEST nb_beans=%u", g_slist_length(beans));
		GString *message = g_string_new("");
		err = meta2_backend_check_content(m2, beans, message, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_CORRUPTED);
		g_error_free(err);
		g_string_free(message, TRUE);
		_bean_cleanl2(beans);
	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_check_1_missing_bean_plain_copy_reparable(void)
{
	void test(struct meta2_backend_s * m2, struct oio_url_s * u) {
		_init_pool_ec_2cpy_3cpy(m2);
		GError *err;
		GSList *beans_2cpy = _create_alias_replicated(m2, u, "TWOCOPIES", 2);
		GString *message_2cpy = g_string_new("");
		_remove_bean(&beans_2cpy, 1, NULL);
		err = meta2_backend_check_content(m2, beans_2cpy, message_2cpy, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_UNCOMPLETE);
		g_error_free(err);
		gchar *missing_chunks = g_strrstr(message_2cpy->str, "\"missing_chunks\":[0]");
		g_assert_nonnull(missing_chunks);
		_bean_cleanl2(beans_2cpy);
		g_string_free(message_2cpy, TRUE);

		GSList *beans_3cpy = _create_alias_replicated(m2, u, "THREECOPIES", 3);
		GString *message_3cpy = g_string_new("");
		_remove_bean(&beans_3cpy, 1, NULL);
		err = meta2_backend_check_content(m2, beans_3cpy, message_3cpy, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_UNCOMPLETE);
		g_error_free(err);
		missing_chunks = g_strrstr(message_3cpy->str, "\"missing_chunks\":[0]");
		g_assert_nonnull(missing_chunks);
		_bean_cleanl2(beans_3cpy);
		g_string_free(message_3cpy, TRUE);
	}
	_container_wraper_allversions("NS", test);

}

static void
test_content_check_2_missing_bean_plain_copy_reparable(void)
{
	void test(struct meta2_backend_s * m2, struct oio_url_s * u) {
		_init_pool_ec_2cpy_3cpy(m2);
		GError *err;
		GSList *beans_3cpy = _create_alias_replicated(m2, u, "THREECOPIES", 3);
		GString *message_3cpy = g_string_new("");
		_remove_bean(&beans_3cpy, 2, NULL);
		err = meta2_backend_check_content(m2, beans_3cpy, message_3cpy, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_UNCOMPLETE);
		g_error_free(err);
		gchar *missing_chunks = g_strrstr(message_3cpy->str, "\"missing_chunks\":[0,0]");
		g_assert_nonnull(missing_chunks);
		g_slist_free_full(beans_3cpy, _bean_clean);
		g_string_free(message_3cpy, TRUE);

	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_check_missing_bean_plain_copy_irreparable(void)
{
	void test(struct meta2_backend_s * m2, struct oio_url_s * u) {
		_init_pool_ec_2cpy_3cpy(m2);
		GError *err;
		GSList *beans_2cpy = _create_alias_replicated(m2, u, "TWOCOPIES", 2);
		GString *message_2cpy = g_string_new("");
		_remove_bean(&beans_2cpy, 2, NULL);
		err = meta2_backend_check_content(m2, beans_2cpy, message_2cpy, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_CORRUPTED);
		g_error_free(err);
		g_string_free(message_2cpy, TRUE);
		_bean_cleanl2(beans_2cpy);

		GSList *beans_3cpy = _create_alias_replicated(m2, u, "THREECOPIES", 3);
		GString *message_3cpy = g_string_new("");
		_remove_bean(&beans_3cpy, 3, NULL);
		err = meta2_backend_check_content(m2, beans_3cpy, message_3cpy, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_CORRUPTED);
		g_error_free(err);
		_bean_cleanl2(beans_3cpy);
		g_string_free(message_3cpy, TRUE);
	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_check_missing_first_pos(void)
{
	void test(struct meta2_backend_s * m2, struct oio_url_s * u) {
		_init_pool_ec_2cpy_3cpy(m2);
		GError *err;
		GString *message_nocpy = g_string_new("");
		GSList *beans_nocpy = _create_alias_replicated(m2, u, NULL, 1);
		_remove_bean(&beans_nocpy, 1, "0");
		err = meta2_backend_check_content(m2, beans_nocpy, message_nocpy, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_CORRUPTED);
		g_error_free(err);
		_bean_cleanl2(beans_nocpy);
		g_string_free(message_nocpy, TRUE);

		GSList *beans_2cpy = _create_alias_replicated(m2, u, "TWOCOPIES", 2);
		GString *message_2cpy = g_string_new("");
		_remove_bean(&beans_2cpy, 1, "0");
		err = meta2_backend_check_content(m2, beans_2cpy, message_2cpy, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_UNCOMPLETE);
		g_error_free(err);
		_remove_bean(&beans_2cpy, 1, "0");
		err = meta2_backend_check_content(m2, beans_2cpy, message_2cpy, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_CORRUPTED);
		g_error_free(err);
		_bean_cleanl2(beans_2cpy);
		g_string_free(message_2cpy, TRUE);
	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_check_ec_missing_1_chunk(void)
{
	void test(struct meta2_backend_s * m2, struct oio_url_s * u) {
		_init_pool_ec_2cpy_3cpy(m2);
		GError *err;
		GString *message_ec1 = g_string_new("");
		GSList *beans_ec1 = _create_alias_ec(m2, u, "EC", 6, 3);
		_remove_bean(&beans_ec1, 1, NULL);
		err = meta2_backend_check_content(m2, beans_ec1, message_ec1, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_UNCOMPLETE);
		g_error_free(err);
		_bean_cleanl2(beans_ec1);
		g_string_free(message_ec1, TRUE);

		GString *message_ecm  = g_string_new("");
		GSList *beans_ecm = _create_alias_ec(m2, u, "EC", 6, 3);
		int m = 3;
		_remove_bean(&beans_ecm, m, NULL);
		err = meta2_backend_check_content(m2, beans_ecm, message_ecm, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_UNCOMPLETE);
		g_error_free(err);
		_bean_cleanl2(beans_ecm);
		g_string_free(message_ecm, TRUE);

		GString *message_ecm1  = g_string_new("");
		GSList *beans_ecm1 = _create_alias_ec(m2, u, "EC", 6, 3);
		int m1 = m + 1;
		_remove_bean(&beans_ecm1, m1, NULL);
		err = meta2_backend_check_content(m2, beans_ecm1, message_ecm1, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_CORRUPTED);
		g_error_free(err);
		_bean_cleanl2(beans_ecm1);
		g_string_free(message_ecm1, TRUE);
	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_put_prop_get(void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u) {
		GSList *beans;
		guint expected;
		GPtrArray *tmp;
		GError *err;

		CLOCK_START = CLOCK = oio_ext_rand_int();
		DECLARE_M2OP(u);

		/* insert a new alias */
		do {
			beans = _create_alias_replicated(m2, u, NULL, 1);
			err = meta2_backend_put_alias(m2, &op, beans, NULL, NULL);
			g_assert_no_error(err);
			_bean_cleanl2(beans);
		} while (0);

		CHECK_ALIAS_VERSION(m2,&op,CLOCK_START);
		check_list_count(m2,u,1);
		CLOCK ++;

		/* set some properties */
		beans = _props_generate(u, 1, 10);
		err = meta2_backend_set_properties(m2, &op, TRUE, beans, _bean_ignore, NULL);
		g_assert_no_error(err);
		_bean_cleanl2(beans);

		/* versioned or not, a container doesn't generate a new version of the
		 * content when a property is set on it. */
		CHECK_ALIAS_VERSION(m2,&op,CLOCK_START);
		check_list_count(m2,u,1);
		CLOCK ++;

		/* check we got our beans, without the properties */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, &op,
				M2V2_FLAG_ALLVERSION|M2V2_FLAG_NOPROPS,
				_bean_buffer_cb, tmp);
		g_assert_no_error(err);
		expected = 2 + chunks_count;
		GRID_DEBUG("TEST count=%u expected=%u", tmp->len, expected);
		g_assert_cmpuint(tmp->len, ==, expected);
		_bean_cleanv2(tmp);

		/* idem, but with the properties */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, &op, M2V2_FLAG_ALLVERSION,
				_bean_buffer_cb, tmp);
		g_assert_no_error(err);
		expected = 10 + 2 + chunks_count;
		GRID_DEBUG("TEST count=%u expected=%u", tmp->len, expected);
		g_assert_cmpuint(tmp->len, ==, expected);
		_bean_cleanv2(tmp);

		/* delete the bean */
		err = meta2_backend_delete_alias(m2, &op, _bean_ignore, NULL);
		g_assert_no_error(err);
		if (VERSIONS_ENABLED(meta2_max_versions)) {
			CHECK_ALIAS_VERSION(m2,&op,1+CLOCK_START);
			check_list_count(m2,u,2);
		} else {
			check_list_count(m2,u,0);
		}

		/* check we get nothing when looking for a valid version */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, &op, M2V2_FLAG_NODELETED,
				_bean_buffer_cb, tmp);
		g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
		g_clear_error (&err);
		expected = 0;
		GRID_DEBUG("TEST count=%u expected=%u", tmp->len, expected);
		g_assert_cmpuint(tmp->len, ==, expected);
		_bean_cleanv2(tmp);
	}

	_container_wraper_allversions("NS", test);
}

static void
test_content_put_get_delete(void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u) {
		guint expected;
		GPtrArray *tmp;
		GError *err;

		CLOCK_START = CLOCK = oio_ext_rand_int();
		DECLARE_M2OP(u);

		/* insert a new alias */
		do {
			GSList *beans = _create_alias_replicated(m2, u, NULL, 1);
			CLOCK ++;
			err = meta2_backend_put_alias(m2, &op, beans, NULL, NULL);
			g_assert_no_error(err);
			_bean_cleanl2(beans);
		} while (0);

		CHECK_ALIAS_VERSION(m2,&op,CLOCK_START);
		check_list_count(m2,u,1);

		/* check we got our beans */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, &op, M2V2_FLAG_ALLVERSION,
				_bean_buffer_cb, tmp);
		g_assert_no_error(err);
		expected = 2+chunks_count;
		g_assert_cmpuint(tmp->len, ==, expected);
		_bean_cleanv2(tmp);

		check_list_count(m2,u,1);

		/* delete the bean */
		err = meta2_backend_delete_alias(m2, &op, _bean_ignore, NULL);
		g_assert_no_error(err);

		if (VERSIONS_ENABLED(meta2_max_versions)) {
			CHECK_ALIAS_VERSION(m2,&op,1+CLOCK_START);
			check_list_count(m2,u,2);
		} else {
			check_list_count(m2,u,0);
		}

		/* check we get nothing when looking for a valid version */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, &op, M2V2_FLAG_NODELETED,
				_bean_buffer_cb, tmp);
		g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
		g_clear_error (&err);
		g_assert_cmpuint(tmp->len, ==, 0);
		_bean_cleanv2(tmp);

		if (VERSIONS_ENABLED(meta2_max_versions)) {
			check_list_count(m2,u,2);
		} else {
			check_list_count(m2,u,0);
		}

		/* check there are 2 versions */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, &op, M2V2_FLAG_ALLVERSION,
				_bean_buffer_cb, tmp);
		if (VERSIONS_ENABLED(meta2_max_versions)) {
			g_assert_no_error(err);
			// nb_versions * (1 alias + 1 content header + chunks_count * (1 chunk))
			expected = 2 * (2 + chunks_count);
			GRID_DEBUG("TEST Got %u beans for all versions, expected %u"
					" (chunks count: %"G_GINT64_FORMAT")",
					tmp->len, expected, chunks_count);
			g_assert_cmpuint(tmp->len, ==, expected);
		} else {
			g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
			g_clear_error (&err);
			g_assert_cmpuint(tmp->len, ==, 0);
		}
		_bean_cleanv2(tmp);

		/* Check we can force the delete by deleting deleted version */
		if (VERSIONS_ENABLED(meta2_max_versions)) {
			tmp = g_ptr_array_new();
			err = meta2_backend_delete_alias(m2, &op, _bean_ignore, NULL);
			g_assert_no_error(err);
			_bean_cleanv2(tmp);

			CHECK_ALIAS_VERSION(m2,&op,CLOCK_START);
			check_list_count(m2,u,1);
		}
	}

	_container_wraper_allversions("NS", test);
}

static void
test_content_put_lower_version(void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u) {
		GSList *beans = NULL;
		GError *err;

		CLOCK_START = CLOCK = oio_ext_rand_int();
		DECLARE_M2OP(u);

		/* generate the beans for an alias of 3 chunks */
		beans = _create_alias_replicated(m2, u, NULL, 1);

		/* first PUT */
		err = meta2_backend_put_alias(m2, &op, beans, NULL, NULL);
		g_assert_no_error(err);
		CHECK_ALIAS_VERSION(m2, &op, _get_real());
		check_list_count(m2, u, 1);
		_bean_cleanl2(beans);

		/* second PUT, with lower version */
		CLOCK--;
		beans = _create_alias_replicated(m2, u, NULL, 1);
		CLOCK++;
		err = meta2_backend_put_alias(m2, &op, beans, NULL, NULL);
		g_assert_error(err, GQ(), CODE_CONTENT_PRECONDITION);
		_bean_cleanl2(beans);
		g_clear_error(&err);

		CHECK_ALIAS_VERSION(m2, &op, CLOCK_START);
	}
	meta2_max_versions = -1;
	_container_wraper("NS", test);
	/* Would fail for another reason */
	// _container_wraper (ns, 0, cf);
	meta2_max_versions = 1;
	_container_wraper("NS", test);
	meta2_max_versions = 2;
	_container_wraper("NS", test);
}

static void
test_content_append_empty(void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u) {
		DECLARE_M2OP(u);
		GError *err = meta2_backend_append_to_alias(m2, &op, NULL, _bean_ignore, NULL);
		g_assert_error(err, GQ(), CODE_BAD_REQUEST);
		g_clear_error(&err);
	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_append(void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u) {
		GPtrArray *tmp;
		GSList *beans = NULL, *newbeans = NULL;
		GError *err;
		guint expected;

		CLOCK_START = CLOCK = oio_ext_rand_int();
		DECLARE_M2OP(u);

		/* generate the beans for an alias of 3 chunks */
		beans = _create_alias_replicated(m2, u, NULL, 1);

		/* first PUT */
		err = meta2_backend_put_alias(m2, &op, beans, NULL, NULL);
		g_assert_no_error(err);
		CHECK_ALIAS_VERSION(m2,&op,_get_real());
		check_list_count(m2,u,1);

		/* count the beans */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, &op, M2V2_FLAG_ALLVERSION,
				_bean_buffer_cb, tmp);
		g_assert_no_error(err);
		expected = 1 + 1 + chunks_count;
		GRID_DEBUG("Put -> %u beans (ALLVERSION)", tmp->len);
		g_assert_cmpuint(tmp->len, ==, expected);
		_bean_cleanv2(tmp);

		/* append th same chunks */
		tmp = g_ptr_array_new ();
		err = meta2_backend_append_to_alias(m2, &op, beans, _bean_buffer_cb, tmp);
		g_assert_nonnull(err);
		g_clear_error (&err);
		_bean_cleanv2 (tmp);

		/* append new chunks */
		struct oio_url_s *u1 = oio_url_dup(u);
		oio_url_set (u1, OIOURL_PATH, "_");
		newbeans = _create_alias_replicated(m2, u1, NULL, 1);
		oio_url_pclean (&u1);

		tmp = g_ptr_array_new ();
		err = meta2_backend_append_to_alias(m2, &op, newbeans, _bean_buffer_cb, tmp);
		GRID_DEBUG("Append -> %u beans", tmp->len);
		CHECK_ALIAS_VERSION(m2,&op,_get_real());
		check_list_count(m2,u,1);
		_bean_cleanv2 (tmp);

		/* check we got our beans */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, &op, M2V2_FLAG_ALLVERSION,
				_bean_buffer_cb, tmp);
		g_assert_no_error(err);
		expected = 1 /* alias */ + 1 /* headers */
			+ chunks_count  /* original chunks */
			+ chunks_count; /* new chunks appended */
		GRID_DEBUG("TEST After the append, got %u, expected %u", tmp->len, expected);
		g_assert_cmpuint(tmp->len, ==, expected);
		_bean_cleanv2(tmp);

		/* delete the alias */
		err = meta2_backend_delete_alias(m2, &op, _bean_ignore, NULL);
		if (VERSIONS_ENABLED(meta2_max_versions)) {
			g_assert_no_error(err);
			CHECK_ALIAS_VERSION(m2,&op,1+_get_real());
			check_list_count(m2,u,2);
		} else {
			g_assert_no_error(err);
			check_list_count(m2,u,0);
		}

		/* check we get nothing when looking for a valid version */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, &op, M2V2_FLAG_NODELETED, _bean_buffer_cb, tmp);
		g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
		g_clear_error (&err);
		GRID_DEBUG("TEST Found %u beans (NODELETED)", tmp->len);
		g_assert_cmpint(tmp->len, ==, 0);
		_bean_cleanv2(tmp);

		/* check we can get both deleted and previous versions */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, &op, M2V2_FLAG_ALLVERSION, _bean_buffer_cb, tmp);
		GRID_DEBUG("TEST Found %u beans (ALLVERSION)", tmp->len);
		if (VERSIONS_ENABLED(meta2_max_versions)) {
			g_assert_no_error(err);
			expected = 2*(1+1+(2*chunks_count));
		} else {
			g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
			g_clear_error (&err);
			expected = 0;
		}
		g_assert_cmpint(tmp->len, ==, expected);
		_bean_cleanv2(tmp);

		_bean_cleanl2(beans);
		_bean_cleanl2 (newbeans);
	}

	_container_wraper_allversions("NS", test);
}

static void
test_content_truncate (void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u) {
		CLOCK_START = CLOCK = oio_ext_rand_int();
		DECLARE_M2OP(u);

		/* check with an absent content */
		do {
			GSList *deleted = NULL, *added = NULL;
			GError *err = meta2_backend_truncate_content(m2, &op, oio_ns_chunk_size, &deleted, &added);
			g_assert_null(deleted);
			g_assert_null(added);
			g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
			g_clear_error(&err);
		} while (0);

		/* PUT a content */
		do {
			GSList *beans = _create_alias_replicated(m2, u, "NONE", 1);
			GError *err = meta2_backend_put_alias(m2, &op, beans, NULL, NULL);
			g_assert_no_error(err);
			CHECK_ALIAS_VERSION(m2,&op,_get_real());
			check_list_count(m2,u,1);
			_bean_cleanl2(beans);
		} while (0);

		/* check with an invalid size (zero) */
		do {
			GSList *deleted = NULL, *added = NULL;
			GError *err = meta2_backend_truncate_content(m2, &op, 0, &deleted, &added);
			g_assert_null(deleted);
			g_assert_null(added);
			g_assert_error(err, GQ(), CODE_BAD_REQUEST);
			g_clear_error(&err);
		} while (0);

		/* check with an invalid size (negative) */
		do {
			GSList *deleted = NULL, *added = NULL;
			GError *err = meta2_backend_truncate_content(m2, &op, -1, &deleted, &added);
			g_assert_null(deleted);
			g_assert_null(added);
			g_assert_error(err, GQ(), CODE_BAD_REQUEST);
			g_clear_error(&err);
		} while (0);

		/* check with an invalid size (not boundary) */
		do {
			GSList *deleted = NULL, *added = NULL;
			GError *err = meta2_backend_truncate_content(m2, &op, oio_ns_chunk_size - 1, &deleted, &added);
			g_assert_null(deleted);
			g_assert_null(added);
			g_assert_error(err, GQ(), CODE_BAD_REQUEST);
			g_clear_error(&err);
		} while (0);

		/* truncate it to 1 metachunk */
		do {
			GSList *deleted = NULL, *added = NULL;
			GError *err = meta2_backend_truncate_content(m2, &op, oio_ns_chunk_size,
					&deleted, &added);
			g_assert_no_error(err);
			g_assert_cmpint(g_slist_length(added), ==, 2 + 1);
			g_assert_cmpint(g_slist_length(deleted), ==, chunks_count - 1);
			_bean_cleanl2(deleted);
			_bean_cleanl2(added);
		} while (0);
	}

	chunks_count = 4;
	_container_wraper_allversions("NS", test);
}

static void
test_container_full (void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u) {
		CLOCK_START = CLOCK = oio_ext_rand_int();
		DECLARE_M2OP(u);

		void path(gint64 id) {
			gchar tmp[64];
			g_snprintf(tmp, sizeof(tmp), "content-%" G_GINT64_FORMAT, id);
			oio_url_set(u, OIOURL_PATH, tmp);
		}
		GError* put(gint64 id) {
			path(id);
			GRID_DEBUG("%s %s", __FUNCTION__, oio_url_get(u, OIOURL_WHOLE));
			GSList *beans = _create_alias_replicated(m2, u, "NONE", 1);
			GError *err = meta2_backend_put_alias(m2, &op, beans, NULL, NULL);
			_bean_cleanl2(beans);
			return err;
		}
		GError* delete(gint64 id, gboolean last) {
			path(id);
			GRID_DEBUG("%s %s", __FUNCTION__, oio_url_get(u, OIOURL_WHOLE));
			op.flag_last_base = BOOL(last);
			return meta2_backend_delete_alias(m2, &op, _bean_ignore, NULL);
		}
		void delete_ok(gint64 id, gboolean last) {
			g_assert_no_error(delete(id, last));
		}
		void delete_full(gint64 id, gboolean last) {
			GError *err = delete(id, last);
			g_assert_error(err, GQ(), CODE_SHARD_FULL);
			g_clear_error(&err);
		}
		void put_ok(gint64 id) {
			GError *err = put(id);
			g_assert_no_error(err);
			check_list_count(m2,u,id);
		}
		void put_full(gint64 id) {
			GError *err = put(id);
			g_assert_error(err, GQ(), CODE_SHARD_FULL);
			g_clear_error(&err);
			check_list_count(m2,u,meta2_container_max_contents);
		}
		void check_full(void) {
			GError *err = meta2_backend_container_not_full(m2, &op);
			g_assert_error(err, GQ(), CODE_SHARD_FULL);
			g_clear_error(&err);
		}

		/* PUT contents until the container is full */
		for (guint i=1; i<meta2_container_max_contents ;++i) {
			put_ok(i);
			g_assert_no_error(meta2_backend_container_not_full(m2, &op));
		}

		/* the PUT that fills the container */
		do {
			put_ok(meta2_container_max_contents);
			check_full();
		} while (0);

		/* PUT some contents, failure (full) */
		for (guint i=1; i<3 ;++i) {
			put_full(meta2_container_max_contents + i);
			check_full();
		}

		/* DELETE a content, success but still full */
		for (guint i=1; i<meta2_container_max_contents ;++i) {
			delete_full(i, TRUE);
			delete_ok(i, FALSE);
			check_full();
		}
	}

	meta2_container_max_contents = 3;
	_container_wraper_allversions("NS", test);
	meta2_container_max_contents = G_MAXINT64;
}

static void
test_content_append_not_found(void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u) {
		guint expected;
		GPtrArray *tmp;
		GSList *beans = NULL, *newbeans = NULL;
		GError *err;

		CLOCK_START = CLOCK = oio_ext_rand_int();
		DECLARE_M2OP(u);
		beans = _create_alias_replicated(m2, u, NULL, 1);
		CLOCK ++;

		/* first PUT */
		err = meta2_backend_append_to_alias(m2, &op, beans, _bean_ignore, NULL);
		CLOCK ++;
		g_assert_no_error(err);
		CHECK_ALIAS_VERSION(m2,&op,CLOCK_START);

		/* count the beans */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, &op, M2V2_FLAG_ALLVERSION,
				_bean_buffer_cb, tmp);
		CLOCK ++;
		g_assert_no_error(err);
		expected = 1 + 1 + chunks_count;
		g_assert_cmpuint(tmp->len, ==, expected);
		_bean_cleanv2(tmp);

		/* re-APPEND */
		struct oio_url_s *u1 = oio_url_dup(u);
		oio_url_set (u1, OIOURL_PATH, "_");
		newbeans = _create_alias_replicated(m2, u1, NULL, 1);
		CLOCK ++;
		err = meta2_backend_append_to_alias(m2, &op, newbeans, _bean_ignore, NULL);
		g_assert_no_error(err);
		oio_url_pclean (&u1);

		CHECK_ALIAS_VERSION(m2,&op,CLOCK_START);

		/* count the beans */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, &op, M2V2_FLAG_ALLVERSION,
				_bean_buffer_cb, tmp);
		CLOCK ++;
		g_assert_no_error(err);
		expected = 1 /* alias */ + 1 /* headers */
			+ chunks_count /* original chunks+contents */
			+ chunks_count; /* new chunks appended */
		g_assert_cmpuint(tmp->len, ==, expected);
		_bean_cleanv2(tmp);

		/* delete the bean */
		err = meta2_backend_delete_alias(m2, &op, _bean_ignore, NULL);
		CLOCK ++;
		g_assert_no_error(err);
		if (VERSIONS_ENABLED(meta2_max_versions)) {
			CHECK_ALIAS_VERSION(m2,&op,1+CLOCK_START);
		} else {
			check_list_count(m2,u,0);
		}

		/* check we get nothing when looking for a valid version */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, &op, M2V2_FLAG_NODELETED, _bean_buffer_cb, tmp);
		g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
		g_clear_error (&err);
		g_assert_cmpuint(tmp->len, ==, 0);
		_bean_cleanv2(tmp);

		/* check we can get both deleted and previous versions */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, &op, M2V2_FLAG_ALLVERSION, _bean_buffer_cb, tmp);
		if (VERSIONS_ENABLED(meta2_max_versions)) {
			g_assert_no_error(err);
		} else {
			g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
			g_clear_error (&err);
		}
		_bean_cleanv2(tmp);
		_bean_cleanl2(newbeans);
		_bean_cleanl2(beans);
	}
	_container_wraper_allversions("NS", test);
}

static void
test_props_gotchas()
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u) {
		GError *err;
		GSList *beans;

		CLOCK_START = CLOCK = oio_ext_rand_int();
		DECLARE_M2OP(u);

		err = meta2_backend_get_properties(m2, &op, 0, _bean_ignore, NULL);
		g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
		g_clear_error(&err);

		beans = _props_generate(u, 1, 10);
		err = meta2_backend_set_properties(m2, &op, FALSE, beans, _bean_ignore, NULL);
		g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
		g_clear_error(&err);
		_bean_cleanl2(beans);
	}
	_container_wraper_allversions("NS", test);
}

static void
test_props_set_simple()
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u) {
		GError *err;
		GSList *beans;

		CLOCK_START = CLOCK = oio_ext_rand_int();
		DECLARE_M2OP(u);

		/* add a content */
		beans = _create_alias_replicated(m2, u, NULL, 1);
		CLOCK ++;
		err = meta2_backend_put_alias(m2, &op, beans, NULL, NULL);
		CLOCK ++;
		g_assert_no_error(err);
		_bean_cleanl2(beans);

		CHECK_ALIAS_VERSION(m2,&op,CLOCK_START);

		/* set it properties */
		beans = _props_generate(u, 1, 10);
		CLOCK ++;
		err = meta2_backend_set_properties(m2, &op, FALSE, beans, _bean_ignore, NULL);

		CLOCK ++;
		g_assert_no_error(err);
		_bean_cleanl2(beans);

		CHECK_ALIAS_VERSION(m2,&op,CLOCK_START);
	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_dedup (void)
{
	guint num_duplicates = 1;

	void change_chunk_hash(GSList *beans, guint start) {
		guint8 counter = start;
		for (GSList *cursor = beans; cursor; cursor = cursor->next) {
			if (DESCR(cursor->data) == &descr_struct_CHUNKS) {
				GByteArray *hash = CHUNKS_get_hash(cursor->data);
				hash->data[0] = counter;
				CHUNKS_set_hash(cursor->data, hash); // no-op because same pointer
				counter++;
			} else if (DESCR(cursor->data) == &descr_struct_CONTENTS_HEADERS) {
				GByteArray *hash = g_byte_array_sized_new(16);
				for (guint8 i = 0; i < 16; i++) {
					hash->data[i] = i + 1;
				}
				CONTENTS_HEADERS_set_hash(cursor->data, hash);
				g_byte_array_free (hash, TRUE);
			}
		}
	}

	void test(struct meta2_backend_s *m2, struct oio_url_s *url) {
		GError *err;

		do {
			/* Generate a list of beans */
			DECLARE_M2OP(url);
			GSList *beans = _create_alias_replicated(m2, url, NULL, 1);
			/* Change the hash of the chunk beans (0 by default) */
			change_chunk_hash(beans, 0);
			/* Put the beans in the database */
			err = meta2_backend_put_alias(m2, &op, beans, NULL, NULL);
			g_assert_no_error(err);
			_bean_cleanl2(beans);
		} while (0);

		/* Generate other contents with same hashes */
		for (guint counter = 1; counter <= num_duplicates; counter++) {
			/* Suffix the base url */
			struct oio_url_s *url2 = oio_url_dup (url);
			DECLARE_M2OP(url2);
			const char *p0 = oio_url_get (url, OIOURL_PATH);
			if (p0) {
				gchar *p = g_strdup_printf("%s-%u", p0, counter);
				oio_url_set (url2, OIOURL_PATH, p);
				g_free (p);
			}
			GSList *beans2 = _create_alias_replicated(m2, url2, NULL, 1);
			change_chunk_hash(beans2, counter);
			err = meta2_backend_put_alias(m2, &op, beans2, NULL, NULL);
			g_assert_no_error(err);
			_bean_cleanl2(beans2);
			oio_url_pclean (&url2);
		}

		do {
			DECLARE_M2OP(url);
			err = meta2_backend_dedup_contents (m2, &op);
			g_assert_no_error(err);
		} while (0);

		/* TODO check the result of the dedup ;) */
	}
	_container_wraper_allversions("NS", test);
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);

	oio_time_monotonic = _get_monotonic;
	oio_time_real = _get_real;
	container_counter = random();

	g_test_add_func("/meta2v2/backend/init_strange_ns",
			test_backend_strange_ns);
	g_test_add_func("/meta2v2/backend/create_destroy",
			test_backend_create_destroy);
	g_test_add_func("/meta2v2/backend/container/create_destroy",
			test_container_create_destroy);
	g_test_add_func("/meta2v2/backend/container/full",
			test_container_full);
	g_test_add_func("/meta2v2/backend/content/put_nobeans",
			test_content_put_no_beans);
	g_test_add_func("/meta2v2/backend/content/delete_notfound",
			test_content_delete_not_found);
	g_test_add_func("/meta2v2/backend/content/put_get_delete",
			test_content_put_get_delete);
	g_test_add_func("/meta2v2/backend/content/put_lower_version",
			test_content_put_lower_version);
	g_test_add_func("/meta2v2/backend/content/put_prop_get",
			test_content_put_prop_get);
	g_test_add_func("/meta2v2/backend/content/append_empty",
			test_content_append_empty);
	g_test_add_func("/meta2v2/backend/props/set_simple",
			test_props_set_simple);
	g_test_add_func("/meta2v2/backend/props/gotchas",
			test_props_gotchas);
	g_test_add_func("/meta2v2/backend/content/append",
			test_content_append);
	g_test_add_func("/meta2v2/backend/content/truncate",
			test_content_truncate);
	g_test_add_func("/meta2v2/backend/content/append_notfound",
			test_content_append_not_found);
	g_test_add_func("/meta2v2/backend/content/dedup",
			test_content_dedup);
	g_test_add_func("/meta2v2/backend/content/check_all_beans_correct",
			test_content_check_all_beans_correct);
	g_test_add_func("/meta2v2/backend/content/check_1_missing_bean_irreparable",
			test_content_check_1_missing_bean_plain_irreparable);
	g_test_add_func("/meta2v2/backend/content/check_1_missing_bean_reparable",
			test_content_check_1_missing_bean_plain_copy_reparable);
	g_test_add_func("/meta2v2/backend/content/check_2_missing_bean_reparable",
			test_content_check_2_missing_bean_plain_copy_reparable);
	g_test_add_func("/meta2v2/backend/content/check_missing_last_pos",
			test_content_check_missing_bean_plain_copy_irreparable);
	g_test_add_func("/meta2v2/backend/content/check_missing_first_pos",
			test_content_check_missing_first_pos);
	g_test_add_func("/meta2v2/backend/content/check_missing_ec_1_chunk",
			test_content_check_ec_missing_1_chunk);

	return g_test_run();
}


