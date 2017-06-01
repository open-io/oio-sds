/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015-2016 OpenIO, as part of OpenIO Software Defined Storage

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

#include <meta2v2/meta2_macros.h>
#include <meta2v2/meta2_utils.h>
#include <meta2v2/meta2_backend_internals.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>
#include <resolver/hc_resolver.h>

#undef GQ
#define GQ() g_quark_from_static_string("oio.m2v2")

typedef void (*repo_test_f) (struct meta2_backend_s *m2);

typedef void (*container_test_f) (struct meta2_backend_s *m2,
		struct oio_url_s *url, gint64 maxver);

static guint64 container_counter = 0;
static gint64 chunk_size = 3000;
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

static gint64 _get_monotonic (void) { return CLOCK; }

static gint64 _get_real (void) { return CLOCK; }

static gboolean
_versioned(struct meta2_backend_s *m2, struct oio_url_s *u)
{
	gint64 v = 0;
	GError *err = meta2_backend_get_max_versions(m2, u, &v);
	g_assert_no_error(err);
	return VERSIONS_ENABLED(v);
}

static void
_debug_beans_list(GSList *l)
{
	for (; l ;l=l->next) {
		GString *s = _bean_debug(NULL, l->data);
		GRID_DEBUG(" %s", s->str);
		g_string_free(s, TRUE);
	}
}

static void
_debug_beans_array(GPtrArray *v)
{
	guint i;
	for (i=0; i<v->len ;i++) {
		GString *s = _bean_debug(NULL, v->pdata[i]);
		GRID_DEBUG(" %s", s->str);
		g_string_free(s, TRUE);
	}
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

	_debug_beans_list(result);
	return result;
}


static GSList*
_create_alias2(struct meta2_backend_s *m2b, struct oio_url_s *url,
		const gchar *polname, int chunks_per_metachunks)
{
	void _onbean(gpointer u, gpointer bean) {
		*((GSList**)u) = g_slist_prepend(*((GSList**)u), bean);
	}

	GError *err;
	guint expected, generated;
	GSList *beans = NULL;

	g_assert(chunks_count > 1);
	err = meta2_backend_generate_beans(m2b, url, (chunk_size*(chunks_count-1))+1,
			polname, FALSE, _onbean, &beans);
	generated = g_slist_length(beans);
	expected = 1 + 1 + chunks_count * chunks_per_metachunks;
	GRID_DEBUG("BEANS generated=%u expected=%u", generated, expected);
	g_assert_no_error(err);
	g_assert(generated == expected);

	_debug_beans_list(beans);
	return beans;
}

static GSList*
_create_alias(struct meta2_backend_s *m2b, struct oio_url_s *url,
		const gchar *polname)
{
	return _create_alias2(m2b, url, polname, 1);
}

static void
check_list_count(struct meta2_backend_s *m2, struct oio_url_s *url,
		guint expected)
{
	GError *err;
	guint counter = 0;

	void _count (gpointer u, gpointer bean) {
		(void) u, (void) bean;
		counter ++;
		_bean_clean(bean);
	}

	struct list_params_s lp = {0};
	lp.flag_allversion = ~0;

	err = meta2_backend_list_aliases(m2, url, &lp, NULL, _count, NULL, NULL);
	g_assert_no_error(err);
	GRID_DEBUG("TEST list_aliases counter=%u expected=%u", counter, expected);
	g_assert(counter == expected);
}

static struct namespace_info_s *
_init_nsinfo(const gchar *ns, gint64 maxvers)
{
	struct namespace_info_s *nsinfo;
	gchar str[512];

	nsinfo = g_malloc0 (sizeof(*nsinfo));
	namespace_info_init (nsinfo);
	nsinfo->chunk_size = chunk_size;
	g_strlcpy (nsinfo->name, ns, sizeof(nsinfo->name));

	g_snprintf (str, sizeof(str), "%"G_GINT64_FORMAT, maxvers);
	g_hash_table_insert(nsinfo->options, g_strdup("meta2_max_versions"),
			metautils_gba_from_string(str));
	g_hash_table_insert(nsinfo->options, g_strdup("storage_policy"),
			metautils_gba_from_string("NONE"));

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
	oio_lb_world__debug(lb_world);

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
_repo_wrapper(const gchar *ns, gint64 maxvers, repo_test_f fr)
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

	nsinfo = _init_nsinfo(ns, maxvers);
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
_container_wraper(const char *ns, gint64 maxvers, container_test_f cf)
{
	void test(struct meta2_backend_s *m2) {
		struct m2v2_create_params_s params = {NULL, NULL, NULL, FALSE};
		struct oio_url_s *url;
		GError *err;

		gchar *strurl = g_strdup_printf(
				"/%s/account/container-%"G_GUINT64_FORMAT"//content-%"G_GINT64_FORMAT,
				ns, ++container_counter, oio_ext_monotonic_time());
		url = oio_url_init(strurl);
		g_free(strurl);

		err = meta2_backend_create_container(m2, url, &params);
		g_assert_no_error(err);

		if (cf)
			cf(m2, url, maxvers);

		err = meta2_backend_destroy_container (m2, url,
				M2V2_DESTROY_FORCE|M2V2_DESTROY_FLUSH);
		g_assert_no_error (err);

		oio_url_pclean(&url);
	}

	GRID_INFO("--- %"G_GINT64_FORMAT" %s ------------------------------------"
			"-----------------", maxvers, ns);
	_repo_wrapper(ns, maxvers, test);
}

static void
_container_wraper_allversions (const char *ns, container_test_f cf)
{
	_container_wraper (ns, -2, cf);
	_container_wraper (ns, -1, cf);
	_container_wraper (ns, 0, cf);
	_container_wraper (ns, 1, cf);
	_container_wraper (ns, 2, cf);
}

static void
test_backend_create_destroy(void)
{
	_repo_wrapper("NS", 0, NULL);
}

static void
test_backend_strange_ns(void)
{
	char ns[LIMIT_LENGTH_NSNAME+1];

	void test(struct meta2_backend_s *m2) {
		g_assert_cmpstr(m2->ns_name, ==, ns);
	}

	/* empty NS is an error */
	memset(ns, 0, sizeof(ns));
	_repo_failure (ns);

	for (guint len=1; len<LIMIT_LENGTH_NSNAME ;len++) {
		memset(ns, 0, sizeof(ns));
		memset(ns, 'x', len);
		_repo_wrapper(ns, 0, test);
	}

	/* too long NS is an error */
	memset(ns, 0, sizeof(ns));
	memset(ns, 'x', sizeof(ns)-1);
	_repo_failure(ns);
}

static void
test_container_create_destroy(void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u, gint64 maxver) {
		g_assert (VERSIONS_ENABLED(maxver) == _versioned(m2, u));
	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_delete_not_found(void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u, gint64 maxver) {
		(void) maxver;
		GError *err = meta2_backend_delete_alias(m2, u, NULL, NULL);
		g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
		g_clear_error(&err);
	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_put_no_beans(void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u, gint64 maxver) {
		(void) maxver;
		GError *err = meta2_backend_put_alias(m2, u, NULL, NULL, NULL);
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
	void test(struct meta2_backend_s * m2, struct oio_url_s * u, gint64 maxver) {
		(void) maxver;
		_init_pool_ec_2cpy_3cpy(m2);
		GError *err;
		GSList *beans_3cpy = _create_alias2(m2, u, "THREECOPIES", 3);
		GString *message = g_string_new("");
		err = meta2_backend_check_content(m2, beans_3cpy, message, false);
		g_string_free(message, TRUE);
		_bean_cleanl2(beans_3cpy);
		g_assert_no_error(err);

		GSList *beans_2cpy = _create_alias2(m2, u, "TWOCOPIES", 2);
		message = g_string_new("");
		err = meta2_backend_check_content(m2, beans_2cpy, message, false);
		g_string_free(message, TRUE);
		_bean_cleanl2(beans_2cpy);
		g_assert_no_error(err);

		message = g_string_new("");
		GSList *beans_ec = _create_alias2(m2, u, "EC", 3);
		err = meta2_backend_check_content(m2, beans_ec, message, false);
		g_string_free(message, TRUE);
		_bean_cleanl2(beans_ec);
		g_assert_no_error(err);

	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_check_1_missing_bean_plain_irreparable(void)
{
	void test(struct meta2_backend_s * m2, struct oio_url_s * u, gint64 maxver) {
		(void) maxver;
		GError *err;
		GSList *beans = _create_alias(m2, u, NULL);
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
		err = meta2_backend_check_content(m2, beans, message, false);
		g_string_free(message, TRUE);
		g_assert_error(err, GQ(), CODE_CONTENT_CORRUPTED);
		_bean_cleanl2(beans);
	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_check_1_missing_bean_plain_copy_reparable(void)
{
	void test(struct meta2_backend_s * m2, struct oio_url_s * u, gint64 maxver) {
		(void) maxver;
		_init_pool_ec_2cpy_3cpy(m2);
		GError *err;
		GSList *beans_2cpy = _create_alias2(m2, u, "TWOCOPIES", 2);
		GString *message_2cpy = g_string_new("");
		_remove_bean(&beans_2cpy, 1, NULL);
		err = meta2_backend_check_content(m2, beans_2cpy, message_2cpy, false);
		g_assert_error(err, GQ(), CODE_CONTENT_UNCOMPLETE);
		gchar *missing_chunks = g_strrstr(message_2cpy->str, "\"missing_chunks\":[2]");
		g_assert_nonnull(missing_chunks);
		_bean_cleanl2(beans_2cpy);
		g_string_free(message_2cpy, TRUE);

		GSList *beans_3cpy = _create_alias2(m2, u, "THREECOPIES", 3);
		GString *message_3cpy = g_string_new("");
		_remove_bean(&beans_3cpy, 1, NULL);
		err = meta2_backend_check_content(m2, beans_3cpy, message_3cpy, false);
		g_assert_error(err, GQ(), CODE_CONTENT_UNCOMPLETE);
		missing_chunks = g_strrstr(message_3cpy->str, "\"missing_chunks\":[2]");
		g_assert_nonnull(missing_chunks);
		_bean_cleanl2(beans_3cpy);
		g_string_free(message_3cpy, TRUE);
	}
	_container_wraper_allversions("NS", test);

}

static void
test_content_check_2_missing_bean_plain_copy_reparable(void)
{
	void test(struct meta2_backend_s * m2, struct oio_url_s * u, gint64 maxver) {
		(void) maxver;
		_init_pool_ec_2cpy_3cpy(m2);
		GError *err;
		GSList *beans_3cpy = _create_alias2(m2, u, "THREECOPIES", 3);
		GString *message_3cpy = g_string_new("");
		_remove_bean(&beans_3cpy, 2, NULL);
		err = meta2_backend_check_content(m2, beans_3cpy, message_3cpy, false);
		g_assert_error(err, GQ(), CODE_CONTENT_UNCOMPLETE);
		GRID_DEBUG("%s", message_3cpy->str);
		gchar *missing_chunks = g_strrstr(message_3cpy->str, "\"missing_chunks\":[2,2]");
		g_assert_nonnull(missing_chunks);
		g_slist_free_full(beans_3cpy, _bean_clean);
		g_string_free(message_3cpy, TRUE);

	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_check_missing_bean_plain_copy_irreparable(void)
{
	void test(struct meta2_backend_s * m2, struct oio_url_s * u, gint64 maxver) {
		(void) maxver;
		_init_pool_ec_2cpy_3cpy(m2);
		GError *err;
		GSList *beans_2cpy = _create_alias2(m2, u, "TWOCOPIES", 2);
		GString *message_2cpy = g_string_new("");
		_remove_bean(&beans_2cpy, 2, NULL);
		err = meta2_backend_check_content(m2, beans_2cpy, message_2cpy, false);
		g_assert_error(err, GQ(), CODE_CONTENT_CORRUPTED);
		g_string_free(message_2cpy, TRUE);
		_bean_cleanl2(beans_2cpy);

		GSList *beans_3cpy = _create_alias2(m2, u, "THREECOPIES", 3);
		GString *message_3cpy = g_string_new("");
		_remove_bean(&beans_3cpy, 3, NULL);
		err = meta2_backend_check_content(m2, beans_3cpy, message_3cpy, false);
		g_assert_error(err, GQ(), CODE_CONTENT_CORRUPTED);
		_bean_cleanl2(beans_3cpy);
		g_string_free(message_3cpy, TRUE);
	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_check_missing_first_pos(void)
{
	void test(struct meta2_backend_s * m2, struct oio_url_s * u, gint64 maxver) {
		(void) maxver;
		_init_pool_ec_2cpy_3cpy(m2);
		GError *err;
		GString *message_nocpy = g_string_new("");
		GSList *beans_nocpy = _create_alias(m2, u, NULL);
		_remove_bean(&beans_nocpy, 1, "0");
		err = meta2_backend_check_content(m2, beans_nocpy, message_nocpy, false);
		g_assert_error(err, GQ(), CODE_CONTENT_CORRUPTED);
		_bean_cleanl2(beans_nocpy);
		g_string_free(message_nocpy, TRUE);

		GSList *beans_2cpy = _create_alias2(m2, u, "TWOCOPIES", 2);
		GString *message_2cpy = g_string_new("");
		_remove_bean(&beans_2cpy, 1, "0");
		err = meta2_backend_check_content(m2, beans_2cpy, message_2cpy, false);
		g_assert_error(err, GQ(), CODE_CONTENT_UNCOMPLETE);
		_remove_bean(&beans_2cpy, 1, "0");
		err = meta2_backend_check_content(m2, beans_2cpy, message_2cpy, false);
		g_assert_error(err, GQ(), CODE_CONTENT_CORRUPTED);
		_bean_cleanl2(beans_2cpy);
		g_string_free(message_2cpy, TRUE);
	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_check_ec_missing_1_chunk(void)
{
	void test(struct meta2_backend_s * m2, struct oio_url_s * u, gint64 maxver) {
		(void) maxver;
		_init_pool_ec_2cpy_3cpy(m2);
		GError *err;
		GString *message_ec1 = g_string_new("");
		GSList *beans_ec1 = _create_alias2(m2, u, "EC", 3);
		_remove_bean(&beans_ec1, 1, NULL);
		err = meta2_backend_check_content(m2, beans_ec1, message_ec1, false);
		g_assert_error(err, GQ(), CODE_CONTENT_UNCOMPLETE);
		_bean_cleanl2(beans_ec1);
		g_string_free(message_ec1, TRUE);

		GString *message_ecm  = g_string_new("");
		GSList *beans_ecm = _create_alias2(m2, u, "EC", 3);
		int m = 3;
		_remove_bean(&beans_ecm, m, NULL);
		err = meta2_backend_check_content(m2, beans_ecm, message_ecm, false);
		g_assert_error(err, GQ(), CODE_CONTENT_UNCOMPLETE);
		_bean_cleanl2(beans_ecm);
		g_string_free(message_ecm, TRUE);

		GString *message_ecm1  = g_string_new("");
		GSList *beans_ecm1 = _create_alias2(m2, u, "EC", 3);
		int m1 = m + 1;
		_remove_bean(&beans_ecm1, m1, NULL);
		err = meta2_backend_check_content(m2, beans_ecm1, message_ecm1, false);
		g_assert_error(err, GQ(), CODE_CONTENT_CORRUPTED);
		_bean_cleanl2(beans_ecm1);
		g_string_free(message_ecm1, TRUE);
	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_put_prop_get(void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u, gint64 maxver) {
		GSList *beans;
		guint expected;
		GPtrArray *tmp;
		GError *err;

		CLOCK_START = CLOCK = oio_ext_rand_int();

		/* insert a new alias */
		do {
			beans = _create_alias(m2, u, NULL);
			err = meta2_backend_put_alias(m2, u, beans, NULL, NULL);
			g_assert_no_error(err);
			_bean_cleanl2(beans);
		} while (0);

		CHECK_ALIAS_VERSION(m2,u,CLOCK_START);
		check_list_count(m2,u,1);
		CLOCK ++;

		/* set some properties */
		beans = _props_generate(u, 1, 10);
		err = meta2_backend_set_properties(m2, u, TRUE, beans, NULL, NULL);
		g_assert_no_error(err);
		_bean_cleanl2(beans);

		/* versioned or not, a container doesn't generate a new version of the
		 * content when a property is set on it. */
		CHECK_ALIAS_VERSION(m2,u,CLOCK_START);
		check_list_count(m2,u,1);
		CLOCK ++;

		/* check we got our beans, without the properties */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u,
				M2V2_FLAG_ALLVERSION|M2V2_FLAG_NOPROPS,
				_bean_buffer_cb, tmp);
		g_assert_no_error(err);
		expected = 2 + chunks_count;
		GRID_DEBUG("TEST count=%u expected=%u", tmp->len, expected);
		_debug_beans_array(tmp);
		g_assert(tmp->len == expected);
		_bean_cleanv2(tmp);

		/* idem, but with the properties */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_ALLVERSION,
				_bean_buffer_cb, tmp);
		g_assert_no_error(err);
		expected = 10 + 2 + chunks_count;
		GRID_DEBUG("TEST count=%u expected=%u", tmp->len, expected);
		_debug_beans_array(tmp);
		g_assert(tmp->len == expected);
		_bean_cleanv2(tmp);

		/* delete the bean */
		err = meta2_backend_delete_alias(m2, u, NULL, NULL);
		g_assert_no_error(err);
		if (VERSIONS_ENABLED(maxver)) {
			CHECK_ALIAS_VERSION(m2,u,1+CLOCK_START);
			check_list_count(m2,u,2);
		} else {
			check_list_count(m2,u,0);
		}

		/* check we get nothing when looking for a valid version */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_NODELETED,
				_bean_buffer_cb, tmp);
		g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
		g_clear_error (&err);
		expected = 0;
		GRID_DEBUG("TEST count=%u expected=%u", tmp->len, expected);
		g_assert(tmp->len == expected);
		_bean_cleanv2(tmp);
	}

	_container_wraper_allversions("NS", test);
}

static void
test_content_put_get_delete(void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u, gint64 maxver) {
		guint expected;
		GPtrArray *tmp;
		GError *err;

		CLOCK_START = CLOCK = oio_ext_rand_int();

		/* insert a new alias */
		do {
			GSList *beans = _create_alias(m2, u, NULL);
			CLOCK ++;
			err = meta2_backend_put_alias(m2, u, beans, NULL, NULL);
			g_assert_no_error(err);
			_bean_cleanl2(beans);
		} while (0);

		CHECK_ALIAS_VERSION(m2,u,CLOCK_START);
		check_list_count(m2,u,1);

		/* check we got our beans */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_ALLVERSION,
				_bean_buffer_cb, tmp);
		g_assert_no_error(err);
		expected = 2+chunks_count;
		g_assert(tmp->len == expected);
		_bean_cleanv2(tmp);

		check_list_count(m2,u,1);

		/* delete the bean */
		err = meta2_backend_delete_alias(m2, u, NULL, NULL);
		g_assert_no_error(err);

		if (VERSIONS_ENABLED(maxver)) {
			CHECK_ALIAS_VERSION(m2,u,1+CLOCK_START);
			check_list_count(m2,u,2);
		} else {
			check_list_count(m2,u,0);
		}

		/* check we get nothing when looking for a valid version */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_NODELETED,
				_bean_buffer_cb, tmp);
		g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
		g_clear_error (&err);
		g_assert(tmp->len == 0);
		_bean_cleanv2(tmp);

		if (VERSIONS_ENABLED(maxver)) {
			check_list_count(m2,u,2);
		} else {
			check_list_count(m2,u,0);
		}

		/* check there are 2 versions */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_ALLVERSION,
				_bean_buffer_cb, tmp);
		if (VERSIONS_ENABLED(maxver)) {
			g_assert_no_error(err);
			// nb_versions * (1 alias + 1 content header + chunks_count * (1 chunk))
			expected = 2 * (2 + chunks_count);
			GRID_DEBUG("TEST Got %u beans for all versions, expected %u"
					" (chunks count: %"G_GINT64_FORMAT")",
					tmp->len, expected, chunks_count);
			g_assert(tmp->len == expected);
		} else {
			g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
			g_clear_error (&err);
			g_assert(tmp->len == 0);
		}
		_bean_cleanv2(tmp);

		/* Check we can force the delete by deleting deleted version */
		if (VERSIONS_ENABLED(maxver)) {
			tmp = g_ptr_array_new();
			err = meta2_backend_delete_alias(m2, u, NULL, NULL);
			g_assert_no_error(err);
			_bean_cleanv2(tmp);

			CHECK_ALIAS_VERSION(m2,u,CLOCK_START);
			check_list_count(m2,u,1);
		}
	}

	_container_wraper_allversions("NS", test);
}

static void
test_content_append_empty(void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u, gint64 maxver) {
		(void) maxver;
		GError *err = meta2_backend_append_to_alias(m2, u, NULL, NULL, NULL);
		g_assert_error(err, GQ(), CODE_BAD_REQUEST);
		g_clear_error(&err);
	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_append(void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u, gint64 maxver) {
		(void) maxver;
		GPtrArray *tmp;
		GSList *beans = NULL, *newbeans = NULL;
		GError *err;
		guint expected;

		CLOCK_START = CLOCK = oio_ext_rand_int();

		/* generate the beans for an alias of 3 chunks */
		beans = _create_alias(m2, u, NULL);

		/* first PUT */
		err = meta2_backend_put_alias(m2, u, beans, NULL, NULL);
		g_assert_no_error(err);
		CHECK_ALIAS_VERSION(m2,u,_get_real());
		check_list_count(m2,u,1);

		/* count the beans */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_ALLVERSION,
				_bean_buffer_cb, tmp);
		g_assert_no_error(err);
		expected = 1 + 1 + chunks_count;
		GRID_DEBUG("Put -> %u beans (ALLVERSION)", tmp->len);
		//_debug_beans_array (tmp);
		g_assert(tmp->len == expected);
		_bean_cleanv2(tmp);

		/* append th same chunks */
		tmp = g_ptr_array_new ();
		err = meta2_backend_append_to_alias(m2, u, beans, _bean_buffer_cb, tmp);
		g_assert(err != NULL);
		g_clear_error (&err);
		_bean_cleanv2 (tmp);

		/* append new chunks */
		struct oio_url_s *u1 = oio_url_dup(u);
		oio_url_set (u1, OIOURL_PATH, "_");
		newbeans = _create_alias(m2, u1, NULL);
		oio_url_pclean (&u1);

		tmp = g_ptr_array_new ();
		err = meta2_backend_append_to_alias(m2, u, newbeans, _bean_buffer_cb, tmp);
		GRID_DEBUG("Append -> %u beans", tmp->len);
		//_debug_beans_array (tmp);
		CHECK_ALIAS_VERSION(m2,u,_get_real());
		check_list_count(m2,u,1);
		_bean_cleanv2 (tmp);

		/* check we got our beans */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_ALLVERSION,
				_bean_buffer_cb, tmp);
		g_assert_no_error(err);
		expected = 1 /* alias */ + 1 /* headers */
			+ chunks_count  /* original chunks */
			+ chunks_count; /* new chunks appended */
		GRID_DEBUG("TEST After the append, got %u, expected %u", tmp->len, expected);
		g_assert(tmp->len == expected);
		_bean_cleanv2(tmp);

		/* delete the alias */
		err = meta2_backend_delete_alias(m2, u, NULL, NULL);
		if (VERSIONS_ENABLED(maxver)) {
			g_assert_no_error(err);
			CHECK_ALIAS_VERSION(m2,u,1+_get_real());
			check_list_count(m2,u,2);
		} else {
			g_assert_no_error(err);
			check_list_count(m2,u,0);
		}

		/* check we get nothing when looking for a valid version */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_NODELETED, _bean_buffer_cb, tmp);
		g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
		g_clear_error (&err);
		GRID_DEBUG("TEST Found %u beans (NODELETED)", tmp->len);
		g_assert_cmpint(tmp->len, ==, 0);
		_bean_cleanv2(tmp);

		/* check we can get both deleted and previous versions */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_ALLVERSION, _bean_buffer_cb, tmp);
		GRID_DEBUG("TEST Found %u beans (ALLVERSION)", tmp->len);
		if (VERSIONS_ENABLED(maxver)) {
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
test_content_append_not_found(void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u, gint64 maxver) {
		guint expected;
		GPtrArray *tmp;
		GSList *beans = NULL, *newbeans = NULL;
		GError *err;

		CLOCK_START = CLOCK = oio_ext_rand_int();
		beans = _create_alias(m2, u, NULL);
		CLOCK ++;

		/* first PUT */
		err = meta2_backend_append_to_alias(m2, u, beans, NULL, NULL);
		CLOCK ++;
		g_assert_no_error(err);
		CHECK_ALIAS_VERSION(m2,u,CLOCK_START);

		/* count the beans */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_ALLVERSION,
				_bean_buffer_cb, tmp);
		CLOCK ++;
		g_assert_no_error(err);
		expected = 1 + 1 + chunks_count;
		g_assert(tmp->len == expected);
		_bean_cleanv2(tmp);

		/* re-APPEND */
		struct oio_url_s *u1 = oio_url_dup(u);
		oio_url_set (u1, OIOURL_PATH, "_");
		newbeans = _create_alias(m2, u1, NULL);
		CLOCK ++;
		err = meta2_backend_append_to_alias(m2, u, newbeans, NULL, NULL);
		g_assert_no_error(err);
		oio_url_pclean (&u1);

		CHECK_ALIAS_VERSION(m2,u,CLOCK_START);

		/* count the beans */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_ALLVERSION,
				_bean_buffer_cb, tmp);
		CLOCK ++;
		g_assert_no_error(err);
		expected = 1 /* alias */ + 1 /* headers */
			+ chunks_count /* original chunks+contents */
			+ chunks_count; /* new chunks appended */
		g_assert(tmp->len == expected);
		_bean_cleanv2(tmp);

		/* delete the bean */
		err = meta2_backend_delete_alias(m2, u, NULL, NULL);
		CLOCK ++;
		g_assert_no_error(err);
		if (VERSIONS_ENABLED(maxver)) {
			CHECK_ALIAS_VERSION(m2,u,1+CLOCK_START);
		} else {
			check_list_count(m2,u,0);
		}

		/* check we get nothing when looking for a valid version */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_NODELETED, _bean_buffer_cb, tmp);
		g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
		g_clear_error (&err);
		g_assert(tmp->len == 0);
		_bean_cleanv2(tmp);

		/* check we can get both deleted and previous versions */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_ALLVERSION, _bean_buffer_cb, tmp);
		if (VERSIONS_ENABLED(maxver)) {
			g_assert_no_error(err);
		} else {
			g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
			g_clear_error (&err);
		}
		_debug_beans_array(tmp);
		_bean_cleanv2(tmp);
		_bean_cleanl2(newbeans);
		_bean_cleanl2(beans);
	}
	_container_wraper_allversions("NS", test);
}

static void
test_props_gotchas()
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u, gint64 maxver) {
		GError *err;
		GSList *beans;
		(void) maxver;

		err = meta2_backend_get_properties(m2, u, 0, NULL, NULL);
		g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
		g_clear_error(&err);

		beans = _props_generate(u, 1, 10);
		err = meta2_backend_set_properties(m2, u, FALSE, beans, NULL, NULL);
		g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
		g_clear_error(&err);
		_bean_cleanl2(beans);
	}
	_container_wraper_allversions("NS", test);
}

static void
test_props_set_simple()
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u, gint64 maxver) {
		GError *err;
		GSList *beans;
		(void) maxver;

		CLOCK_START = CLOCK = oio_ext_rand_int();

		/* add a content */
		beans = _create_alias(m2, u, NULL);
		CLOCK ++;
		err = meta2_backend_put_alias(m2, u, beans, NULL, NULL);
		CLOCK ++;
		g_assert_no_error(err);
		_bean_cleanl2(beans);

		CHECK_ALIAS_VERSION(m2,u,CLOCK_START);

		/* set it properties */
		beans = _props_generate(u, 1, 10);
		CLOCK ++;
		err = meta2_backend_set_properties(m2, u, FALSE, beans, NULL, NULL);
		CLOCK ++;
		g_assert_no_error(err);
		_bean_cleanl2(beans);

		CHECK_ALIAS_VERSION(m2,u,CLOCK_START);
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
				GRID_INFO("---- forging content hash ----");
				for (guint8 i = 0; i < 16; i++) {
					hash->data[i] = i + 1;
				}
				CONTENTS_HEADERS_set_hash(cursor->data, hash);
				g_byte_array_free (hash, TRUE);
			}
		}
	}

	void test(struct meta2_backend_s *m2, struct oio_url_s *url, gint64 maxver) {
		GError *err;
		(void) maxver;
		/* Generate a list of beans */
		GSList *beans = _create_alias(m2, url, NULL);
		/* Change the hash of the chunk beans (0 by default) */
		change_chunk_hash(beans, 0);
		/* Put the beans in the database */
		err = meta2_backend_put_alias(m2, url, beans, NULL, NULL);
		g_assert_no_error(err);
		_bean_cleanl2(beans);

		/* Generate other contents with same hashes */
		for (guint counter = 1; counter <= num_duplicates; counter++) {
			/* Suffix the base url */
			struct oio_url_s *url2 = oio_url_dup (url);
			const char *p0 = oio_url_get (url, OIOURL_PATH);
			if (p0) {
				gchar *p = g_strdup_printf("%s-%u", p0, counter);
				oio_url_set (url2, OIOURL_PATH, p);
				g_free (p);
			}
			GSList *beans2 = _create_alias(m2, url2, NULL);
			change_chunk_hash(beans2, counter);
			err = meta2_backend_put_alias(m2, url2, beans2, NULL, NULL);
			g_assert_no_error(err);
			_bean_cleanl2(beans2);
			oio_url_pclean (&url2);
		}

		err = meta2_backend_dedup_contents (m2, url);
		g_assert_no_error(err);

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
	g_test_add_func("/meta2v2/backend/content/put_nobeans",
			test_content_put_no_beans);
	g_test_add_func("/meta2v2/backend/content/delete_notfound",
			test_content_delete_not_found);
	g_test_add_func("/meta2v2/backend/content/put_get_delete",
			test_content_put_get_delete);
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


