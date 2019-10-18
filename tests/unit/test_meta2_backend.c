/*
OpenIO SDS unit tests
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

#include <string.h>
#include <glib.h>

#include <metautils/lib/common_variables.h>
#include <meta2v2/meta2_macros.h>
#include <meta2v2/meta2_utils.h>
#include <meta2v2/meta2_backend_internals.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>
#include <resolver/hc_resolver.h>
#include <cluster/lib/gridcluster.h>

#undef GQ
#define GQ() g_quark_from_static_string("oio.m2v2")

typedef void (*repo_test_f) (struct meta2_backend_s *m2);

typedef void (*container_test_f) (struct meta2_backend_s *m2,
		struct oio_url_s *url, gint64 maxver);

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

static gint64 _get_monotonic (void) { return CLOCK; }

static gint64 _get_real (void) { return CLOCK; }

static gint64
_version(struct meta2_backend_s *m2, struct oio_url_s *u)
{
	gint64 v = 0;
	GError *err = meta2_backend_get_max_versions(m2, u, &v);
	g_assert_no_error(err);
	return v;
}

static gboolean
_versioned(struct meta2_backend_s *m2, struct oio_url_s *u)
{
	const gint64 v = _version(m2, u);
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
	GSList *properties = NULL;
	void _onbean(gpointer u, gpointer bean) {
		if (DESCR(bean) == &descr_struct_PROPERTIES)
			properties = g_slist_prepend(properties, bean);
		else
			*((GSList**)u) = g_slist_prepend(*((GSList**)u), bean);
	}

	GError *err;
	guint expected, generated, expected_props, generated_props;
	GSList *beans = NULL;

	g_assert(chunks_count > 1);
	gint64 size;
	if (g_strcmp0(polname, "EC") == 0) {
		size = (6 * oio_ns_chunk_size * (chunks_count - 1)) + 1;
	} else {
		size = (oio_ns_chunk_size * (chunks_count - 1)) + 1;
	}
	err = meta2_backend_generate_beans(m2b, url, size, polname, FALSE,
			_onbean, &beans);
	generated = g_slist_length(beans);
	generated_props = g_slist_length(properties);
	expected = 1 + 1 + chunks_count * chunks_per_metachunks;
	expected_props = chunks_count * chunks_per_metachunks;
	GRID_DEBUG("BEANS policy=%s generated=%u expected=%u properties=%u",
			polname, generated, expected, generated_props);
	_bean_debugl2(__FUNCTION__, beans);
	g_assert_no_error(err);
	g_assert_cmpuint(generated, ==, expected);
	g_assert_cmpuint(generated_props, ==, expected_props);

	_debug_beans_list(beans);
	_debug_beans_list(properties);
	_bean_cleanl2(properties);
	return beans;
}

static GSList*
_create_alias(struct meta2_backend_s *m2b, struct oio_url_s *url,
		const gchar *polname)
{
	if (polname) {
		struct storage_policy_s *pol =
				storage_policy_init(m2b->nsinfo, polname);
		gint64 nb_chunks = storage_policy_get_nb_chunks(pol);
		storage_policy_clean(pol);
		return _create_alias2(m2b, url, polname, nb_chunks);
	} else {
		return _create_alias2(m2b, url, "SINGLE", 1);
	}
}

static void
_set_content_id(struct oio_url_s *url) {
	guint32 binid[4];
	for (gsize i = 0; i < 4; i++)
		binid[i] = oio_ext_rand_int();
	gchar content_id[33];
	oio_str_bin2hex(binid, sizeof(binid), content_id, sizeof(content_id));
	oio_url_set(url, OIOURL_CONTENTID, content_id);
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

	nsinfo = g_malloc0 (sizeof(*nsinfo));
	namespace_info_init (nsinfo);
	g_strlcpy (nsinfo->name, ns, sizeof(nsinfo->name));

	gchar tmp[32];
	g_snprintf(tmp, sizeof(tmp), "%" G_GINT64_FORMAT, maxvers);
	g_assert_true(oio_var_value_one("meta2.max_versions", tmp));

	g_hash_table_insert(nsinfo->storage_policy, g_strdup("SINGLE"),
			metautils_gba_from_string("rawx:NONE"));
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
	memset(item->addr, 0, sizeof(item->addr));
	for (int i = 0; i < nb_services; i++) {
		item->location = 65536 + 6000 + i;
		item->weight = 50;
		g_snprintf(item->id, LIMIT_LENGTH_SRVID, "127.0.0.1:%d", 6000+i);
		oio_lb_world__feed_slot(lb_world, "*", item);
	}
	oio_lb_world__purge_old_generations(lb_world);
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

	resolver = hc_resolver_create(conscience_locate_meta0);
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

	resolver = hc_resolver_create(conscience_locate_meta0);
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
		struct m2v2_create_params_s params = {0};
		struct oio_url_s *url;
		GError *err;

		gchar *strurl = g_strdup_printf(
				"/%s/account/container-%"G_GUINT64_FORMAT"//content-%"G_GINT64_FORMAT,
				ns, ++container_counter, oio_ext_monotonic_time());
		url = oio_url_init(strurl);
		g_free(strurl);
		_set_content_id(url);

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
		g_assert_cmpint(maxver, ==, _version(m2, u));
		g_assert_cmpint(VERSIONS_ENABLED(maxver), ==, _versioned(m2, u));
	}
	_container_wraper_allversions("NS", test);
}

static void
test_container_flush(void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u, gint64 maxver) {
		(void) maxver;
		GPtrArray *tmp;
		GSList *beans = NULL;
		GError *err;

		CLOCK_START = CLOCK = oio_ext_rand_int();

		/* generate the beans for an alias of 3 chunks */
		beans = _create_alias(m2, u, NULL);

		/* PUT */
		err = meta2_backend_put_alias(m2, u, beans, 0,
				NULL, NULL, NULL, NULL);
		g_assert_no_error(err);
		CHECK_ALIAS_VERSION(m2,u,_get_real());
		check_list_count(m2,u,1);

		/* flush the container */
		gboolean truncated = FALSE;
		err = meta2_backend_flush_container(m2, u, NULL, NULL, &truncated);
		g_assert_no_error(err);
		g_assert(!truncated);
		check_list_count(m2, u, 0);

		/* check we get nothing when looking for a valid version */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_NODELETED, _bean_buffer_cb, tmp);
		g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
		g_clear_error(&err);
		GRID_DEBUG("TEST Found %u beans (NODELETED)", tmp->len);
		g_assert_cmpint(tmp->len, ==, 0);
		_bean_cleanv2(tmp);

		_bean_cleanl2(beans);
	}

	_container_wraper_allversions("NS", test);
}

static void
test_content_delete_not_found(void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u, gint64 maxver) {
		(void) maxver;
		GError *err = meta2_backend_delete_alias(m2, u, FALSE, NULL, NULL);
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
		GError *err = meta2_backend_put_alias(m2, u, NULL, 0,
				NULL, NULL, NULL, NULL);
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
test_content_check_plain_all_present_chunks(void)
{
	void test(struct meta2_backend_s * m2, struct oio_url_s * u, gint64 maxver) {
		(void) maxver;
		_init_pool_ec_2cpy_3cpy(m2);
		GError *err;

		GSList *beans_nocpy = _create_alias(m2, u, NULL);
		gint64 nb_missing_chunks = 0;
		err = meta2_backend_check_content(m2, u, &beans_nocpy,
				&nb_missing_chunks, NULL, FALSE);
		_bean_cleanl2(beans_nocpy);
		g_assert_no_error(err);
		g_assert_cmpint(0, ==, nb_missing_chunks);

		GSList *beans_3cpy = _create_alias2(m2, u, "THREECOPIES", 3);
		nb_missing_chunks = 0;
		err = meta2_backend_check_content(m2, u, &beans_3cpy,
				&nb_missing_chunks, NULL, FALSE);
		_bean_cleanl2(beans_3cpy);
		g_assert_no_error(err);
		g_assert_cmpint(0, ==, nb_missing_chunks);

		GSList *beans_2cpy = _create_alias2(m2, u, "TWOCOPIES", 2);
		nb_missing_chunks = 0;
		err = meta2_backend_check_content(m2, u, &beans_2cpy,
				&nb_missing_chunks, NULL, FALSE);
		_bean_cleanl2(beans_2cpy);
		g_assert_no_error(err);
		g_assert_cmpint(0, ==, nb_missing_chunks);
	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_check_plain_missing_chunks_reparable(void)
{
	void test(struct meta2_backend_s * m2, struct oio_url_s * u, gint64 maxver) {
		(void) maxver;
		_init_pool_ec_2cpy_3cpy(m2);
		GError *err;
		GString *gmessage = g_string_new("");
		void _save_message(gchar *message, gpointer udata UNUSED) {
			g_string_append(gmessage, message);
			g_free(message);
		}
		gint64 nb_missing_chunks = 0;

		GSList *beans_2cpy = _create_alias2(m2, u, "TWOCOPIES", 2);
		_remove_bean(&beans_2cpy, 1, "2");
		err = meta2_backend_check_content(m2, u, &beans_2cpy,
				&nb_missing_chunks, _save_message, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_UNCOMPLETE);
		g_error_free(err);
		gchar *missing_chunks = g_strrstr(gmessage->str,
				"\"missing_chunks\":[\"2\"]");
		g_assert_nonnull(missing_chunks);
		g_assert_cmpint(1, ==, nb_missing_chunks);
		_bean_cleanl2(beans_2cpy);

		GSList *beans_3cpy = _create_alias2(m2, u, "THREECOPIES", 3);
		_remove_bean(&beans_3cpy, 1, "1");
		g_string_set_size(gmessage, 0);
		nb_missing_chunks = 0;
		err = meta2_backend_check_content(m2, u, &beans_3cpy,
				&nb_missing_chunks, _save_message, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_UNCOMPLETE);
		g_error_free(err);
		missing_chunks = g_strrstr(gmessage->str, "\"missing_chunks\":[\"1\"]");
		g_assert_nonnull(missing_chunks);
		g_assert_cmpint(1, ==, nb_missing_chunks);

		_remove_bean(&beans_3cpy, 1, "1");
		g_string_set_size(gmessage, 0);
		nb_missing_chunks = 0;
		err = meta2_backend_check_content(m2, u, &beans_3cpy,
				&nb_missing_chunks, _save_message, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_UNCOMPLETE);
		g_error_free(err);
		missing_chunks = g_strrstr(gmessage->str, "\"missing_chunks\":[\"1\",\"1\"]");
		g_assert_nonnull(missing_chunks);
		g_assert_cmpint(2, ==, nb_missing_chunks);
		_bean_cleanl2(beans_3cpy);

		g_string_free(gmessage, TRUE);
	}
	_container_wraper_allversions("NS", test);

}

static void
test_content_check_plain_missing_chunks_irreparable(void)
{
	void test(struct meta2_backend_s * m2, struct oio_url_s * u, gint64 maxver) {
		(void) maxver;
		_init_pool_ec_2cpy_3cpy(m2);
		GError *err;
		gint64 nb_missing_chunks = 0;

		GSList *beans_single = _create_alias(m2, u, NULL);
		_remove_bean(&beans_single, 1, "1");
		err = meta2_backend_check_content(m2, u, &beans_single,
				&nb_missing_chunks, NULL, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_CORRUPTED);
		g_error_free(err);
		_bean_cleanl2(beans_single);

		GSList *beans_2cpy = _create_alias2(m2, u, "TWOCOPIES", 2);
		_remove_bean(&beans_2cpy, 2, "2");
		err = meta2_backend_check_content(m2, u, &beans_2cpy,
				&nb_missing_chunks, NULL, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_CORRUPTED);
		g_error_free(err);
		_bean_cleanl2(beans_2cpy);

		GSList *beans_3cpy = _create_alias2(m2, u, "THREECOPIES", 3);
		_remove_bean(&beans_3cpy, 3, "1");
		err = meta2_backend_check_content(m2, u, &beans_3cpy,
				&nb_missing_chunks, NULL, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_CORRUPTED);
		g_error_free(err);
		_bean_cleanl2(beans_3cpy);
	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_check_plain_first_missing_chunks(void)
{
	void test(struct meta2_backend_s * m2, struct oio_url_s * u, gint64 maxver) {
		(void) maxver;
		_init_pool_ec_2cpy_3cpy(m2);
		GError *err;
		GString *gmessage = g_string_new("");
		void _save_message(gchar *message, gpointer udata UNUSED) {
			g_string_append(gmessage, message);
			g_free(message);
		}
		gint64 nb_missing_chunks = 0;

		GSList *beans_nocpy = _create_alias(m2, u, NULL);
		_remove_bean(&beans_nocpy, 1, "0");
		err = meta2_backend_check_content(m2, u, &beans_nocpy,
				&nb_missing_chunks, NULL, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_CORRUPTED);
		g_error_free(err);
		_bean_cleanl2(beans_nocpy);

		GSList *beans_2cpy = _create_alias2(m2, u, "TWOCOPIES", 2);
		_remove_bean(&beans_2cpy, 1, "0");
		g_string_set_size(gmessage, 0);
		nb_missing_chunks = 0;
		err = meta2_backend_check_content(m2, u, &beans_2cpy,
				&nb_missing_chunks, _save_message, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_UNCOMPLETE);
		g_error_free(err);
		gchar *missing_chunks = g_strrstr(gmessage->str,
				"\"missing_chunks\":[\"0\"]");
		g_assert_nonnull(missing_chunks);
		g_assert_cmpint(1, ==, nb_missing_chunks);

		_remove_bean(&beans_2cpy, 1, "1");
		g_string_set_size(gmessage, 0);
		nb_missing_chunks = 0;
		err = meta2_backend_check_content(m2, u, &beans_2cpy,
				&nb_missing_chunks, _save_message, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_UNCOMPLETE);
		g_error_free(err);
		missing_chunks = g_strrstr(gmessage->str,
				"\"missing_chunks\":[\"1\",\"0\"]");
		g_assert_nonnull(missing_chunks);
		g_assert_cmpint(2, ==, nb_missing_chunks);

		_remove_bean(&beans_2cpy, 1, "0");
		err = meta2_backend_check_content(m2, u, &beans_2cpy,
				&nb_missing_chunks, NULL, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_CORRUPTED);
		g_error_free(err);
		_bean_cleanl2(beans_2cpy);

		g_string_free(gmessage, TRUE);
	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_check_plain_last_missing_chunks(void)
{
	void test(struct meta2_backend_s * m2, struct oio_url_s * u, gint64 maxver) {
		(void) maxver;
		_init_pool_ec_2cpy_3cpy(m2);
		GError *err;
		GString *gmessage = g_string_new("");
		void _save_message(gchar *message, gpointer udata UNUSED) {
			g_string_append(gmessage, message);
			g_free(message);
		}
		gint64 nb_missing_chunks = 0;

		GSList *beans_nocpy = _create_alias(m2, u, NULL);
		_remove_bean(&beans_nocpy, 1, "2");
		err = meta2_backend_check_content(m2, u, &beans_nocpy,
				&nb_missing_chunks, NULL, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_CORRUPTED);
		g_error_free(err);
		_bean_cleanl2(beans_nocpy);

		GSList *beans_2cpy = _create_alias2(m2, u, "TWOCOPIES", 2);
		_remove_bean(&beans_2cpy, 1, "2");
		g_string_set_size(gmessage, 0);
		nb_missing_chunks = 0;
		err = meta2_backend_check_content(m2, u, &beans_2cpy,
				&nb_missing_chunks, _save_message, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_UNCOMPLETE);
		g_error_free(err);
		gchar *missing_chunks = g_strrstr(gmessage->str,
				"\"missing_chunks\":[\"2\"]");
		g_assert_nonnull(missing_chunks);
		g_assert_cmpint(1, ==, nb_missing_chunks);

		_remove_bean(&beans_2cpy, 1, "1");
		g_string_set_size(gmessage, 0);
		nb_missing_chunks = 0;
		err = meta2_backend_check_content(m2, u, &beans_2cpy,
				&nb_missing_chunks, _save_message, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_UNCOMPLETE);
		g_error_free(err);
		missing_chunks = g_strrstr(gmessage->str,
				"\"missing_chunks\":[\"2\",\"1\"]");
		g_assert_nonnull(missing_chunks);
		g_assert_cmpint(2, ==, nb_missing_chunks);

		_remove_bean(&beans_2cpy, 1, "2");
		err = meta2_backend_check_content(m2, u, &beans_2cpy,
				&nb_missing_chunks, NULL, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_CORRUPTED);
		g_error_free(err);
		_bean_cleanl2(beans_2cpy);

		g_string_free(gmessage, TRUE);
	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_check_ec_all_present_chunks(void)
{
	void test(struct meta2_backend_s * m2, struct oio_url_s * u, gint64 maxver) {
		(void) maxver;
		_init_pool_ec_2cpy_3cpy(m2);
		GError *err;
		gint64 nb_missing_chunks = 0;

		GSList *beans_ec = _create_alias2(m2, u, "EC", 9);
		err = meta2_backend_check_content(m2, u, &beans_ec,
				&nb_missing_chunks, NULL, FALSE);
		g_assert_no_error(err);
		g_assert_cmpint(0, ==, nb_missing_chunks);
		_bean_cleanl2(beans_ec);

	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_check_ec_missing_chunks_reparable(void)
{
	void test(struct meta2_backend_s * m2, struct oio_url_s * u, gint64 maxver) {
		(void) maxver;
		_init_pool_ec_2cpy_3cpy(m2);
		GError *err;
		GString *gmessage = g_string_new("");
		void _save_message(gchar *message, gpointer udata UNUSED) {
			g_string_append(gmessage, message);
			g_free(message);
		}
		gint64 nb_missing_chunks = 0;

		GSList *beans_ec = _create_alias2(m2, u, "EC", 9);
		_remove_bean(&beans_ec, 1, "1.0");
		err = meta2_backend_check_content(m2, u, &beans_ec,
				&nb_missing_chunks, _save_message, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_UNCOMPLETE);
		g_error_free(err);
		gchar *missing_chunks = g_strrstr(gmessage->str,
				"\"missing_chunks\":[\"1.0\"]");
		g_assert_nonnull(missing_chunks);
		g_assert_cmpint(1, ==, nb_missing_chunks);

		_remove_bean(&beans_ec, 1, "1.2");
		_remove_bean(&beans_ec, 1, "1.8");
		g_string_set_size(gmessage, 0);
		nb_missing_chunks = 0;
		err = meta2_backend_check_content(m2, u, &beans_ec,
				&nb_missing_chunks, _save_message, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_UNCOMPLETE);
		g_error_free(err);
		missing_chunks = g_strrstr(gmessage->str,
				"\"missing_chunks\":[\"1.8\",\"1.2\",\"1.0\"]");
		g_assert_nonnull(missing_chunks);
		g_assert_cmpint(3, ==, nb_missing_chunks);
		_bean_cleanl2(beans_ec);

		g_string_free(gmessage, TRUE);
	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_check_ec_missing_chunks_irreparable(void)
{
	void test(struct meta2_backend_s * m2, struct oio_url_s * u, gint64 maxver) {
		(void) maxver;
		_init_pool_ec_2cpy_3cpy(m2);
		GError *err;
		gint64 nb_missing_chunks = 0;

		GSList *beans_ec = _create_alias2(m2, u, "EC", 9);
		_remove_bean(&beans_ec, 1, "1.1");
		_remove_bean(&beans_ec, 1, "1.2");
		_remove_bean(&beans_ec, 1, "1.3");
		_remove_bean(&beans_ec, 1, "1.5");
		err = meta2_backend_check_content(m2, u, &beans_ec,
				&nb_missing_chunks, NULL, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_CORRUPTED);
		g_error_free(err);

		_remove_bean(&beans_ec, 1, "1.0");
		_remove_bean(&beans_ec, 1, "1.4");
		_remove_bean(&beans_ec, 1, "1.6");
		_remove_bean(&beans_ec, 1, "1.7");
		_remove_bean(&beans_ec, 1, "1.8");
		err = meta2_backend_check_content(m2, u, &beans_ec,
				&nb_missing_chunks, NULL, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_CORRUPTED);
		g_error_free(err);
		_bean_cleanl2(beans_ec);
	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_check_ec_first_missing_chunks(void)
{
	void test(struct meta2_backend_s * m2, struct oio_url_s * u, gint64 maxver) {
		(void) maxver;
		_init_pool_ec_2cpy_3cpy(m2);
		GError *err;
		GString *gmessage = g_string_new("");
		void _save_message(gchar *message, gpointer udata UNUSED) {
			g_string_append(gmessage, message);
			g_free(message);
		}
		gint64 nb_missing_chunks = 0;

		GSList *beans_ec = _create_alias2(m2, u, "EC", 9);
		_remove_bean(&beans_ec, 1, "0.0");
		err = meta2_backend_check_content(m2, u, &beans_ec, &nb_missing_chunks,
				_save_message, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_UNCOMPLETE);
		g_error_free(err);
		gchar *missing_chunks = g_strrstr(gmessage->str,
				"\"missing_chunks\":[\"0.0\"]");
		g_assert_nonnull(missing_chunks);
		g_assert_cmpint(1, ==, nb_missing_chunks);

		_remove_bean(&beans_ec, 1, "0.3");
		_remove_bean(&beans_ec, 1, "0.5");
		_remove_bean(&beans_ec, 1, "1.5");
		g_string_set_size(gmessage, 0);
		nb_missing_chunks = 0;
		err = meta2_backend_check_content(m2, u, &beans_ec, &nb_missing_chunks,
				_save_message, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_UNCOMPLETE);
		g_error_free(err);
		missing_chunks = g_strrstr(gmessage->str,
				"\"missing_chunks\":[\"1.5\",\"0.5\",\"0.3\",\"0.0\"]");
		g_assert_nonnull(missing_chunks);
		g_assert_cmpint(4, ==, nb_missing_chunks);

		_remove_bean(&beans_ec, 1, "0.1");
		err = meta2_backend_check_content(m2, u, &beans_ec, &nb_missing_chunks,
				NULL, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_CORRUPTED);
		g_error_free(err);

		_remove_bean(&beans_ec, 1, "0.2");
		_remove_bean(&beans_ec, 1, "0.4");
		_remove_bean(&beans_ec, 1, "0.6");
		_remove_bean(&beans_ec, 1, "0.7");
		_remove_bean(&beans_ec, 1, "0.8");
		err = meta2_backend_check_content(m2, u, &beans_ec, &nb_missing_chunks,
				NULL, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_CORRUPTED);
		g_error_free(err);
		_bean_cleanl2(beans_ec);

		g_string_free(gmessage, TRUE);
	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_check_ec_last_missing_chunks(void)
{
	void test(struct meta2_backend_s * m2, struct oio_url_s * u, gint64 maxver) {
		(void) maxver;
		_init_pool_ec_2cpy_3cpy(m2);
		GError *err;
		GString *gmessage = g_string_new("");
		void _save_message(gchar *message, gpointer udata UNUSED) {
			g_string_append(gmessage, message);
			g_free(message);
		}
		gint64 nb_missing_chunks = 0;

		GSList *beans_ec = _create_alias2(m2, u, "EC", 9);
		_remove_bean(&beans_ec, 1, "2.8");
		err = meta2_backend_check_content(m2, u, &beans_ec, &nb_missing_chunks,
				_save_message, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_UNCOMPLETE);
		g_error_free(err);
		gchar *missing_chunks = g_strrstr(gmessage->str,
				"\"missing_chunks\":[\"2.8\"]");
		g_assert_nonnull(missing_chunks);
		g_assert_cmpint(1, ==, nb_missing_chunks);

		_remove_bean(&beans_ec, 1, "2.3");
		_remove_bean(&beans_ec, 1, "2.5");
		_remove_bean(&beans_ec, 1, "1.5");
		g_string_set_size(gmessage, 0);
		nb_missing_chunks = 0;
		err = meta2_backend_check_content(m2, u, &beans_ec, &nb_missing_chunks,
				_save_message, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_UNCOMPLETE);
		g_error_free(err);
		missing_chunks = g_strrstr(gmessage->str,
				"\"missing_chunks\":[\"2.8\",\"2.5\",\"2.3\",\"1.5\"]");
		g_assert_nonnull(missing_chunks);
		g_assert_cmpint(4, ==, nb_missing_chunks);

		_remove_bean(&beans_ec, 1, "2.1");
		err = meta2_backend_check_content(m2, u, &beans_ec, &nb_missing_chunks,
				NULL, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_CORRUPTED);
		g_error_free(err);

		_remove_bean(&beans_ec, 1, "2.0");
		_remove_bean(&beans_ec, 1, "2.2");
		_remove_bean(&beans_ec, 1, "2.4");
		_remove_bean(&beans_ec, 1, "2.6");
		_remove_bean(&beans_ec, 1, "2.7");
		err = meta2_backend_check_content(m2, u, &beans_ec, &nb_missing_chunks,
				NULL, FALSE);
		g_assert_error(err, GQ(), CODE_CONTENT_CORRUPTED);
		g_error_free(err);
		_bean_cleanl2(beans_ec);

		g_string_free(gmessage, TRUE);
	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_put_prop_get(void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u, gint64 maxver) {
		GSList *beans;
		GSList *modified = NULL;
		guint expected;
		GPtrArray *tmp;
		GError *err;

		CLOCK_START = CLOCK = oio_ext_rand_int();

		/* insert a new alias */
		do {
			beans = _create_alias(m2, u, NULL);
			err = meta2_backend_put_alias(m2, u, beans, 0,
					NULL, NULL, NULL, NULL);
			g_assert_no_error(err);
			_bean_cleanl2(beans);
		} while (0);

		CHECK_ALIAS_VERSION(m2,u,CLOCK_START);
		check_list_count(m2,u,1);
		CLOCK ++;

		/* set some properties */
		beans = _props_generate(u, 1, 10);
		err = meta2_backend_set_properties(m2, u, TRUE, beans, &modified);
		g_assert_no_error(err);
		_bean_cleanl2(beans);
		_bean_cleanl2(modified);

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
		g_assert_cmpuint(tmp->len, ==, expected);
		_bean_cleanv2(tmp);

		/* idem, but with the properties */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_ALLVERSION,
				_bean_buffer_cb, tmp);
		g_assert_no_error(err);
		expected = 10 + 2 + chunks_count;
		GRID_DEBUG("TEST count=%u expected=%u", tmp->len, expected);
		_debug_beans_array(tmp);
		g_assert_cmpuint(tmp->len, ==, expected);
		_bean_cleanv2(tmp);

		/* delete the bean */
		err = meta2_backend_delete_alias(m2, u, FALSE, NULL, NULL);
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
		g_assert_cmpuint(tmp->len, ==, expected);
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
			err = meta2_backend_put_alias(m2, u, beans, 0,
					NULL, NULL, NULL, NULL);
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
		g_assert_cmpuint(tmp->len, ==, expected);
		_bean_cleanv2(tmp);

		check_list_count(m2,u,1);

		/* delete the bean */
		err = meta2_backend_delete_alias(m2, u, FALSE, NULL, NULL);
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
		g_assert_cmpuint(tmp->len, ==, 0);
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
			// 1 alias + 1 content header + chunks_count * (1 chunk)
			// + 1 deleted alias
			expected = (1 + 1 + chunks_count) + (1);
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
		if (VERSIONS_ENABLED(maxver)) {
			tmp = g_ptr_array_new();
			err = meta2_backend_delete_alias(m2, u, FALSE, NULL, NULL);
			g_assert_no_error(err);
			_bean_cleanv2(tmp);

			CHECK_ALIAS_VERSION(m2,u,CLOCK_START);
			check_list_count(m2,u,1);
		}
	}

	_container_wraper_allversions("NS", test);
}

static void
test_content_put_lower_version(void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u, gint64 maxver) {
		GSList *beans = NULL;
		GError *err;

		CLOCK_START = CLOCK = oio_ext_rand_int();

		/* generate the beans for an alias of 3 chunks */
		beans = _create_alias(m2, u, NULL);

		/* first PUT */
		err = meta2_backend_put_alias(m2, u, beans, 0,
				NULL, NULL, NULL, NULL);
		g_assert_no_error(err);
		CHECK_ALIAS_VERSION(m2, u, _get_real());
		check_list_count(m2, u, 1);
		_bean_cleanl2(beans);

		/* second PUT, with lower version */
		CLOCK--;
		beans = _create_alias(m2, u, NULL);
		CLOCK++;
		_set_content_id(u);
		err = meta2_backend_put_alias(m2, u, beans, 0,
				NULL, NULL, NULL, NULL);
		if (VERSIONS_ENABLED(maxver)) {
			g_assert_no_error(err);
		} else {
			g_assert_error(err, GQ(), CODE_CONTENT_PRECONDITION);
		}
		_bean_cleanl2(beans);
		g_clear_error(&err);

		CHECK_ALIAS_VERSION(m2, u, CLOCK_START);
	}
	_container_wraper("NS", -1, test);
	/* Would fail for another reason */
	// _container_wraper (ns, 0, cf);
	_container_wraper("NS", 1, test);
	_container_wraper("NS", 2, test);
}

static void
test_content_append_empty(void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u, gint64 maxver) {
		(void) maxver;
		GError *err = meta2_backend_append_to_alias(m2, u, NULL, 0, NULL, NULL);
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
		err = meta2_backend_put_alias(m2, u, beans, 0,
				NULL, NULL, NULL, NULL);
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
		g_assert_cmpuint(tmp->len, ==, expected);
		_bean_cleanv2(tmp);

		/* append th same chunks */
		tmp = g_ptr_array_new ();
		err = meta2_backend_append_to_alias(m2, u, beans, 0, _bean_buffer_cb, tmp);
		g_assert_nonnull(err);
		g_clear_error (&err);
		_bean_cleanv2 (tmp);

		/* append new chunks */
		struct oio_url_s *u1 = oio_url_dup(u);
		oio_url_set (u1, OIOURL_PATH, "_");
		_set_content_id(u1);
		newbeans = _create_alias(m2, u1, NULL);
		oio_url_pclean (&u1);

		tmp = g_ptr_array_new ();
		err = meta2_backend_append_to_alias(m2, u, newbeans, 0, _bean_buffer_cb, tmp);
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
		g_assert_cmpuint(tmp->len, ==, expected);
		_bean_cleanv2(tmp);

		/* delete the alias */
		err = meta2_backend_delete_alias(m2, u, FALSE, NULL, NULL);
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
			// 1 alias + 1 content header + chunks_count * (2 chunks)
			// + 1 deleted alias
			expected = (1 + 1 + 2 * chunks_count) + (1);
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
		err = meta2_backend_append_to_alias(m2, u, beans, 0, NULL, NULL);
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
		g_assert_cmpuint(tmp->len, ==, expected);
		_bean_cleanv2(tmp);

		/* re-APPEND */
		struct oio_url_s *u1 = oio_url_dup(u);
		oio_url_set (u1, OIOURL_PATH, "_");
		_set_content_id(u1);
		newbeans = _create_alias(m2, u1, NULL);
		CLOCK ++;
		err = meta2_backend_append_to_alias(m2, u, newbeans, 0, NULL, NULL);
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
		g_assert_cmpuint(tmp->len, ==, expected);
		_bean_cleanv2(tmp);

		/* delete the bean */
		err = meta2_backend_delete_alias(m2, u, FALSE, NULL, NULL);
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
		g_assert_cmpuint(tmp->len, ==, 0);
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
		GSList *modified = NULL;
		(void) maxver;

		err = meta2_backend_get_properties(m2, u, 0, NULL, NULL);
		g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
		g_clear_error(&err);

		beans = _props_generate(u, 1, 10);
		err = meta2_backend_set_properties(m2, u, FALSE, beans, &modified);
		g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
		g_clear_error(&err);
		_bean_cleanl2(beans);
		_bean_cleanl2(modified);
	}
	_container_wraper_allversions("NS", test);
}

static void
test_props_set_simple()
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u, gint64 maxver) {
		GError *err;
		GSList *beans;
		GSList *modified = NULL;
		(void) maxver;

		CLOCK_START = CLOCK = oio_ext_rand_int();

		/* add a content */
		beans = _create_alias(m2, u, NULL);
		CLOCK ++;
		err = meta2_backend_put_alias(m2, u, beans, 0,
				NULL, NULL, NULL, NULL);
		CLOCK ++;
		g_assert_no_error(err);
		_bean_cleanl2(beans);

		CHECK_ALIAS_VERSION(m2,u,CLOCK_START);

		/* set it properties */
		beans = _props_generate(u, 1, 10);
		CLOCK ++;
		err = meta2_backend_set_properties(m2, u, FALSE, beans, &modified);
		CLOCK ++;
		g_assert_no_error(err);
		_bean_cleanl2(beans);
		_bean_cleanl2(modified);

		CHECK_ALIAS_VERSION(m2,u,CLOCK_START);
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
	g_test_add_func("/meta2v2/backend/container/flush",
			test_container_flush);
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
	g_test_add_func("/meta2v2/backend/content/append_notfound",
			test_content_append_not_found);
	g_test_add_func("/meta2v2/backend/content/check_plain_all_present_chunks",
			test_content_check_plain_all_present_chunks);
	g_test_add_func("/meta2v2/backend/content/check_plain_missing_chunks_reparable",
			test_content_check_plain_missing_chunks_reparable);
	g_test_add_func("/meta2v2/backend/content/check_plain_missing_chunks_irreparable",
			test_content_check_plain_missing_chunks_irreparable);
	g_test_add_func("/meta2v2/backend/content/check_plain_first_missing_chunks",
			test_content_check_plain_first_missing_chunks);
	g_test_add_func("/meta2v2/backend/content/check_plain_last_missing_chunks",
			test_content_check_plain_last_missing_chunks);
	g_test_add_func("/meta2v2/backend/content/check_ec_all_present_chunks",
			test_content_check_ec_all_present_chunks);
	g_test_add_func("/meta2v2/backend/content/check_ec_missing_chunks_reparable",
			test_content_check_ec_missing_chunks_reparable);
	g_test_add_func("/meta2v2/backend/content/check_ec_missing_chunks_irreparable",
			test_content_check_ec_missing_chunks_irreparable);
	g_test_add_func("/meta2v2/backend/content/check_ec_first_missing_chunks",
			test_content_check_ec_first_missing_chunks);
	g_test_add_func("/meta2v2/backend/content/check_ec_last_missing_chunks",
			test_content_check_ec_last_missing_chunks);

	return g_test_run();
}
