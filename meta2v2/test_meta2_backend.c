/*
OpenIO SDS meta2v2
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

#include <string.h>
#include <glib.h>

#include <meta2v2/meta2_macros.h>
#include <meta2v2/meta2_utils.h>
#include <meta2v2/meta2_backend_internals.h>
#include <meta2v2/meta2v2_remote.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>
#include <resolver/hc_resolver.h>

typedef void (*repo_test_f) (struct meta2_backend_s *m2);

typedef void (*container_test_f) (struct meta2_backend_s *m2,
		struct oio_url_s *url, gint64 max_versions);

static guint64 container_counter = 0;
static gint64 chunk_size = 3000;
static gint64 chunks_count = 3;

#define CHECK_ALIAS_VERSION(m2,u,v) do {\
	gint64 _v = 0, _v0 = (v); \
	err = meta2_backend_get_alias_version(m2, u, &_v); \
	GRID_DEBUG("err=%d version=%"G_GINT64_FORMAT" expected=%"G_GINT64_FORMAT,\
			err?err->code:0, _v, _v0); \
	g_assert_no_error(err); \
	g_assert(_v0 == _v); \
} while (0);

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
		struct bean_PROPERTIES_s *prop = _bean_create(&descr_struct_PROPERTIES);
		PROPERTIES_set2_alias(prop, oio_url_get(url, OIOURL_PATH));
		PROPERTIES_set_version(prop, v);
		PROPERTIES_set2_key(prop, name);
		PROPERTIES_set2_value(prop, (guint8*)"value", sizeof("value"));
		result = g_slist_prepend(result, prop);
	}

	_debug_beans_list(result);
	return result;
}

static GSList*
_create_alias(struct meta2_backend_s *m2b, struct oio_url_s *url,
		const gchar *polname)
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
	expected = 1 + 1 + chunks_count;
	GRID_DEBUG("BEANS generated=%u expected=%u", generated, expected);
	g_assert_no_error(err);
	g_assert(generated == expected);

	_debug_beans_list(beans);
	return beans;
}

static void
check_list_count(struct meta2_backend_s *m2, struct oio_url_s *url, guint expected)
{
	GError *err;
	guint counter = 0;

	void counter_cb(gpointer u, gpointer bean) {
		(void) u, (void) bean;
		counter ++;
		_bean_clean(bean);
	}

	struct list_params_s lp;
	memset(&lp, '\0', sizeof(struct list_params_s));
	lp.flag_allversion = ~0;

	err = meta2_backend_list_aliases(m2, url, &lp, NULL, counter_cb, NULL, NULL);
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
	metautils_strlcpy_physical_ns(nsinfo->name, ns, sizeof(nsinfo->name));

	g_snprintf (str, sizeof(str), "%"G_GINT64_FORMAT, maxvers);
	g_hash_table_insert(nsinfo->options, g_strdup("meta2_max_versions"),
			metautils_gba_from_string(str));

	g_hash_table_insert(nsinfo->storage_policy, g_strdup("classic"),
			metautils_gba_from_string("DUMMY:DUPONETWO:NONE"));
	g_hash_table_insert(nsinfo->storage_policy, g_strdup("polcheck"),
			metautils_gba_from_string("DUMMY:DUPONETHREE:SIMCOMP"));
	g_hash_table_insert(nsinfo->storage_policy, g_strdup("secure"),
			metautils_gba_from_string("DUMMY:DUP_SECURE:NONE"));

	g_hash_table_insert(nsinfo->data_security, g_strdup("DUPONETWO"),
			metautils_gba_from_string("DUP:distance=1|nb_copy=2"));
	g_hash_table_insert(nsinfo->data_security, g_strdup("DUPONETHREE"),
			metautils_gba_from_string("DUP:distance=1|nb_copy=3"));
	g_hash_table_insert(nsinfo->data_security, g_strdup("DUP_SECURE"),
			metautils_gba_from_string("DUP:distance=4|nb_copy=2"));

	g_hash_table_insert(nsinfo->data_treatments, g_strdup("SIMCOMP"),
			metautils_gba_from_string("COMP:algo=ZLIB|blocksize=262144"));

	return nsinfo;
}

static struct grid_lbpool_s *
_init_lb(const gchar *ns)
{
	struct def_s { const gchar *url, *loc; };
	static struct def_s defs[] = {
		{"127.0.0.1:1025","site0.salle0.baie0.device0"},
		{"127.0.0.1:1026","site0.salle0.baie0.device1"},
		{"127.0.0.1:1027","site0.salle0.baie1.device0"},
		{"127.0.0.1:1028","site0.salle1.baie0.device0"},
		{"127.0.0.1:1029","site0.salle1.baie1.device0"},
		{"127.0.0.1:1030","site0.salle1.baie0.device1"},
		{NULL,NULL}
	};

	struct def_s *pdef = defs;
	gint score = 0;

	gboolean provide(struct service_info_s **p_si) {
		struct service_info_s *si;
		if (!pdef->url)
			return FALSE;

		si = g_malloc0(sizeof(*si));
		metautils_strlcpy_physical_ns(si->ns_name, "NS", sizeof(si->ns_name));
		g_strlcpy(si->type, "rawx", sizeof(si->type));
		si->score.timestamp = time(0);
		si->score.value = ++score;
		grid_string_to_addrinfo(pdef->url, &(si->addr));

		pdef++;
		*p_si = si;
		return TRUE;
	}

	struct grid_lbpool_s *glp = grid_lbpool_create(ns);
	g_assert(glp != NULL);
	grid_lbpool_configure_string(glp, "rawx", "RR");
	grid_lbpool_reload(glp, "rawx", provide);
	return glp;
}

static void
_repo_wraper(const gchar *ns, gint64 maxvers, repo_test_f fr)
{
	gchar repodir[512];
	GError *err = NULL;
	struct grid_lbpool_s *glp = NULL;
	struct meta2_backend_s *backend = NULL;
	struct sqlx_repository_s *repository = NULL;
	struct hc_resolver_s *resolver = NULL;
	struct namespace_info_s *nsinfo = NULL;
	struct sqlx_repo_config_s cfg;

	g_printerr("\n");
	g_assert(ns != NULL);

	nsinfo = _init_nsinfo(ns, maxvers);
	g_assert_nonnull (nsinfo);

	g_snprintf(repodir, sizeof(repodir), "%s/.oio/sds/data/test-%d", g_get_home_dir(), getpid());
	g_mkdir_with_parents(repodir, 0755);

	glp = _init_lb(ns);

	resolver = hc_resolver_create();
	g_assert(resolver != NULL);

	memset(&cfg, 0, sizeof(cfg));
	cfg.flags = SQLX_REPO_DELETEON;
	err = sqlx_repository_init(repodir, &cfg, &repository);
	g_assert_no_error(err);

	err = meta2_backend_init(&backend, repository, ns, glp, resolver);
	g_assert_no_error(err);
	meta2_backend_configure_nsinfo(backend, nsinfo);

	if (fr)
		fr(backend);

	meta2_backend_clean(backend);
	sqlx_repository_clean(repository);
	hc_resolver_destroy(resolver);
	grid_lbpool_destroy(glp);
	namespace_info_free (nsinfo);
}

static void
_repo_failure(const gchar *ns)
{
	gchar repodir[512];
	GError *err = NULL;
	struct meta2_backend_s *backend = NULL;
	struct sqlx_repository_s *repository = NULL;
	struct hc_resolver_s *resolver = NULL;
	struct grid_lbpool_s *glp = NULL;
	struct sqlx_repo_config_s cfg;

	g_assert(ns != NULL);

	g_snprintf(repodir, sizeof(repodir), "%s/.oio/sds/data/test-%d", g_get_home_dir(), getpid());
	g_mkdir_with_parents(repodir, 0755);

	glp = _init_lb(ns);

	resolver = hc_resolver_create();
	g_assert(resolver != NULL);

	g_printerr("\n");
	memset(&cfg, 0, sizeof(cfg));
	cfg.flags = SQLX_REPO_DELETEON;
	err = sqlx_repository_init(repodir, &cfg, &repository);
	g_assert_no_error(err);
	err = meta2_backend_init(&backend, repository, ns, glp, resolver);
	g_assert_error(err, GQ(), CODE_BAD_REQUEST);
	g_clear_error (&err);

	meta2_backend_clean(backend);
	sqlx_repository_clean(repository);
	hc_resolver_destroy(resolver);
	grid_lbpool_destroy (glp);
}

static void
_container_wraper(const char *ns, gint64 maxvers, container_test_f cf)
{
	void test(struct meta2_backend_s *m2) {
		struct m2v2_create_params_s params = {NULL, NULL, NULL, FALSE};
		struct oio_url_s *url;
		GError *err;

		gchar *strurl = g_strdup_printf(
				"/%s/account/container-%"G_GUINT64_FORMAT"/content-%"G_GINT64_FORMAT,
				ns, ++container_counter, g_get_monotonic_time());
		url = oio_url_init(strurl);
		g_free(strurl);

		err = meta2_backend_create_container(m2, url, &params);
		g_assert_no_error(err);

		if (cf)
			cf(m2, url, maxvers);

		err = meta2_backend_destroy_container (m2, url, M2V2_DESTROY_FORCE|M2V2_DESTROY_FLUSH);
		g_assert_no_error (err);

		oio_url_pclean(&url);
	}

	g_printerr("--- %"G_GINT64_FORMAT" %s -----------------------------------------------------",
			maxvers, ns);
	_repo_wraper(ns, maxvers, test);
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
	_repo_wraper("NS", 0, NULL);
}

static void
test_backend_strange_ns(void)
{
	static gchar ns_255[LIMIT_LENGTH_NSNAME];
	static gchar ns_256[LIMIT_LENGTH_NSNAME+1];

	void test(struct meta2_backend_s *m2) {
		g_assert(strlen(m2->backend.ns_name) > 0);
		g_assert(NULL == strchr(m2->backend.ns_name, '.'));
	}

	/* successful creations */
	_repo_wraper("NS", 0, test);
	_repo_wraper("NS00", 0, test);
	_repo_wraper("NS000", 0, test);
	memset(ns_255, '0', sizeof(ns_255));
	ns_255[0] = 'N';
	ns_255[1] = 'S';
	ns_255[sizeof(ns_255)-1] = 0;
	_repo_wraper(ns_255, 0, test);
	_repo_wraper("NS.VNS0", 0, test);

	memset(ns_256, '0', sizeof(ns_256));
	ns_256[0] = 'N';
	ns_256[1] = 'S';
	ns_256[2] = '.';
	ns_256[sizeof(ns_256)-1] = 0;
	_repo_wraper(ns_256, 0, test);

	/* creations expected to fail */
	memset(ns_256, '0', sizeof(ns_256));
	ns_256[0] = 'N';
	ns_256[1] = 'S';
	ns_256[sizeof(ns_256)-1] = 0;
	_repo_failure(ns_256);
}

static void
test_container_create_destroy(void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u, gint64 max_versions) {
		g_assert (VERSIONS_ENABLED(max_versions) == _versioned(m2, u));
	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_delete_not_found(void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u, gint64 max_versions) {
		(void) max_versions;
		GError *err = meta2_backend_delete_alias(m2, u, NULL, NULL);
		g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
		g_clear_error(&err);
	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_put_no_beans(void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u, gint64 max_versions) {
		(void) max_versions;
		GError *err = meta2_backend_put_alias(m2, u, NULL, NULL, NULL, NULL);
		g_assert_error(err, GQ(), CODE_BAD_REQUEST);
		g_clear_error(&err);
	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_put_prop_get(void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u, gint64 max_versions) {
		GSList *beans;
		guint expected;
		GPtrArray *tmp;
		GError *err;

		/* insert a new alias */
		do {
			beans = _create_alias(m2, u, NULL);
			err = meta2_backend_put_alias(m2, u, beans, NULL, NULL, NULL);
			g_assert_no_error(err);
			_bean_cleanl2(beans);
		} while (0);

		CHECK_ALIAS_VERSION(m2,u,0);
		check_list_count(m2,u,1);

		/* set some properties */
		beans = _props_generate(u, 1, 10);
		err = meta2_backend_set_properties(m2, u, TRUE, beans, NULL, NULL);
		g_assert_no_error(err);
		_bean_cleanl2(beans);

		/* versioned or not, a container doesn't generate a new version of the
		 * content when a property is set on it. */
		CHECK_ALIAS_VERSION(m2,u,0);
		check_list_count(m2,u,1);

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
		if (VERSIONS_ENABLED(max_versions)) {
			CHECK_ALIAS_VERSION(m2,u,1);
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
	void test(struct meta2_backend_s *m2, struct oio_url_s *u, gint64 max_versions) {
		guint expected;
		GPtrArray *tmp;
		GError *err;

		/* insert a new alias */
		do {
			GSList *beans = _create_alias(m2, u, NULL);
			err = meta2_backend_put_alias(m2, u, beans, NULL, NULL, NULL);
			g_assert_no_error(err);
			_bean_cleanl2(beans);
		} while (0);

		CHECK_ALIAS_VERSION(m2,u,0);
		check_list_count(m2,u,1);

		/* check we got our beans */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_ALLVERSION, _bean_buffer_cb, tmp);
		g_assert_no_error(err);
		expected = 2+chunks_count;
		g_assert(tmp->len == expected);
		_bean_cleanv2(tmp);

		check_list_count(m2,u,1);

		/* delete the bean */
		err = meta2_backend_delete_alias(m2, u, NULL, NULL);
		g_assert_no_error(err);

		if (VERSIONS_ENABLED(max_versions)) {
			CHECK_ALIAS_VERSION(m2,u,1); // v1: original, v2: copy with 'deleted' flag
			check_list_count(m2,u,2);
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

		if (VERSIONS_ENABLED(max_versions)) {
			check_list_count(m2,u,2);
		} else {
			check_list_count(m2,u,0);
		}

		/* check there are 2 versions */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_ALLVERSION,
				_bean_buffer_cb, tmp);
		if (VERSIONS_ENABLED(max_versions)) {
			g_assert_no_error(err);
			// nb_versions * (1 alias + 1 content header + chunks_count * (1 chunk))
			expected = 2 * (2 + chunks_count);
			GRID_DEBUG("TEST Got %u beans for all versions, expected %u (chunks count: %"G_GINT64_FORMAT")",
					tmp->len, expected, chunks_count);
			g_assert(tmp->len == expected);
		} else {
			g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
			g_clear_error (&err);
			g_assert(tmp->len == 0);
		}
		_bean_cleanv2(tmp);

		/* Check we can force the delete by deleting deleted version */
		if (VERSIONS_ENABLED(max_versions)) {
			tmp = g_ptr_array_new();
			err = meta2_backend_delete_alias(m2, u, NULL, NULL);
			g_assert_no_error(err);
			_bean_cleanv2(tmp);

			CHECK_ALIAS_VERSION(m2,u,0);
			check_list_count(m2,u,1);
		}
	}

	_container_wraper_allversions("NS", test);
}

static void
test_content_append_empty(void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u, gint64 max_versions) {
		(void) max_versions;
		GError *err = meta2_backend_append_to_alias(m2, u, NULL, NULL, NULL);
		g_assert_error(err, GQ(), CODE_BAD_REQUEST);
		g_clear_error(&err);
	}
	_container_wraper_allversions("NS", test);
}

static void
test_content_append(void)
{
	void test(struct meta2_backend_s *m2, struct oio_url_s *u, gint64 max_versions) {
		(void) max_versions;
		GPtrArray *tmp;
		GSList *beans = NULL, *newbeans = NULL;
		GError *err;
		guint expected;

		/* generate the beans for an alias of 3 chunks */
		beans = _create_alias(m2, u, NULL);

		/* first PUT */
		err = meta2_backend_put_alias(m2, u, beans, NULL, NULL, NULL);
		g_assert_no_error(err);
		CHECK_ALIAS_VERSION(m2,u,0);
		check_list_count(m2,u,1);

		/* count the beans */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_ALLVERSION, _bean_buffer_cb, tmp);
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
		CHECK_ALIAS_VERSION(m2,u,0);
		check_list_count(m2,u,1);
		_bean_cleanv2 (tmp);

		/* check we got our beans */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_ALLVERSION, _bean_buffer_cb, tmp);
		g_assert_no_error(err);
		expected = 1 /* alias */ + 1 /* headers */
			+ chunks_count  /* original chunks */
			+ chunks_count; /* new chunks appended */
		GRID_DEBUG("TEST After the append, got %u, expected %u", tmp->len, expected);
		g_assert(tmp->len == expected);
		_bean_cleanv2(tmp);

		/* delete the alias */
		err = meta2_backend_delete_alias(m2, u, NULL, NULL);
		if (VERSIONS_ENABLED(max_versions)) {
			g_assert_no_error(err);
			CHECK_ALIAS_VERSION(m2,u,1);
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
		if (VERSIONS_ENABLED(max_versions)) {
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
	void test(struct meta2_backend_s *m2, struct oio_url_s *u, gint64 max_versions) {
		guint expected;
		GPtrArray *tmp;
		GSList *beans = NULL, *newbeans = NULL;
		GError *err;

		beans = _create_alias(m2, u, NULL);

		/* first PUT */
		err = meta2_backend_append_to_alias(m2, u, beans, NULL, NULL);
		g_assert_no_error(err);
		CHECK_ALIAS_VERSION(m2,u,0);

		/* count the beans */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_ALLVERSION, _bean_buffer_cb, tmp);
		g_assert_no_error(err);
		expected = 1 + 1 + chunks_count;
		g_assert(tmp->len == expected);
		_bean_cleanv2(tmp);

		/* re-APPEND */
		struct oio_url_s *u1 = oio_url_dup(u);
		oio_url_set (u1, OIOURL_PATH, "_");
		newbeans = _create_alias(m2, u1, NULL);
		err = meta2_backend_append_to_alias(m2, u, newbeans, NULL, NULL);
		g_assert_no_error(err);
		oio_url_pclean (&u1);

		CHECK_ALIAS_VERSION(m2,u,0);

		/* count the beans */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_ALLVERSION, _bean_buffer_cb, tmp);
		g_assert_no_error(err);
		expected = 1 /* alias */ + 1 /* headers */
			+ chunks_count /* original chunks+contents */
			+ chunks_count; /* new chunks appended */
		g_assert(tmp->len == expected);
		_bean_cleanv2(tmp);

		/* delete the bean */
		err = meta2_backend_delete_alias(m2, u, NULL, NULL);
		g_assert_no_error(err);
		if (VERSIONS_ENABLED(max_versions)) {
			CHECK_ALIAS_VERSION(m2,u,1);
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
		if (VERSIONS_ENABLED(max_versions)) {
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
	void test(struct meta2_backend_s *m2, struct oio_url_s *u, gint64 max_versions) {
		GError *err;
		GSList *beans;

		err = meta2_backend_get_properties(m2, u, NULL, NULL);
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
	void test(struct meta2_backend_s *m2, struct oio_url_s *u, gint64 max_versions) {
		GError *err;
		GSList *beans;

		/* add a content */
		beans = _create_alias(m2, u, NULL);
		err = meta2_backend_put_alias(m2, u, beans, NULL, NULL, NULL);
		g_assert_no_error(err);
		_bean_cleanl2(beans);

		CHECK_ALIAS_VERSION(m2,u,0);

		/* set it properties */
		beans = _props_generate(u, 1, 10);
		err = meta2_backend_set_properties(m2, u, FALSE, beans, NULL, NULL);
		g_assert_no_error(err);
		_bean_cleanl2(beans);

		CHECK_ALIAS_VERSION(m2,u,0);
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

	void test(struct meta2_backend_s *m2, struct oio_url_s *url, gint64 max_versions) {
		GError *err;
		/* Generate a list of beans */
		GSList *beans = _create_alias(m2, url, NULL);
		/* Change the hash of the chunk beans (0 by default) */
		change_chunk_hash(beans, 0);
		/* Put the beans in the database */
		err = meta2_backend_put_alias(m2, url, beans, NULL, NULL, NULL);
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
			err = meta2_backend_put_alias(m2, url2, beans2, NULL, NULL, NULL);
			g_assert_no_error(err);
			_bean_cleanl2(beans2);
			oio_url_pclean (&url2);
		}

		err = meta2_backend_deduplicate_contents (m2, url, 0, NULL);
		g_assert_no_error(err);

		/* TODO check the result of the dedup ;) */
	}
	_container_wraper_allversions("NS", test);
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);

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

	return g_test_run();
}

