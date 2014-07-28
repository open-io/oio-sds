#include <string.h>

#include <meta2v2/meta2_backend_internals.h>
#include <meta2v2/meta2v2_remote.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>
#include <meta2v2/meta2_test_common.h>
#include <resolver/hc_resolver.h>

static guint64 container_counter = 0;
static gint64 version = 0;
static gint64 chunk_size = 3000;
static gint64 chunks_count = 3;

#define CHECK_ALIAS_VERSION(m2,u,v) do {\
	gint64 _v = (v); \
	err = meta2_backend_get_alias_version(m2, u, 0, &version); \
	GRID_DEBUG("err=%d version=%"G_GINT64_FORMAT" expected=%"G_GINT64_FORMAT,\
			err?err->code:0, version, _v); \
	g_assert_no_error(err); \
	g_assert(version == _v); \
} while (0);

static gboolean
_versioned(struct meta2_backend_s *m2, struct hc_url_s *u)
{
	gint64 v = 0;
	GError *err = meta2_backend_get_max_versions(m2, u, &v);
	g_assert_no_error(err);
	return v != 0; // -1 means unlimited
}

static void
_debug_beans_list(GSList *l)
{
	if (!g_getenv("GS_DEBUG_ENABLED"))
		return;
	for (; l ;l=l->next) {
		GString *s = _bean_debug(NULL, l->data);
		GRID_DEBUG("TEST DUMP %s", s->str);
		g_string_free(s, TRUE);
	}
}

static void
_debug_beans_array(GPtrArray *v)
{
	if (!g_getenv("GS_DEBUG_ENABLED"))
		return;
	guint i;
	for (i=0; i<v->len ;i++) {
		GString *s = _bean_debug(NULL, v->pdata[i]);
		GRID_DEBUG("TEST DUMP %s", s->str);
		g_string_free(s, TRUE);
	}
}

/**
 * Generates properties beans
 */
static GSList *
_props_generate(struct hc_url_s *url, gint64 v, guint count)
{
	GSList *result = NULL;
	while (count-- > 0) {
		gchar name[32];
		g_snprintf(name, sizeof(name), "prop-%u", count);
		struct bean_PROPERTIES_s *prop = _bean_create(&descr_struct_PROPERTIES);
		PROPERTIES_set2_alias(prop, hc_url_get(url, HCURL_PATH));
		PROPERTIES_set_alias_version(prop, v);
		PROPERTIES_set2_key(prop, name);
		PROPERTIES_set2_value(prop, (guint8*)"value", sizeof("value"));
		PROPERTIES_set_deleted(prop, FALSE);
		result = g_slist_prepend(result, prop);
	}

	_debug_beans_list(result);
	return result;
}

static GSList*
_create_alias(struct meta2_backend_s *m2b, struct hc_url_s *url,
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
	expected = (2+2*chunks_count);
	GRID_DEBUG("BEANS generated=%u expected=%u", generated, expected);
	g_assert_no_error(err);
	g_assert(generated == expected);

	_debug_beans_list(beans);
	return beans;
}

static void
_appender(gpointer u, gpointer bean)
{
	if (GRID_TRACE_ENABLED()) {
		GString *gs = _bean_debug(NULL, bean);
		GRID_TRACE("TEST  append %s", gs->str);
		g_string_free(gs, TRUE);
	}
	g_ptr_array_add((GPtrArray*)u, bean);
}

static void
check_list_count(struct meta2_backend_s *m2, struct hc_url_s *url, guint expected)
{
	GError *err;
	guint counter = 0;

	void counter_cb(gpointer u, gpointer bean) {
		(void) u;
		(void) bean;
		counter ++;
		_bean_clean(bean);
	}

	struct list_params_s lp;
	memset(&lp, '\0', sizeof(struct list_params_s));
	lp.flags = M2V2_FLAG_ALLVERSION;
	lp.type = DEFAULT;

	err = meta2_backend_list_aliases(m2, url, &lp, counter_cb, NULL);
	g_assert_no_error(err);
	GRID_DEBUG("TEST list_aliases counter=%u expected=%u", counter, expected);
	g_assert(counter == expected);
}

static void
_init_nsinfo(struct namespace_info_s *nsinfo, const gchar *ns)
{
	memset(nsinfo, 0, sizeof(*nsinfo));
	metautils_strlcpy_physical_ns(nsinfo->name, ns, sizeof(nsinfo->name));
	nsinfo->chunk_size = chunk_size;

	nsinfo->writable_vns = g_slist_prepend(nsinfo->writable_vns, g_strdup("NS.VNS0"));
	nsinfo->writable_vns = g_slist_prepend(nsinfo->writable_vns, g_strdup("NS.VNS1"));

	nsinfo->storage_policy = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, metautils_gba_unref);
	nsinfo->data_security = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, metautils_gba_unref);
	nsinfo->data_treatments = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, metautils_gba_unref);

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
		grid_string_to_addrinfo(pdef->url, NULL, &(si->addr));

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
_repo_wraper(const gchar *ns, repo_test_f fr)
{
	gchar repodir[512];
	GError *err = NULL;
	struct grid_lbpool_s *glp = NULL;
	struct meta2_backend_s *backend = NULL;
	struct sqlx_repository_s *repository = NULL;
	struct hc_resolver_s *resolver = NULL;
	struct namespace_info_s nsinfo;
	struct sqlx_repo_config_s cfg;

	g_printerr("\n");
	g_assert(ns != NULL);

	_init_nsinfo(&nsinfo, ns);

	g_snprintf(repodir, sizeof(repodir), "/tmp/repo-%d", getpid());
	g_mkdir_with_parents(repodir, 0755);

	glp = _init_lb(ns);

	resolver = hc_resolver_create();
	g_assert(resolver != NULL);

	memset(&cfg, 0, sizeof(cfg));
	cfg.flags = SQLX_REPO_DELETEON;
	cfg.lock.ns = "NS";
	cfg.lock.type = "meta2";
	cfg.lock.srv = "test-meta2";
	err = sqlx_repository_init(repodir, &cfg, &repository);
	g_assert_no_error(err);

	err = meta2_backend_init(&backend, repository, ns, glp, resolver);
	g_assert_no_error(err);
	meta2_backend_configure_nsinfo(backend, &nsinfo);

	if (fr)
		fr(backend);

	meta2_backend_clean(backend);
	sqlx_repository_clean(repository);
	hc_resolver_destroy(resolver);
	grid_lbpool_destroy(glp);
}

static void
_repo_failure(const gchar *ns)
{
	gchar repodir[512];
	GError *err = NULL;
	struct meta2_backend_s *backend = NULL;
	struct sqlx_repository_s *repository = NULL;
	struct hc_resolver_s *resolver = NULL;
	struct sqlx_repo_config_s cfg;
	struct grid_lbpool_s *glp = NULL;

	g_assert(ns != NULL);

	g_snprintf(repodir, sizeof(repodir), "/tmp/repo-%d", getpid());
	g_mkdir_with_parents(repodir, 0755);

	glp = _init_lb(ns);

	resolver = hc_resolver_create();
	g_assert(resolver != NULL);

	g_printerr("\n");
	memset(&cfg, 0, sizeof(cfg));
	cfg.flags = SQLX_REPO_DELETEON;
	cfg.lock.ns = "NS";
	cfg.lock.type = "meta2";
	cfg.lock.srv = "test-meta2";
	err = sqlx_repository_init(repodir, &cfg, &repository);
	g_assert_no_error(err);
	err = meta2_backend_init(&backend, repository, ns, glp, resolver);
	g_assert_error(err, GQ(), 400);

	meta2_backend_clean(backend);
	sqlx_repository_clean(repository);
	hc_resolver_destroy(resolver);
}

static void
_container_wraper(container_test_f cf)
{
	void test(struct meta2_backend_s *m2) {
		struct m2v2_create_params_s params = {NULL, NULL, FALSE};
		struct hc_url_s *url;
		GError *err;

		gchar *strurl = g_strdup_printf(
				"/NS/container-%"G_GUINT64_FORMAT"/content-%ld",
				++container_counter, time(0));
		url = hc_url_init(strurl);
		g_free(strurl);

		err = meta2_backend_create_container(m2, url, &params);
		g_assert_no_error(err);

		err = meta2_backend_open_container(m2, url);
		g_assert_no_error(err);

		if (cf)
			cf(m2, url);

		err = meta2_backend_close_container(m2, url);
		g_assert_no_error(err);

		hc_url_clean(url);
	}

	_repo_wraper("NS", test);
}

static void
test_backend_create_destroy(void)
{
	_repo_wraper("NS", NULL);
}

static void
test_backend_strange_ns(void)
{
	static gchar ns_255[256];
	static gchar ns_256[257];

	void test(struct meta2_backend_s *m2) {
		g_assert(strlen(m2->ns_name) > 0);
		g_assert(NULL == strchr(m2->ns_name, '.'));
	}

	/* successful creations */
	_repo_wraper("NS", test);
	_repo_wraper("NS00", test);
	_repo_wraper("NS000", test);
	memset(ns_255, '0', sizeof(ns_255));
	ns_255[0] = 'N';
	ns_255[1] = 'S';
	ns_255[sizeof(ns_255)-1] = 0;
	_repo_wraper(ns_255, test);
	_repo_wraper("NS.VNS0", test);

	memset(ns_256, '0', sizeof(ns_256));
	ns_256[0] = 'N';
	ns_256[1] = 'S';
	ns_256[2] = '.';
	ns_256[sizeof(ns_256)-1] = 0;
	_repo_wraper(ns_256, test);

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
	_container_wraper(NULL);
}

static void
test_content_delete_not_found(void)
{
	void test(struct meta2_backend_s *m2, struct hc_url_s *u) {
		GError *err = meta2_backend_delete_alias(m2, u, FALSE, NULL, NULL);
		g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
		g_clear_error(&err);
	}
	_container_wraper(test);
}

static void
test_content_put_no_beans(void)
{
	void test(struct meta2_backend_s *m2, struct hc_url_s *u) {
		GError *err = meta2_backend_put_alias(m2, u, NULL, NULL, NULL);
		g_assert_error(err, GQ(), 400);
		g_clear_error(&err);
	}
	_container_wraper(test);
}

static void
test_content_put_prop_get(void)
{
	void test(struct meta2_backend_s *m2, struct hc_url_s *u) {
		GSList *beans;
		guint expected;
		GPtrArray *tmp;
		GError *err;

		/* insert a new alias */
		beans = _create_alias(m2, u, NULL);
		err = meta2_backend_put_alias(m2, u, beans, NULL, NULL);
		g_assert_no_error(err);
		_bean_cleanl2(beans);

		CHECK_ALIAS_VERSION(m2,u,1);
		check_list_count(m2,u,1);

		/* set some properties */
		beans = _props_generate(u, 1, 10);
		err = meta2_backend_set_properties(m2, u, beans, NULL, NULL);
		g_assert_no_error(err);
		_bean_cleanl2(beans);

		CHECK_ALIAS_VERSION(m2,u,(_versioned(m2,u)?2:1));
		check_list_count(m2,u,(_versioned(m2,u)?2:1));

		/* check we got our beans */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_ALLVERSION, _appender, tmp);
		g_assert_no_error(err);
		expected = 10 + (_versioned(m2,u)?2:1) * (2+2*chunks_count);
		GRID_DEBUG("TEST count=%u expected=%u", tmp->len, expected);
		_debug_beans_array(tmp);
		g_assert(tmp->len == expected);
		_bean_cleanv2(tmp);

		/* delete the bean */
		err = meta2_backend_delete_alias(m2, u, FALSE, NULL, NULL);
		g_assert_no_error(err);

		CHECK_ALIAS_VERSION(m2,u,(_versioned(m2,u)?3:1));
		check_list_count(m2,u,(_versioned(m2,u)?3:1));

		/* check we get nothing when looking for a valid version */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_NODELETED, _appender, tmp);
		g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
		expected = 0;
		GRID_DEBUG("TEST count=%u expected=%u", tmp->len, expected);
		g_assert(tmp->len == expected);
		_bean_cleanv2(tmp);

		/* Check we can undelete (by deleting deleted version) */
		err = meta2_backend_delete_alias(m2, u, FALSE, NULL, NULL);
		g_assert_no_error(err);

		CHECK_ALIAS_VERSION(m2,u,(_versioned(m2,u)?2:1));
		check_list_count(m2,u,(_versioned(m2,u)?2:1));
	}
	_container_wraper(test);
}

static void
test_content_put_get_delete(void)
{
	void test(struct meta2_backend_s *m2, struct hc_url_s *u) {
		guint expected;
		GPtrArray *tmp;
		GError *err;

		/* insert a new alias */
		GSList *beans = _create_alias(m2, u, NULL);
		err = meta2_backend_put_alias(m2, u, beans, NULL, NULL);
		g_assert_no_error(err);
		_bean_cleanl2(beans);

		CHECK_ALIAS_VERSION(m2,u,1);
		check_list_count(m2,u,1);

		/* check we got our beans */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_ALLVERSION, _appender, tmp);
		g_assert_no_error(err);
		expected = 2+2*chunks_count;
		g_assert(tmp->len == expected);
		_bean_cleanv2(tmp);

		check_list_count(m2,u,1);

		/* delete the bean */
		err = meta2_backend_delete_alias(m2, u, FALSE, NULL, NULL);
		g_assert_no_error(err);

		CHECK_ALIAS_VERSION(m2,u,2); // v1: original, v2: copy with 'deleted' flag
		check_list_count(m2,u,2);

		/* check we get nothing when looking for a valid version */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_NODELETED, _appender, tmp);
		g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
		g_assert(tmp->len == 0);
		_bean_cleanv2(tmp);

		check_list_count(m2,u,2);

		/* check there are 2 versions */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_ALLVERSION, _appender, tmp);
		g_assert_no_error(err);
		// nb_versions * (1 alias + 1 content header + chunks_count * (1 chunk + 1 content))
		expected = 2 * (2 + 2 * chunks_count);
		GRID_DEBUG("TEST Got %u beans for all versions, expected %u (chunks count: %"G_GINT64_FORMAT")",
				tmp->len, expected, chunks_count);
		g_assert(tmp->len == expected);
		_bean_cleanv2(tmp);

		/* Check we can undelete (by deleting deleted version) */
		tmp = g_ptr_array_new();
		err = meta2_backend_delete_alias(m2, u, FALSE, NULL, NULL);
		g_assert_no_error(err);
		_bean_cleanv2(tmp);

		CHECK_ALIAS_VERSION(m2,u,1);
	}
	_container_wraper(test);
}

static void
test_content_append_empty(void)
{
	void test(struct meta2_backend_s *m2, struct hc_url_s *u) {
		GError *err = meta2_backend_append_to_alias(m2, u, NULL, NULL, NULL);
		g_assert_error(err, GQ(), 400);
		g_clear_error(&err);
	}
	_container_wraper(test);
}

static void
test_content_append(void)
{
	void test(struct meta2_backend_s *m2, struct hc_url_s *u) {
		GPtrArray *tmp;
		GSList *beans = NULL;
		GError *err;
		guint expected;

		/* generate the beans for an alias of 3 chunks */
		beans = _create_alias(m2, u, NULL);

		/* first PUT */
		err = meta2_backend_put_alias(m2, u, beans, NULL, NULL);
		g_assert_no_error(err);

		CHECK_ALIAS_VERSION(m2,u,1);

		/* count the beans */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_ALLVERSION, _appender, tmp);
		g_assert_no_error(err);
		expected = 1 + 1 + (2*chunks_count);
		GRID_DEBUG("TEST Found %u beans (ALLVERSION)", tmp->len);
		g_assert(tmp->len == expected);
		_bean_cleanv2(tmp);

		/* append */
		err = meta2_backend_append_to_alias(m2, u, beans, NULL, NULL);
		g_assert_no_error(err);

		CHECK_ALIAS_VERSION(m2,u,2);

		/* check we got our beans */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_ALLVERSION, _appender, tmp);
		g_assert_no_error(err);
		expected = 2 /* alias */ + 2 /* headers */
			+ (2*chunks_count) /* original chunks+contents */
			+ (2*chunks_count) /* new chunks+contents duplicated */
			+ (2*chunks_count); /* new chunks appended */
		GRID_DEBUG("TEST After the append, got %u, expected %u", tmp->len, expected);
		g_assert(tmp->len == expected);
		_bean_cleanv2(tmp);

		/* delete the bean */
		err = meta2_backend_delete_alias(m2, u, FALSE, NULL, NULL);
		g_assert_no_error(err);

		CHECK_ALIAS_VERSION(m2,u,3);

		/* check we get nothing when looking for a valid version */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_NODELETED, _appender, tmp);
		g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
		GRID_DEBUG("TEST Found %u beans (NODELETED)", tmp->len);
		g_assert(tmp->len == 0);
		_bean_cleanv2(tmp);

		/* check we can get both deleted and previous versions */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_ALLVERSION, _appender, tmp);
		g_assert_no_error(err);
		_debug_beans_array(tmp);
		expected = 3+3+(10*chunks_count);
		g_assert_cmpint(tmp->len, ==, expected);
		_bean_cleanv2(tmp);

		_bean_cleanl2(beans);
	}
	_container_wraper(test);
}

static void
test_content_append_not_found(void)
{
	void test(struct meta2_backend_s *m2, struct hc_url_s *u) {
		guint expected;
		GPtrArray *tmp;
		GSList *beans = NULL;
		GError *err;

		beans = _create_alias(m2, u, NULL);

		/* first PUT */
		err = meta2_backend_append_to_alias(m2, u, beans, NULL, NULL);
		g_assert_no_error(err);

		CHECK_ALIAS_VERSION(m2,u,1);

		/* count the beans */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_ALLVERSION, _appender, tmp);
		g_assert_no_error(err);
		expected = 1 + 1 + (2*chunks_count);
		g_assert(tmp->len == expected);
		_bean_cleanv2(tmp);

		/* re-APPEND */
		err = meta2_backend_append_to_alias(m2, u, beans, NULL, NULL);
		g_assert_no_error(err);
		_bean_cleanl2(beans);

		CHECK_ALIAS_VERSION(m2,u,2);

		/* count the beans */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_ALLVERSION, _appender, tmp);
		g_assert_no_error(err);
		expected = 2 /* alias */
			+ 2 /* headers */
			+ (2*chunks_count) /* original chunks+contents */
			+ (2*chunks_count) /* new chunks+contents duplicated */
			+ (2*chunks_count); /* new chunks appended */
		g_assert(tmp->len == expected);
		_bean_cleanv2(tmp);

		/* delete the bean */
		err = meta2_backend_delete_alias(m2, u, FALSE, NULL, NULL);
		g_assert_no_error(err);

		CHECK_ALIAS_VERSION(m2,u,3);


		/* check we get nothing when looking for a valid version */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_NODELETED, _appender, tmp);
		g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
		g_assert(tmp->len == 0);
		_bean_cleanv2(tmp);

		/* check we can get both deleted and previous versions */
		tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2, u, M2V2_FLAG_ALLVERSION, _appender, tmp);
		g_assert_no_error(err);
		_debug_beans_array(tmp);
		_bean_cleanv2(tmp);
	}
	_container_wraper(test);
}

static void
test_props_gotchas()
{
	void test(struct meta2_backend_s *m2, struct hc_url_s *u) {
		GError *err;
		GSList *beans;

		err = meta2_backend_set_properties(m2, u, NULL, NULL, NULL);
		g_assert_error(err, GQ(), 400);
		g_clear_error(&err);

		err = meta2_backend_get_properties(m2, u, 0, NULL, NULL);
		g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
		g_clear_error(&err);

		beans = _props_generate(u, 1, 10);
		err = meta2_backend_set_properties(m2, u, beans, NULL, NULL);
		g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
		g_clear_error(&err);
		_bean_cleanl2(beans);
	}
	_container_wraper(test);
}

static void
test_props_set_simple()
{
	void test(struct meta2_backend_s *m2, struct hc_url_s *u) {
		GError *err;
		GSList *beans;

		/* add a content */
		beans = _create_alias(m2, u, NULL);
		err = meta2_backend_put_alias(m2, u, beans, NULL, NULL);
		g_assert_no_error(err);
		_bean_cleanl2(beans);

		CHECK_ALIAS_VERSION(m2,u,1);

		/* set it properties */
		beans = _props_generate(u, 1, 10);
		err = meta2_backend_set_properties(m2, u, beans, NULL, NULL);
		g_assert_no_error(err);
		_bean_cleanl2(beans);

		CHECK_ALIAS_VERSION(m2,u,(_versioned(m2,u)?2:1));
	}
	_container_wraper(test);
}

static void
test_props_set_deleted()
{
	void test(struct meta2_backend_s *m2, struct hc_url_s *u) {
		GError *err;
		GSList *beans;

		/* add a content */
		beans = _create_alias(m2, u, NULL);
		err = meta2_backend_put_alias(m2, u, beans, NULL, NULL);
		g_assert_no_error(err);
		_bean_cleanl2(beans);

		CHECK_ALIAS_VERSION(m2,u,1);

		/* delete the content */
		err = meta2_backend_delete_alias(m2, u, FALSE, NULL, NULL);
		g_assert_no_error(err);

		CHECK_ALIAS_VERSION(m2,u,(_versioned(m2,u)?2:1));

		/* set it properties */
		beans = _props_generate(u, 1, 10);
		err = meta2_backend_set_properties(m2, u, beans, NULL, NULL);
		g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
		g_clear_error(&err);
		_bean_cleanl2(beans);

		CHECK_ALIAS_VERSION(m2,u,(_versioned(m2,u)?2:1));

		// XXX: why do we check a second time?
		/* set it properties */
		beans = _props_generate(u, 1, 10);
		err = meta2_backend_set_properties(m2, u, beans, NULL, NULL);
		g_assert_error(err, GQ(), CODE_CONTENT_NOTFOUND);
		g_clear_error(&err);
		_bean_cleanl2(beans);

		CHECK_ALIAS_VERSION(m2,u,(_versioned(m2,u)?2:1));
	}
	_container_wraper(test);
}

int
main(int argc, char **argv)
{
	if (!g_thread_supported())
		g_thread_init(NULL);
	g_set_prgname(argv[0]);

	g_test_init (&argc, &argv, NULL);
	g_log_set_default_handler(logger_stderr, NULL);
	logger_init_level(GRID_LOGLVL_TRACE2);

	container_counter = random();

	g_test_add_func("/meta2v2/backend/backend/strange_ns",
			test_backend_strange_ns);
	g_test_add_func("/meta2v2/backend/backend/create_destroy",
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
	g_test_add_func("/meta2v2/backend/content/append",
			test_content_append);
	g_test_add_func("/meta2v2/backend/content/append_notfound",
			test_content_append_not_found);
	g_test_add_func("/meta2v2/backend/props/set_simple",
			test_props_set_simple);
	g_test_add_func("/meta2v2/backend/props/set_deleted",
			test_props_set_deleted);
	g_test_add_func("/meta2v2/backend/props/gotchas",
			test_props_gotchas);

	return g_test_run();
}

