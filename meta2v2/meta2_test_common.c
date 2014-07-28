#include <string.h>

#include <metautils/lib/metautils.h>

#include <sqliterepo/sqliterepo.h>

#include <meta2v2/meta2v2_remote.h>
#include <meta2v2/meta2_backend.h>
#include <meta2v2/meta2_utils.h>
#include <meta2v2/generic.h>

#include <resolver/hc_resolver.h>

#include "./meta2_test_common.h"

static guint64 container_counter = 0;
//static gint64 version = 0;
static gint64 chunk_size = 3000;
static gint64 chunks_count = 3;


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

void
debug_beans_list(GSList *l)
{
	if (!g_getenv("GS_DEBUG_ENABLED"))
		return;
	for (; l ;l=l->next) {
		GString *s = _bean_debug(NULL, l->data);
		GRID_DEBUG("TEST DUMP %s", s->str);
		g_string_free(s, TRUE);
	}
}

void
debug_beans_array(GPtrArray *v)
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

GSList*
create_alias(struct meta2_backend_s *m2b, struct hc_url_s *url,
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

	debug_beans_list(beans);
	return beans;
}

void
repo_wrapper(const gchar *ns, repo_test_f fr)
{
	gchar repodir[512];
	GError *err = NULL;
	struct meta2_backend_s *backend = NULL;
	struct sqlx_repository_s *repository = NULL;
	struct hc_resolver_s *resolver = NULL;
	struct namespace_info_s nsinfo;
	struct sqlx_repo_config_s cfg;
	struct grid_lbpool_s *glp;

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

void
container_wrapper(container_test_f cf)
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

	repo_wrapper("NS", test);
}

