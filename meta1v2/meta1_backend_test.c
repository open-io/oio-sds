#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.meta1.test"
#endif

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <metautils/lib/metautils.h>
#include <sqliterepo/sqliterepo.h>

#include "./internals.h"
#include "./meta1_backend.h"
#include "./meta1_prefixes.h"

static struct grid_lbpool_s *glp = NULL;

static gboolean flag_destroy = FALSE;
static container_id_t cid;
static const gchar *basedir = "/tmp/repo";
static const gchar *ns = "NS";
static const gchar *vns = "NS.test";
static const gchar *cname = "JFS";
static const gchar *srvname = "meta2";
static const gchar *local_url = "127.0.0.1:65535";
gchar *meta1_url = NULL;
static gchar zk_url[512];

static void
assert_noerror(GError *err)
{
	if (err != NULL)
		g_error("ERROR! code=%d message=%s", err->code, err->message);
}

static struct meta1_backend_s *
_meta1_init(void)
{
	struct sqlx_repo_config_s cfg;
	struct meta1_backend_s *m1 = NULL;
	struct sqlx_repository_s *repo = NULL;
	GError *err;

	memset(&cfg, 0, sizeof(cfg));
	err = sqlx_repository_init(basedir, &cfg, &repo);
	m1 = meta1_backend_init(ns, repo, glp);
	assert_noerror(err);
	g_assert(m1 != NULL);

	err = meta1_prefixes_manage_all(meta1_backend_get_prefixes(m1), local_url);
	assert_noerror(err);

	assert_noerror(err);

	return m1;
}

static struct service_info_s *
__build_si(guint i)
{
	struct service_info_s *si;

	si = g_malloc0(sizeof(*si));
	g_strlcpy(si->ns_name, ns, sizeof(si->ns_name));
	g_strlcpy(si->type, "meta2", sizeof(si->type));
	if (!inet_pton(AF_INET, "127.0.0.1", &(si->addr.addr.v4))) {
		g_free(si);
		return NULL;
	}
	si->addr.type = TADDR_V4;
	si->addr.port = htons(i);
	si->score.value = i+1;
	si->score.timestamp = time(0);
	return si;
}

static struct grid_lbpool_s *
lb_init(void)
{
	guint i, count, max;

	gboolean __provide(struct service_info_s **p_si) {
		g_assert(p_si != NULL);
		if (i >= max)
			return FALSE;
		*p_si = __build_si(i ++);
		count ++;
		return TRUE;
	}

	struct grid_lbpool_s *g = grid_lbpool_create(ns);
	g_assert(g != NULL);

	grid_lbpool_configure_string(g, "rawx", "RR");

	max = 10;
	i = count = 0;
	grid_lbpool_reload(g, srvname, &__provide);
	g_assert(count == max);

	return g;
}

static void
test_meta1_backend_create_destroy(void)
{
	GError *err;
	container_id_t local_cid;

	struct meta1_backend_s *m1 = NULL;
	m1 = _meta1_init();

	memset(local_cid, 0, sizeof(container_id_t));
	err = meta1_backend_create_container(m1, vns, cname, &local_cid);
	assert_noerror(err);
	g_assert(0 == memcmp(local_cid, cid, sizeof(container_id_t)));

	err = meta1_backend_destroy_container(m1, cid, TRUE);
	g_assert(err == NULL);

	meta1_backend_clean(m1);
}

static void
test_meta1_backend_get_all(void)
{
	GError *err;
	container_id_t local_cid;

	struct meta1_backend_s *m1 = NULL;
	m1 = _meta1_init();

	do {
		gchar **srv = NULL;
		err = meta1_backend_get_container_all_services(m1, cid, srvname, &srv);
		g_assert(err != NULL);
		g_assert(srv == NULL);
		g_clear_error(&err);
	} while (0);

	memset(local_cid, 0, sizeof(container_id_t));
	err = meta1_backend_create_container(m1, vns, cname, &local_cid);
	assert_noerror(err);
	g_assert(0 == memcmp(local_cid, cid, sizeof(container_id_t)));

	do {
		gchar **srv = NULL;
		err = meta1_backend_get_container_all_services(m1, cid, srvname, &srv);
		g_assert(err == NULL);
		g_assert(srv != NULL);
		g_strfreev(srv);
	} while (0);

	err = meta1_backend_destroy_container(m1, cid, TRUE);
	assert_noerror(err);

	meta1_backend_clean(m1);
}

static void
test_meta1_backend_get_available(void)
{
	GError *err = NULL;
	container_id_t local_cid;
	gchar strcid[STRLEN_CONTAINERID];
	struct meta1_backend_s *m1 = NULL;

	container_id_to_string(cid, strcid, sizeof(strcid));
	struct hc_url_s *u = hc_url_empty();
	hc_url_set(u, HCURL_HEXID, strcid);
	m1 = _meta1_init();

	do {
		gchar **srv = NULL;
		err = meta1_backend_get_container_service_available(m1, u, srvname,
				FALSE, &srv);
		g_assert(err != NULL);
		g_assert(srv == NULL);
		g_clear_error(&err);
	} while (0);

	memset(local_cid, 0, sizeof(container_id_t));
	err = meta1_backend_create_container(m1, vns, cname, &local_cid);
	assert_noerror(err);
	g_assert(0 == memcmp(local_cid, cid, sizeof(container_id_t)));

	do {
		gchar **srv = NULL;
		err = meta1_backend_get_container_service_available(m1, u, srvname,
				FALSE, &srv);
		assert_noerror(err);
		g_assert(srv != NULL);
		g_strfreev(srv);
	} while (0);

	if (flag_destroy) {
		err = meta1_backend_destroy_container(m1, cid, TRUE);
		assert_noerror(err);
	}

	meta1_backend_clean(m1);
}

int
main(int argc, char **argv)
{
	memset(zk_url, 0, sizeof(zk_url));
	srand(time(0) ^ getpid());
	HC_PROC_INIT(argv, GRID_LOGLVL_TRACE2);
	g_test_init (&argc, &argv, NULL);

	if (argc < 2)
		g_strlcat(zk_url, "0.0.0.0:2181", sizeof(zk_url)-1);
	else {
		int i;
		for (i=1; i<argc ;i++) {
			if (*zk_url)
				g_strlcat(zk_url, ",", sizeof(zk_url));
			g_strlcat(zk_url, argv[i], sizeof(zk_url));
		}
	}

	glp = lb_init();

	meta1_url = g_strdup(local_url);
	meta1_name2hash((guint8*)cid, vns, cname);

	g_test_add_func("/meta1/backend/create_destroy", test_meta1_backend_create_destroy);
	g_test_add_func("/meta1/backend/get_all", test_meta1_backend_get_all);
	g_test_add_func("/meta1/backend/get_available", test_meta1_backend_get_available);

	return g_test_run();
}

