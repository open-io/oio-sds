/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.meta1.test"
#endif

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <glib.h>

#include "../metautils/lib/lb.h"
#include "../sqliterepo/sqliterepo.h"

#include "./internals.h"
#include "./meta1_backend.h"
#include "./meta1_prefixes.h"

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
	GError *err;
	struct meta1_backend_s *m1 = NULL;

	err = meta1_backend_init(&m1, ns, local_url, basedir);
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

static struct grid_lb_s *
lb_init(struct grid_lb_iterator_s **iter)
{
	struct grid_lb_s *lb;
	guint i, count, max;

	auto gboolean __provide(struct service_info_s **p_si);

	gboolean __provide(struct service_info_s **p_si) {
		g_assert(p_si != NULL);
		if (i >= max)
			return FALSE;
		*p_si = __build_si(i ++);
		count ++;
		return TRUE;
	}

	max = 10;
	i = count = 0;
	lb = grid_lb_init(ns, srvname);
	g_assert(lb != NULL);
	grid_lb_reload(lb, &__provide);
	*iter = grid_lb_iterator_random(lb);
	g_assert(count == max);
	return lb;
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
	struct grid_lb_s *lb = NULL;
	struct grid_lb_iterator_s *iter = NULL;
	container_id_t local_cid;
	struct meta1_backend_s *m1 = NULL;

	m1 = _meta1_init();

	lb = lb_init(&iter);
	meta1_configure_type(m1, srvname, iter);

	do {
		gchar **srv = NULL;
		err = meta1_backend_get_container_service_available(m1, cid, srvname, &srv);
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
		err = meta1_backend_get_container_service_available(m1, cid, srvname, &srv);
		assert_noerror(err);
		g_assert(srv != NULL);
		g_strfreev(srv);
	} while (0);

	if (flag_destroy) {
		err = meta1_backend_destroy_container(m1, cid, TRUE);
		assert_noerror(err);
	}

	meta1_backend_clean(m1);
	grid_lb_iterator_clean(iter);
	grid_lb_clean(lb);
}

int
main(int argc, char **argv)
{
	memset(zk_url, 0, sizeof(zk_url));
	srand(time(0) ^ getpid());
	if (!g_thread_supported())
		g_thread_init(NULL);
	g_set_prgname(argv[0]);
	g_log_set_default_handler(logger_stderr, NULL);
	g_log_set_handler(NULL, G_LOG_LEVEL_MASK|G_LOG_FLAG_FATAL, logger_stderr, NULL);
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
	meta1_url = g_strdup(local_url);
	meta1_name2hash((guint8*)cid, vns, cname);

	g_test_add_func("/meta1/backend/create_destroy", test_meta1_backend_create_destroy);
	g_test_add_func("/meta1/backend/get_all", test_meta1_backend_get_all);
	g_test_add_func("/meta1/backend/get_available", test_meta1_backend_get_available);

	return g_test_run();
}

