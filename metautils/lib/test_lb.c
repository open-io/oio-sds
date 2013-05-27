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
# define G_LOG_DOMAIN "grid.lb.test"
#endif

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

#include <arpa/inet.h>

#include <glib.h>

#include <metautils.h>

#include "./lb.h"
#include "./loggers.h"

#define BOOL(B) ((B)?1:0)

#define SRVTYPE "sqlx"

#define ADDR_GOOD "127.0.0.1"
#define ADDR_BAD  "127.0.0.2"

static gboolean print_out = FALSE;
static guint max_feed = 10;
static guint max_get = 10000;

static struct service_info_s *
_build_si(const gchar *a, guint i)
{
	struct service_info_s *si;

	si = g_malloc0(sizeof(*si));
	g_strlcpy(si->ns_name, "NS", sizeof(si->ns_name));
	g_strlcpy(si->type, SRVTYPE, sizeof(si->type));
	si->addr.addr.v4 = inet_addr(a);
	si->addr.type = TADDR_V4;
	si->addr.port = htons(i+2);
	si->score.value = i;
	si->score.timestamp = time(0);
	return si;
}

static guint
_fill(struct grid_lb_s *lb, guint max)
{
	guint i, count;
	int dump;

	gboolean provide(struct service_info_s **p_si) {
		g_assert(p_si != NULL);
		if (i >= max)
			return FALSE;
		*p_si = _build_si(ADDR_GOOD, i ++);
		if (dump) {
			gchar *str = service_info_to_string(*p_si);
			g_free(str);
		}
		count ++;
		return TRUE;
	}

	dump = 0;
	i = count = 0;
	grid_lb_reload(lb, &provide);

	dump = 1;
	i = count = 0;
	grid_lb_reload(lb, &provide);

	g_assert(count == max);
	return count;
}

static struct grid_lb_s *
_build(void)
{
	struct grid_lb_s *lb;

	lb = grid_lb_init("NS", SRVTYPE);
	g_assert(lb != NULL);

	_fill(lb, max_feed);
	return lb;
}

static void
check_presence(gboolean expected, struct grid_lb_iterator_s *iter, struct service_info_s *si)
{
	gboolean available;
	gchar *str;

	available = grid_lb_iterator_is_srv_available(iter, si);
	available = BOOL(available);
	expected = BOOL(expected);

	str = service_info_to_string(si);
	g_free(str);

	g_assert(available == expected);
}

static void
check_not_found(struct grid_lb_iterator_s *iter)
{
	struct service_info_s *si;

	si = _build_si(ADDR_GOOD, 1);
	check_presence(TRUE, iter, si);
	service_info_clean(si);

	si = _build_si(ADDR_BAD, 1);
	check_presence(FALSE, iter, si);
	service_info_clean(si);

	si = _build_si(ADDR_BAD, 1);
	si->addr.port = htons(1U);
	check_presence(FALSE, iter, si);
	service_info_clean(si);


	si = _build_si(ADDR_GOOD, max_feed);
	check_presence(FALSE, iter, si);
	service_info_clean(si);

	si = _build_si(ADDR_GOOD, 1);
	si->addr.port = htons(1U);
	check_presence(FALSE, iter, si);
	service_info_clean(si);

	si = _build_si(ADDR_GOOD, max_feed);
	check_presence(FALSE, iter, si);
	service_info_clean(si);

	si = _build_si(ADDR_GOOD, 0);
	check_presence(FALSE, iter, si);
	service_info_clean(si);
}

static guint
_count(struct grid_lb_iterator_s *iter, const gchar *tag, guint max)
{
	gchar path[1024];
	FILE *out = NULL;
	guint count = 0;

	if (print_out) {
		g_snprintf(path, sizeof(path), "/tmp/%s.out", tag);
		out = fopen(path, "w");
		g_assert(out != NULL);
	}
	
	while ((max--) > 0) {
		struct service_info_s *si = NULL;
		if (!grid_lb_iterator_next(iter, &si, 300))
			break;

		if (out) {
			gchar addr[64];
			addr_info_to_string(&(si->addr), addr, sizeof(addr));
		}

		service_info_clean(si);
		count ++;
	}

	if (out)
		fclose(out);
	return count;
}

#if 0
static void
test_lb_SINGLE(void)
{
	struct grid_lb_s *lb;
	struct grid_lb_iterator_s *iter;

	lb = _build();
	iter = grid_lb_iterator_single_run(lb);

	g_assert(iter != NULL);

	check_not_found(iter);

	g_assert(MIN(max_feed,max_get) == _count(iter, __FUNCTION__, max_get));

	grid_lb_iterator_clean(iter);
	grid_lb_clean(lb);
}
#endif

static void
test_lb_RR(void)
{
	struct grid_lb_s *lb;
	struct grid_lb_iterator_s *iter;

	lb = _build();
	iter = grid_lb_iterator_round_robin(lb);

	g_assert(iter != NULL);

	check_not_found(iter);

	g_assert(max_get == _count(iter, __FUNCTION__, max_get));

	grid_lb_iterator_clean(iter);
	grid_lb_clean(lb);
}

static void
test_lb_WRR(void)
{
	struct grid_lb_s *lb;
	struct grid_lb_iterator_s *iter;

	lb = _build();
	iter = grid_lb_iterator_weighted_round_robin(lb);

	g_assert(iter != NULL);

	check_not_found(iter);

	g_assert(max_get == _count(iter, __FUNCTION__, max_get));

	grid_lb_iterator_clean(iter);
	grid_lb_clean(lb);
}

static void
test_lb_SRR(void)
{
	struct grid_lb_s *lb;
	struct grid_lb_iterator_s *iter;

	lb = _build();
	iter = grid_lb_iterator_scored_round_robin(lb);

	g_assert(iter != NULL);

	check_not_found(iter);

	g_assert(max_get == _count(iter, __FUNCTION__, max_get));

	grid_lb_iterator_clean(iter);
	grid_lb_clean(lb);
}

static void
test_lb_RAND(void)
{
	struct grid_lb_s *lb;
	struct grid_lb_iterator_s *iter;

	lb = _build();
	iter = grid_lb_iterator_random(lb);

	g_assert(iter != NULL);

	check_not_found(iter);

	g_assert(max_get == _count(iter, __FUNCTION__, max_get));

	grid_lb_iterator_clean(iter);
	grid_lb_clean(lb);
}

static void
test_lb_WRAND(void)
{
	struct grid_lb_s *lb;
	struct grid_lb_iterator_s *iter;

	lb = _build();
	iter = grid_lb_iterator_weighted_random(lb);

	g_assert(iter != NULL);

	check_not_found(iter);

	g_assert(max_get == _count(iter, __FUNCTION__, max_get));

	grid_lb_iterator_clean(iter);
	grid_lb_clean(lb);
}

static void
test_lb_SRAND(void)
{
	struct grid_lb_s *lb;
	struct grid_lb_iterator_s *iter;

	lb = _build();

	iter = grid_lb_iterator_scored_random(lb);

	g_assert(iter != NULL);

	check_not_found(iter);

	g_assert(max_get == _count(iter, __FUNCTION__, max_get));

	grid_lb_iterator_clean(iter);
	grid_lb_clean(lb);
}

/* -------------------------------------------------------------------------- */

int
main(int argc, char **argv)
{
	srand(time(0) ^ getpid());
	if (!g_thread_supported())
		g_thread_init(NULL);
	g_set_prgname(argv[0]);
	g_log_set_handler(NULL, G_LOG_LEVEL_MASK|G_LOG_FLAG_FATAL, logger_stderr, NULL);
	g_test_init (&argc, &argv, NULL);

	g_test_add_func("/grid/lb/WRAND", test_lb_WRAND);
	g_test_add_func("/grid/lb/SRAND", test_lb_SRAND);
	g_test_add_func("/grid/lb/RAND", test_lb_RAND);
	g_test_add_func("/grid/lb/SRR", test_lb_SRR);
	g_test_add_func("/grid/lb/WRR", test_lb_WRR);
	g_test_add_func("/grid/lb/RR", test_lb_RR);
	/*g_test_add_func("/grid/lb/SINGLE", test_lb_SINGLE);*/

	return g_test_run();
}

