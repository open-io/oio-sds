/*
OpenIO SDS metautils
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <math.h>

#include <metautils/lib/metautils.h>

#define SRVTYPE "sqlx"

#define ADDR_GOOD "127.0.0.1"
#define ADDR_BAD  "127.0.0.2"
#define NS "NS"

static guint max_feed = 37;
static guint max_get = 5001;

static struct service_info_s *
_build_si(const gchar *a, guint i)
{
	struct service_info_s *si;

	si = g_malloc0(sizeof(*si));
	g_strlcpy(si->ns_name, NS, sizeof(si->ns_name));
	g_strlcpy(si->type, SRVTYPE, sizeof(si->type));
	si->addr.addr.v4 = inet_addr(a);
	si->addr.type = TADDR_V4;
	si->addr.port = htons(i+2);
	si->score.value = i;
	si->score.timestamp = oio_ext_real_time () / G_TIME_SPAN_SECOND;
	return si;
}

static struct service_info_s *
_build_si_loc(const gchar *a, guint i)
{
	struct service_info_s *si = _build_si(a, i);

	if (!si->tags)
		si->tags = g_ptr_array_new();
	service_tag_t *tag = service_info_ensure_tag(si->tags, NAME_TAGNAME_RAWX_LOC);
	char tag_loc[32] = {0};
	g_snprintf(tag_loc, sizeof(tag_loc), "loc.%u", i);
	service_tag_set_value_string(tag, tag_loc);

	return si;
}

static guint
_fill(struct grid_lbpool_s *lbp, const char *srvtype, guint max)
{
	guint i, count;

	gboolean provide(struct service_info_s **p_si) {
		g_assert(p_si != NULL);
		if (i >= max)
			return FALSE;
		*p_si = _build_si_loc(ADDR_GOOD, i++);
		count ++;
		return TRUE;
	}

	i = count = 0;
	grid_lbpool_reload(lbp, srvtype, &provide);

	g_assert(count == max);
	return count;
}

static void
check_presence(gboolean expected, struct grid_lb_iterator_s *iter,
		struct service_info_s *si)
{
	gchar *k = service_info_key (si);
	STRING_STACKIFY(k);
	k = strrchr(k, '|') + 1;  // Hack to make the test pass until we remove it
	gboolean available = grid_lb_iterator_is_url_available(iter, k);
	g_assert(BOOL(available) == BOOL(expected));
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

	si = _build_si(ADDR_GOOD, max_feed + 1);
	check_presence(FALSE, iter, si);
	service_info_clean(si);

	si = _build_si(ADDR_GOOD, 1);
	si->addr.port = htons(1U);
	check_presence(FALSE, iter, si);
	service_info_clean(si);

	si = _build_si(ADDR_GOOD, max_feed + 1);
	check_presence(FALSE, iter, si);
	service_info_clean(si);

	si = _build_si(ADDR_GOOD, 0);
	check_presence(FALSE, iter, si);
	service_info_clean(si);
}

static gint
cmp_addr(gconstpointer a, gconstpointer b, gpointer user_data)
{
	(void) user_data;
	return addr_info_compare(a, b);
}

static void
_compute_repartition(GTree *used, struct service_info_s **siv)
{
	while (*siv) {
		struct service_info_s *si = *siv;
		guint *pi = g_tree_lookup(used, &(si->addr));
		if (!pi) {
			pi = g_malloc0(sizeof(guint));
			*pi = 1;
			g_tree_insert(used, g_memdup(&(si->addr), sizeof(struct addr_info_s)), pi);
		}
		else {
			++ *pi;
		}
	}
}

static void
_check_repartition_uniform(GTree *used, gdouble ratio)
{
	gint64 count = 0, total = 0;
	gdouble average = 0.0, min = 0.0, max = 0.0;

	gboolean hook_sum(gpointer ai, guint *pi, gpointer ignored) {
		(void) ai, (void) ignored;
		total += *pi;
		++ count;
		return FALSE;
	}
	gboolean hook_check(gpointer ai, guint *pi, gpointer ignored) {
		(void) ai, (void) ignored;
		gdouble current = *pi;
		g_debug("count=%f average=%f min=%f max=%f", current, average, min, max);
		g_assert(current <= max);
		g_assert(current >= min);
		return FALSE;
	}

	g_tree_foreach(used, (GTraverseFunc)hook_sum, NULL);
	if (count > 0) {
		average = (gdouble)total / (gdouble)count;
		min = floor(average * (1.0 - ratio));
		max = ceil(average * (1.0 + ratio));
	}
	g_tree_foreach(used, (GTraverseFunc)hook_check, NULL);
	g_assert((guint)g_tree_nnodes(used) == max_feed - 1);
}

static void
generate_set_and_check_uniform_repartition(struct grid_lb_iterator_s *iter,
		gdouble ratio)
{
	struct service_info_s **siv = NULL;
	GTree *used = g_tree_new_full(cmp_addr, NULL, g_free, g_free);

	struct lb_next_opt_ext_s opt = {0};
	opt.max = max_get;
	opt.distance = 1;
	opt.weak_distance = 1;
	opt.duplicates = TRUE;
	gboolean rc = grid_lb_iterator_next_set2(iter, &siv, &opt, NULL);
	g_assert(rc != FALSE);

	_compute_repartition(used, siv);
	_check_repartition_uniform(used, ratio);
	g_tree_destroy(used);
	service_info_cleanv(siv, FALSE);
}

static void
generate_1by1_and_check_uniform_repartition(struct grid_lb_iterator_s *iter,
		gdouble ratio)
{
	GTree *used = g_tree_new_full(cmp_addr, NULL, g_free, g_free);
	for (guint i=0; i<max_get; ++i) {
		struct service_info_s **siv = NULL;
		struct lb_next_opt_ext_s opt = {0};
		opt.max = 1;
		if (!grid_lb_iterator_next_set2(iter, &siv, &opt, NULL))
			break;
		if (!siv)
			break;
		_compute_repartition(used, siv);
		service_info_cleanv(siv, FALSE);
	}
	_check_repartition_uniform(used, ratio);
	g_tree_destroy(used);
}

static guint
_count_set(struct grid_lb_iterator_s *iter, guint max, gboolean weak,
		gboolean expect)
{
	struct service_info_s **siv = NULL;
	gboolean rc;

	struct lb_next_opt_ext_s opt = {0};
	opt.max = max;
	opt.distance = 1;
	opt.weak_distance = weak;
	opt.duplicates = TRUE;

	rc = grid_lb_iterator_next_set2(iter, &siv, &opt, NULL);
	g_assert(rc == expect);

	if (expect) {
		guint count = g_strv_length((gchar**)siv);
		service_info_cleanv(siv, FALSE);
		return count;
	}
	return 0;
}

static guint
_count_single(struct grid_lb_iterator_s *iter, guint max)
{
	guint count = 0;

	while ((max--) > 0) {
		struct service_info_s **siv = NULL;
		struct lb_next_opt_ext_s opt = {0};
		opt.max = 1;
		if (!grid_lb_iterator_next_set2(iter, &siv, &opt, NULL))
			break;
		service_info_cleanv(siv, FALSE);
		count ++;
	}

	return count;
}

static void
check_service_count(struct grid_lb_iterator_s *iter)
{
	g_assert(iter != NULL);
	check_not_found(iter);
	g_assert(max_get == _count_single(iter, max_get));

	// Half the number of services in the pool -> should work
	g_assert(_count_set(iter, max_feed / 2, FALSE, TRUE) == max_feed / 2);

	// More services than the number in the pool -> should fail
	g_assert(_count_set(iter, max_feed + 10, FALSE, FALSE) == 0);
	// More services than the number in the pool, but weak distance -> should work
	g_assert(_count_set(iter, max_feed + 10, TRUE, TRUE) == (max_feed + 10));

	// Far more services than the number in the pool -> should fail
	g_assert(_count_set(iter, max_get, FALSE, FALSE) == 0);
	// Far more services than the number in the pool, but weak distance -> should work
	g_assert(_count_set(iter, max_get, TRUE, TRUE) == max_get);
}

static void
check_service_count_near_limit(struct grid_lb_iterator_s *iter)
{
	// One service less than the number in the pool -> should work
	g_assert(_count_set(iter, max_feed - 2, FALSE, TRUE) == max_feed - 2);
	// As much services as the number in the pool -> should work
	g_assert(_count_set(iter, max_feed - 1, FALSE, TRUE) == max_feed - 1);
}

static void
test_lb_RR(void)
{
	struct grid_lbpool_s *lbp = grid_lbpool_create (NS);
	struct grid_lb_iterator_s *iter = grid_lbpool_ensure_iterator (lbp, SRVTYPE);
	grid_lbpool_configure_string (lbp, SRVTYPE, "RR");
	_fill (lbp, SRVTYPE, max_feed);

	check_service_count(iter);
	check_service_count_near_limit(iter);
	generate_1by1_and_check_uniform_repartition(iter, 0.01);
	generate_set_and_check_uniform_repartition(iter, 0.01);

	grid_lb_iterator_clean(iter);
	grid_lbpool_destroy (lbp);
}

static void
test_lb_WRR(void)
{
	struct grid_lbpool_s *lbp = grid_lbpool_create (NS);
	struct grid_lb_iterator_s *iter = grid_lbpool_ensure_iterator (lbp, SRVTYPE);
	grid_lbpool_configure_string (lbp, SRVTYPE, "WRR");
	_fill (lbp, SRVTYPE, max_feed);

	check_service_count(iter);
	check_service_count_near_limit(iter);

	grid_lb_iterator_clean(iter);
	grid_lbpool_destroy(lbp);
}

static void
test_lb_RAND(void)
{
	struct grid_lbpool_s *lbp = grid_lbpool_create (NS);
	struct grid_lb_iterator_s *iter = grid_lbpool_ensure_iterator (lbp, SRVTYPE);
	grid_lbpool_configure_string (lbp, SRVTYPE, "RAND");
	_fill (lbp, SRVTYPE, max_feed);

	check_service_count(iter);
	generate_1by1_and_check_uniform_repartition(iter, 0.3);
	generate_set_and_check_uniform_repartition(iter, 0.3);

	grid_lb_iterator_clean(iter);
	grid_lbpool_destroy(lbp);
}

static void
test_lb_WRAND(void)
{
	struct grid_lbpool_s *lbp = grid_lbpool_create (NS);
	struct grid_lb_iterator_s *iter = grid_lbpool_ensure_iterator (lbp, SRVTYPE);
	grid_lbpool_configure_string (lbp, SRVTYPE, "WRAND");
	_fill (lbp, SRVTYPE, max_feed);

	check_service_count(iter);

	grid_lb_iterator_clean(iter);
	grid_lbpool_destroy (lbp);
}

static void
test_pool_create_destroy(void)
{
	struct grid_lbpool_s *glp = grid_lbpool_create("NS");
	g_assert(glp != NULL);
	grid_lbpool_destroy(glp);
}

/* -------------------------------------------------------------------------- */

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/grid/lb/WRAND", test_lb_WRAND);
	g_test_add_func("/grid/lb/RAND", test_lb_RAND);
	g_test_add_func("/grid/lb/WRR", test_lb_WRR);
	g_test_add_func("/grid/lb/RR", test_lb_RR);
	g_test_add_func("/grid/pool/create_destroy", test_pool_create_destroy);
	return g_test_run();
}

