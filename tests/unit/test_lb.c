/*
OpenIO SDS core / LB
Copyright (C) 2016 OpenIO, as part of OpenIO Software Defined Storage

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

#include <stdlib.h>
#include <glib.h>
#include <core/oiolb.h>
#include <metautils/lib/metautils.h>

static struct oio_lb_item_s *
_srv (int i)
{
	oio_location_t loc = i+1; // discard 0
	size_t len = 8 + sizeof (struct oio_lb_item_s);
	struct oio_lb_item_s *srv = g_malloc0 (len);
	srv->location = ((loc & ~0xFF) << 16) | (loc & 0xFF);
	srv->weight = 90 + i;
	sprintf(srv->id, "ID-%04d", i);
	return srv;
}

static void
test_local_poll (void)
{
	struct oio_lb_world_s *world = oio_lb_local__create_world ();
	oio_lb_world__create_slot (world, "0");
	oio_lb_world__create_slot (world, "1");
	oio_lb_world__create_slot (world, "2");
	oio_lb_world__create_slot (world, "*");

	/* fill some services */
	for (int i = 0; i < 1024; ++i) {
		struct oio_lb_item_s *srv = _srv (i);
		oio_lb_world__feed_slot (world, (i%2)? "1":"0", srv);
		if (!(i%3))
			oio_lb_world__feed_slot (world, "2", srv);
		oio_lb_world__feed_slot (world, "*", srv);
		g_free (srv);
	}

	oio_lb_world__debug (world);

	/* create a pool and poll it */
	struct oio_lb_pool_s *pool = oio_lb_world__create_pool (world, "pool-test");
	oio_lb_world__add_pool_target (pool, "0,1,*");
	oio_lb_world__add_pool_target (pool, "2,1,*");
	g_assert_cmpuint (oio_lb_world__count_slots (world), ==, 4);

	/* now poll some pools */
	for (int i = 0; i < 4096; i++) {
		guint count_rc, count;
		void _on_item (oio_location_t location, const char *id) {
			(void) location, (void) id;
			GRID_TRACE("Polled %s/%"OIO_LOC_FORMAT, id, location);
			++ count;
		}
		count = 0;
		count_rc = oio_lb_pool__poll (pool, NULL, _on_item);
		g_assert_cmpuint (count_rc, ==, count);
		g_assert_cmpuint (count_rc, ==, 2);
	}

	oio_lb_world__debug (world);

	oio_lb_pool__destroy (pool);
	oio_lb_world__destroy (world);
}

static void
test_local_poll_same_low_bits(void)
{
	struct oio_lb_world_s *world = oio_lb_local__create_world();
	oio_lb_world__create_slot(world, "0");
	oio_lb_world__create_slot(world, "*");

	/* fill some services */
	for (int i = 0; i < 3; ++i) {
		struct oio_lb_item_s *srv = _srv((i << 16) + 0x66);
		oio_lb_world__feed_slot(world, "0", srv);
		oio_lb_world__feed_slot(world, "*", srv);
		g_free(srv);
	}

	oio_lb_world__debug(world);

	/* create a pool and poll it */
	struct oio_lb_pool_s *pool = oio_lb_world__create_pool(world, "pool-test");
	oio_lb_world__add_pool_target(pool, "0,*");
	oio_lb_world__add_pool_target(pool, "0,*");
	oio_lb_world__add_pool_target(pool, "0,*");
	g_assert_cmpuint (oio_lb_world__count_slots(world), ==, 2);

	/* now poll some pools */
	for (int i = 0; i < 4096; i++) {
		guint count_rc, count;
		void _on_item (oio_location_t location, const char *id) {
			(void) location, (void) id;
			GRID_TRACE("Polled %s/%"OIO_LOC_FORMAT, id, location);
			++ count;
		}
		count = 0;
		count_rc = oio_lb_pool__poll(pool, NULL, _on_item);
		g_assert_cmpuint(count_rc, ==, count);
		g_assert_cmpuint(count_rc, ==, 3);
	}

	oio_lb_world__debug(world);

	oio_lb_pool__destroy(pool);
	oio_lb_world__destroy(world);
}

static struct oio_lb_item_s *
_srv2(int i, int svc_per_slot)
{
	size_t len = 8 + sizeof (struct oio_lb_item_s);
	struct oio_lb_item_s *srv = g_malloc0 (len);
	oio_location_t loc = i;
	srv->location = loc % svc_per_slot + loc / svc_per_slot * 65536 + 1;
	srv->weight = 80;
	sprintf(srv->id, "ID-%04d", i);
	GRID_TRACE("Built service id=%s,location=%lu,weight=%d",
			srv->id, srv->location, srv->weight);
	return srv;
}

static void
_test_uniform_repartition(int services, int slots, int targets)
{
	struct oio_lb_world_s *world = oio_lb_local__create_world ();
	void *slot_names_raw = alloca(5 * slots);
	char *slot_names[slots];
	int targets_per_slot[slots];
	int actual_svc_per_slot[slots];
	int svc_per_slot = (services-1) / slots + 1;
	int shots = 10000;

	GRID_DEBUG("Creating world with %d slots, %d services (%d services per slot)",
			slots, services, svc_per_slot);
	for (int i = 0; i < slots; i++) {
		targets_per_slot[i] = 0;
		actual_svc_per_slot[i] = 0;
		slot_names[i] = slot_names_raw + 5*i;
		sprintf(slot_names[i], "%04d", i);
		oio_lb_world__create_slot(world, slot_names[i]);
	}
	oio_lb_world__create_slot(world, "*");

	/* fill some services */
	for (int i = 0; i < services; i++) {
		struct oio_lb_item_s *srv = _srv2(i, svc_per_slot);
		oio_lb_world__feed_slot(world, slot_names[i/svc_per_slot], srv);
		oio_lb_world__feed_slot(world, "*", srv);
		actual_svc_per_slot[i/svc_per_slot]++;
		g_free(srv);
	}

	/* create a pool and poll it */
	GRID_DEBUG("Creating a pool with %d targets", targets);
	struct oio_lb_pool_s *pool = oio_lb_world__create_pool(world, "pool-test");
	for (int i = 0; i < targets; i++) {
		char target[16] = {0};
		sprintf(target, "%04d,*", i % slots);
		targets_per_slot[i % slots]++;
		oio_lb_world__add_pool_target(pool, target);
	}
	g_assert_cmpuint(oio_lb_world__count_slots(world), ==, slots+1);

	int counts[services];
	memset(counts, 0, services * sizeof(int));
	/* now poll some pools */
	for (int i = 0; i < shots; i++) {
		guint count_rc, count;
		void _on_item(oio_location_t location, const char *id) {
			(void) location, (void) id;
			GRID_TRACE("Polled %s/%"OIO_LOC_FORMAT, id, location);
			++count;
			counts[atoi(id+3)]++;
		}
		count = 0;
		count_rc = oio_lb_pool__poll(pool, NULL, _on_item);
		g_assert_cmpuint(count_rc, ==, count);
		g_assert_cmpuint(count_rc, ==, targets);
	}

	oio_lb_world__debug(world);

	GRID_DEBUG("Repartition with %d targets:", targets);
	for (int i = 0; i < services; i++) {
		int slot = i/svc_per_slot;
		int ideal_count = targets_per_slot[slot] * shots / actual_svc_per_slot[slot];
		int min_count = ideal_count * 80 / 100;
		int max_count = ideal_count * 120 / 100;
		GRID_DEBUG("service %04d (slot %d) chosen %d times (min/ideal/max/diff: %d/%d/%d/%+2.2f%%)",
				i, slot, counts[i], min_count, ideal_count, max_count,
				counts[i]*100.0f/(float)ideal_count - 100.0f);
		g_assert_cmpint(counts[i], >=, min_count);
		g_assert_cmpint(counts[i], <=, max_count);
	}

	oio_lb_pool__destroy(pool);
	oio_lb_world__destroy(world);
}

struct repartition_test_s {
	int services;
	int slots;
	int targets;
};

static void
test_uniform_repartition(gconstpointer raw_test_data)
{
	const struct repartition_test_s *test_data = raw_test_data;
	return _test_uniform_repartition(test_data->services,
			test_data->slots, test_data->targets);
}

static void
test_local_feed_twice(void)
{
	struct oio_lb_world_s *world = oio_lb_local__create_world();
	struct oio_lb_item_s *srv0 = g_malloc0(8 + sizeof (struct oio_lb_item_s));
	struct oio_lb_item_s *srv1 = g_malloc0(8 + sizeof (struct oio_lb_item_s));
	srv0->location = 42 + 65536;
	srv0->weight = 42;
	g_sprintf(srv0->id, "ID-%d", 42);
	srv1->location = 43 + 65536;
	srv1->weight = 42;
	g_sprintf(srv1->id, "ID-%d", 43);

	oio_lb_world__create_slot(world, "0");
	oio_lb_world__feed_slot(world, "0", srv1);
	oio_lb_world__feed_slot(world, "0", srv0);
	oio_lb_world__feed_slot(world, "0", srv0);

	g_assert_cmpuint(2, ==, oio_lb_world__count_slot_items(world, "0"));
	g_free(srv0);
	g_free(srv1);
	oio_lb_world__destroy(world);
}

static void
test_local_feed (void)
{
	struct oio_lb_world_s *world = oio_lb_local__create_world ();
	oio_lb_world__create_slot (world, "0");
	oio_lb_world__create_slot (world, "1");
	oio_lb_world__create_slot (world, "2");
	oio_lb_world__create_slot (world, "3");
	oio_lb_world__create_slot (world, "*");
	struct oio_lb_pool_s *pool = oio_lb_world__create_pool (world, "pool-test");
	oio_lb_world__add_pool_target (pool, "0,1,2,3,*");
	oio_lb_world__add_pool_target (pool, "1,2,3,0,*");
	oio_lb_world__add_pool_target (pool, "2,3,0,1,*");
	oio_lb_world__add_pool_target (pool, "3,0,1,2,*");
	g_assert_cmpuint (oio_lb_world__count_slots (world), ==, 5);

	for (int j = 0; j < 8; ++j) {
		struct oio_lb_item_s *srv = g_malloc0 (8 + sizeof (struct oio_lb_item_s));
		for (int i = 0; i < 8; ++i) {
			srv->location = 65430 - i;
			srv->weight = 90 + i;
			strcpy (srv->id, "ID-");
			srv->id[strlen(srv->id)] = '0' + i;
			oio_lb_world__feed_slot (world, "*", srv);
			if (!(i%2)) oio_lb_world__feed_slot (world, "0", srv);
			if (!(i%3)) oio_lb_world__feed_slot (world, "1", srv);
			if (!(i%4)) oio_lb_world__feed_slot (world, "2", srv);
			if (!(i%5)) oio_lb_world__feed_slot (world, "3", srv);
		}
		g_free (srv);
	}
	g_assert_cmpuint (oio_lb_world__count_slots (world), ==, 5);
	g_assert_cmpuint (oio_lb_world__count_items (world), ==, 8);

	oio_lb_world__debug (world);
	oio_lb_pool__destroy (pool);
	oio_lb_world__destroy (world);
}

static void
test_local_pool (void)
{
	struct oio_lb_world_s *world = oio_lb_local__create_world ();
	oio_lb_world__create_slot (world, "0");
	oio_lb_world__create_slot (world, "1");
	oio_lb_world__create_slot (world, "2");
	oio_lb_world__create_slot (world, "3");
	for (int i=0; i<8 ;++i) {
		struct oio_lb_pool_s *pool = oio_lb_world__create_pool (world, "pool-test");
		oio_lb_world__add_pool_target (pool, "0,1,2,3");
		oio_lb_world__add_pool_target (pool, "1,2,3,0");
		oio_lb_world__add_pool_target (pool, "2,3,0,1");
		oio_lb_world__add_pool_target (pool, "3,0,1,2");
		oio_lb_pool__destroy (pool);
	}
	oio_lb_world__destroy (world);
}

static void
test_local_world (void)
{
	for (int i=0; i<8 ;++i) {
		struct oio_lb_world_s *world = oio_lb_local__create_world ();
		for (int j=0; j<8 ;++j) {
			char tmp[] = {'s', 'l', 'o', 't', '-', j+'0', 0};
			for (int k=0; k<4 ;++k)
				oio_lb_world__create_slot (world, tmp);
		}
		oio_lb_world__destroy (world);
	}
}

static void
_add_repartition_test(int services, int slots, int targets)
{
	char name[128] = {0};
	snprintf(name, sizeof(name), "/core/lb/local/poll_%d_%d_%d",
			services, slots, targets);
	struct repartition_test_s *test_data = \
			g_malloc0(sizeof(struct repartition_test_s));
	test_data->services = services;
	test_data->slots = slots;
	test_data->targets = targets;
	g_test_add_data_func_full(name, test_data,
			test_uniform_repartition, g_free);
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/core/lb/local/world", test_local_world);
	g_test_add_func("/core/lb/local/pool", test_local_pool);
	g_test_add_func("/core/lb/local/feed", test_local_feed);
	g_test_add_func("/core/lb/local/feed_twice", test_local_feed_twice);
	g_test_add_func("/core/lb/local/poll", test_local_poll);
	g_test_add_func("/core/lb/local/poll_same_low",
			test_local_poll_same_low_bits);

	_add_repartition_test(30, 1, 1);
	_add_repartition_test(30, 1, 3);
	_add_repartition_test(30, 1, 9);
	_add_repartition_test(30, 1, 18);

	_add_repartition_test(9, 1, 9);
	_add_repartition_test(88, 3, 18);

	_add_repartition_test(30, 3, 9);
	_add_repartition_test(40, 4, 9);
	_add_repartition_test(30, 3, 10);
	_add_repartition_test(40, 4, 10);
	_add_repartition_test(36, 18, 18);

	return g_test_run();
}

