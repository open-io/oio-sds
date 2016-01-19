/*
OpenIO SDS core / LB
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

#include <glib.h>
#include <core/oiolb.h>
#include <metautils/lib/metautils.h>

static struct oio_lb_item_s *
_srv (int i)
{
	size_t len = 8 + sizeof (struct oio_lb_item_s);
	struct oio_lb_item_s *srv = g_malloc0 (len);
	srv->location = 65430 - i;
	srv->weight = 90 + i;
	strcpy (srv->id, "ID-");
	srv->id[strlen(srv->id)] = '0' + i;
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
	for (int i=0; i<1024 ;++i) {
		struct oio_lb_item_s *srv = _srv (i);
		oio_lb_world__feed_slot (world, (i%2)?"1":"0", srv);
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
	for (int i=0; i<4096 ;i++) {
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

	oio_lb_pool__destroy (pool);
	oio_lb_world__destroy (world);
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

	for (int j=0; j<8 ;++j) {
		struct oio_lb_item_s *srv = g_malloc0 (8 + sizeof (struct oio_lb_item_s));
		for (int i=0; i<8 ;++i) {
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

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/core/lb/local/world", test_local_world);
	g_test_add_func("/core/lb/local/pool", test_local_pool);
	g_test_add_func("/core/lb/local/feed", test_local_feed);
	g_test_add_func("/core/lb/local/poll", test_local_poll);
	return g_test_run();
}

