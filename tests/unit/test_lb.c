/*
OpenIO SDS unit tests
Copyright (C) 2016-2019 OpenIO SAS, as part of OpenIO SDS

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
#include <math.h>
#include <glib.h>
#include <core/oiolb.h>
#include <metautils/lib/metautils.h>

#ifndef LB_TESTS_DATASETS
#define LB_TESTS_DATASETS "tests/datasets"
#endif

static void
_srv(int i, struct oio_lb_item_s *srv)
{
	oio_location_t loc = i+1; // discard 0
	memset(srv, 0, sizeof(struct oio_lb_item_s));
	srv->location = ((loc & ~0xFF) << 16) | (loc & 0xFF);
	srv->weight = 90 + i;
	sprintf(srv->id, "ID-%04d", i);
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
	struct oio_lb_item_s srv;
	for (int i = 0; i < 1024; ++i) {
		_srv(i, &srv);
		oio_lb_world__feed_slot(world, (i%2)? "1":"0", &srv);
		if (!(i%3))
			oio_lb_world__feed_slot(world, "2", &srv);
		oio_lb_world__feed_slot(world, "*", &srv);
	}

	oio_lb_world__purge_old_generations(world);
	oio_lb_world__debug (world);

	/* create a pool and poll it */
	struct oio_lb_pool_s *pool = oio_lb_world__create_pool (world, "pool-test");
	oio_lb_world__add_pool_target (pool, "0,1,*");
	oio_lb_world__add_pool_target (pool, "2,1,*");
	g_assert_cmpuint (oio_lb_world__count_slots (world), ==, 4);

	/* now poll some pools */
	for (int i = 0; i < 4096; i++) {
		guint count = 0;
		void _on_item(struct oio_lb_selected_item_s *sel, gpointer u UNUSED) {
			(void) sel;
			GRID_TRACE("Polled %s/%"OIO_LOC_FORMAT,
					sel->item->id, sel->item->location);
			++count;
		}
		GError *err = oio_lb_pool__poll(pool, NULL, _on_item, NULL);
		g_assert_no_error(err);
		g_assert_cmpuint(count, ==, 2);
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
	struct oio_lb_item_s srv;
	for (int i = 0; i < 3; ++i) {
		_srv((i << 16) + 0x66, &srv);
		oio_lb_world__feed_slot(world, "0", &srv);
		oio_lb_world__feed_slot(world, "*", &srv);
	}

	oio_lb_world__purge_old_generations(world);
	oio_lb_world__debug(world);

	/* create a pool and poll it */
	struct oio_lb_pool_s *pool = oio_lb_world__create_pool(world, "pool-test");
	oio_lb_world__add_pool_target(pool, "0,*");
	oio_lb_world__add_pool_target(pool, "0,*");
	oio_lb_world__add_pool_target(pool, "0,*");
	g_assert_cmpuint (oio_lb_world__count_slots(world), ==, 2);

	/* now poll some pools */
	for (int i = 0; i < 4096; i++) {
		guint count = 0;
		void _on_item(struct oio_lb_selected_item_s *sel, gpointer u UNUSED) {
			(void) sel;
			GRID_TRACE("Polled %s/%"OIO_LOC_FORMAT,
					sel->item->id, sel->item->location);
			++ count;
		}
		GError *err = oio_lb_pool__poll(pool, NULL, _on_item, NULL);
		g_assert_no_error(err);
		g_assert_cmpuint(count, ==, 3);
	}

	oio_lb_world__debug(world);

	oio_lb_pool__destroy(pool);
	oio_lb_world__destroy(world);
}

static struct oio_lb_item_s *
_srv2(int i, int svc_per_slot)
{
	struct oio_lb_item_s *srv = g_malloc0(sizeof(struct oio_lb_item_s));
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
	oio_lb_world__purge_old_generations(world);

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
		guint count = 0;
		void _on_item(struct oio_lb_selected_item_s *sel, gpointer u UNUSED) {
			GRID_TRACE("Polled %s/%"OIO_LOC_FORMAT,
					sel->item->id, sel->item->location);
			++count;
			counts[atoi(sel->item->id+3)]++;
		}
		GError *err = oio_lb_pool__poll(pool, NULL, _on_item, NULL);
		g_assert_no_error(err);
		g_assert_cmpuint(count, ==, targets);
	}

	oio_lb_world__debug(world);

	GRID_DEBUG("Repartition with %d targets:", targets);
	double variance = 0.0;
	for (int i = 0; i < services; i++) {
		int slot = i/svc_per_slot;
		int ideal_count = targets_per_slot[slot] * shots / actual_svc_per_slot[slot];
		int min_count = ideal_count * 80 / 100;
		int max_count = ideal_count * 120 / 100;
		double deviation_percent = counts[i]*100.0f/(float)ideal_count - 100.0f;
		GRID_DEBUG("service %04d (slot %d) chosen %d times (min/ideal/max/diff: %d/%d/%d/%+2.2f%%)",
				i, slot, counts[i], min_count, ideal_count, max_count,
				deviation_percent);
		variance += (counts[i] - ideal_count) * (counts[i] - ideal_count);
	}
	variance /= services;
	GRID_DEBUG("Standard deviation: %lf", sqrt(variance));
	GRID_DEBUG("Checking...");
	for (int i = 0; i < services; i++) {
		int slot = i/svc_per_slot;
		int ideal_count = targets_per_slot[slot] * shots / actual_svc_per_slot[slot];
		int min_count = ideal_count * 80 / 100;
		int max_count = ideal_count * 120 / 100;
		if (counts[i] < min_count || counts[i] > max_count) {
			GRID_ERROR("service %04d (slot %d) chosen %d times (%+2.2f%%)",
					i, slot, counts[i],
					counts[i]*100.0f/(float)ideal_count - 100.0f);
			GRID_ERROR("re-run with G_DEBUG_LEVEL=D to get details");
			g_assert_cmpint(counts[i], >=, min_count);
			g_assert_cmpint(counts[i], <=, max_count);
		}
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
_srv3(int i, const char *loc, struct oio_lb_item_s *srv)
{
	memset(srv, 0, sizeof(struct oio_lb_item_s));
	srv->location = location_from_dotted_string(loc);
	srv->weight = 80;
	sprintf(srv->id, "ID-%04d", i);
	GRID_TRACE("Built service id=%s,location=%lu,weight=%d",
			srv->id, srv->location, srv->weight);
}

static struct oio_lb_world_s *
_world_from_loc_strings(const char **locations)
{
	struct oio_lb_world_s *world = oio_lb_local__create_world();
	oio_lb_world__create_slot(world, "*");

	int i = 0;
	struct oio_lb_item_s srv;
	for (const char **loc = locations; locations && *loc; loc++, i++) {
		_srv3(i, *loc, &srv);
		oio_lb_world__feed_slot(world, "*", &srv);
	}
	oio_lb_world__purge_old_generations(world);

	return world;
}

static struct oio_lb_world_s *
_world_from_file(const char *src_file)
{
	GRID_DEBUG("Loading LB world from %s", src_file);

	struct oio_lb_world_s *world = oio_lb_local__create_world();
	GError *err = oio_lb_world__feed_from_file(world, "*", src_file);
	g_assert_no_error(err);

	return world;
}

static struct oio_lb_pool_s *
_create_test_pool(struct oio_lb_world_s *world,
		int targets, gboolean is_balanced)
{
	struct oio_lb_pool_s *pool = oio_lb_world__create_pool(world, "pool-test");
	guint n_slots = oio_lb_world__count_slots(world) - 1;
	if (is_balanced && n_slots > 1) {
		// Ignore the '*' slot, thus -1
		guint items_per_slot = targets / n_slots;
		GRID_DEBUG("Creating a pool with %d targets on %u slots",
				targets, n_slots);
		for (guint i = 0; i < n_slots; i++) {
			for (guint j = 0; j < items_per_slot; j++) {
				gchar target[32];
				// User-friendly site names, thus +1
				g_snprintf(target, sizeof(target), "site%u,*", i + 1);
				oio_lb_world__add_pool_target(pool, target);
			}
		}
	} else {
		GRID_DEBUG("Creating a pool with %d targets", targets);
		const char *target = "*";
		for (int i = 0; i < targets; i++) {
			oio_lb_world__add_pool_target(pool, target);
		}
	}
	return pool;
}

// FIXME(FVE): autodetect if is_balanced
static void
_test_repartition_by_loc_level(struct oio_lb_world_s *world,
		int targets, int shots, gboolean is_balanced)
{
	int unbalanced = 0;

	/* create a pool and poll it */
	struct oio_lb_pool_s *pool = _create_test_pool(
			world, targets, is_balanced);

	GString *pool_dump = oio_lb_world__dump_pool_options(pool);
	GRID_INFO("Using pool: %s", pool_dump->str);
	g_string_free(pool_dump, TRUE);

	oio_lb_world__debug(world);

	GHashTable *counts = g_hash_table_new_full(
			g_str_hash, g_str_equal, g_free, NULL);
	oio_lb_pool__poll_many(pool, shots, counts, &unbalanced);
	GRID_INFO("%d unbalanced situations on %d shots", unbalanced, shots);

	// FIXME(FVE): 50% is really high.
	// This test must be changed when OB-384 is resolved.
	if (is_balanced)
		g_assert_cmpint(unbalanced, <=, shots / 2);
	oio_lb_world__check_repartition(world, targets, shots, counts);

	g_hash_table_destroy(counts);
	oio_lb_pool__destroy(pool);
}

static void
_test_repartition_by_level__locations(const char **locations, int targets,
		gboolean is_balanced)
{
	struct oio_lb_world_s *world = _world_from_loc_strings(locations);
	_test_repartition_by_loc_level(world, targets, 10000, is_balanced);
	oio_lb_world__destroy(world);
}

static void
_test_repartition_by_level__file(const char *service_file, int targets)
{
	struct oio_lb_world_s *world = _world_from_file(service_file);
	// FIXME(FVE): not all files are balanced
	_test_repartition_by_loc_level(world, targets, 50000, TRUE);
	oio_lb_world__destroy(world);
}

struct level_repartition_test_s {
	const char **locations;
	const char *file;
	int targets;
	gboolean is_balanced;
};

static void
level_repartition_test_free(gpointer data)
{
	struct level_repartition_test_s *test = data;
	g_free((gpointer)test->file);
	test->file = NULL;
	g_free(data);
}

static void
test_uniform_level_repartition(gconstpointer raw_test_data)
{
	const struct level_repartition_test_s *test_data = raw_test_data;
	if (test_data->file)
		return _test_repartition_by_level__file(
				test_data->file, test_data->targets);
	return _test_repartition_by_level__locations(
			test_data->locations, test_data->targets, test_data->is_balanced);
}


static void
test_local_feed_twice(void)
{
	struct oio_lb_world_s *world = oio_lb_local__create_world();
	struct oio_lb_item_s *srv0 = g_malloc0(sizeof(struct oio_lb_item_s));
	struct oio_lb_item_s *srv1 = g_malloc0(sizeof(struct oio_lb_item_s));
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
	oio_lb_world__purge_old_generations(world);

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
		struct oio_lb_item_s *srv = g_malloc0(sizeof(struct oio_lb_item_s));
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
	oio_lb_world__purge_old_generations(world);
	g_assert_cmpuint (oio_lb_world__count_slots (world), ==, 5);
	g_assert_cmpuint (oio_lb_world__count_items (world), ==, 8);

	oio_lb_world__debug (world);
	oio_lb_pool__destroy (pool);
	oio_lb_world__destroy (world);
}

static void
test_local_feed_zero_scored(void)
{
	struct oio_lb_world_s *world = oio_lb_local__create_world();
	struct oio_lb_item_s *srv0 = g_malloc0(sizeof(struct oio_lb_item_s));
	struct oio_lb_item_s *srv1 = g_malloc0(sizeof(struct oio_lb_item_s));
	struct oio_lb_item_s *srv2 = g_malloc0(sizeof(struct oio_lb_item_s));
	srv0->location = 42 + 65536;
	srv0->weight = 0;
	g_sprintf(srv0->id, "ID-%d", 42);
	srv1->location = 43 + 65536;
	srv1->weight = 42;
	g_sprintf(srv1->id, "ID-%d", 43);
	srv2->location = 44 + 65536;
	srv2->weight = 0;
	g_sprintf(srv2->id, "ID-%d", 44);

	oio_lb_world__create_slot(world, "0");
	oio_lb_world__feed_slot(world, "0", srv0);
	oio_lb_world__feed_slot(world, "0", srv1);
	oio_lb_world__feed_slot(world, "0", srv2);

	oio_lb_world__debug(world);
	g_assert_cmpuint(1, ==, oio_lb_world__count_slot_items(world, "0"));
	oio_lb_world__rehash_all_slots(world);
	g_assert_cmpuint(1, ==, oio_lb_world__count_slot_items(world, "0"));

	g_free(srv0);
	g_free(srv1);
	g_free(srv2);
	oio_lb_world__destroy(world);
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
test_weird_pool_configurations(void)
{
	struct oio_lb_world_s *lb_world = oio_lb_local__create_world();

	struct oio_lb_pool_s *trailing =
			oio_lb_world__create_pool(lb_world, "trailing");
	oio_lb_world__add_pool_targets(trailing, "3,rawx;");
	g_assert_cmpuint(3, ==, oio_lb_world__count_pool_targets(trailing));
	oio_lb_pool__destroy(trailing);

	struct oio_lb_pool_s *middle_empty =
			oio_lb_world__create_pool(lb_world, "middle_empty");
	oio_lb_world__add_pool_targets(middle_empty, "2,rawx;;1,rawx");
	g_assert_cmpuint(3, ==, oio_lb_world__count_pool_targets(middle_empty));
	oio_lb_pool__destroy(middle_empty);

	oio_lb_world__destroy(lb_world);
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
_test_service_info_to_lb_item(const char *source0, oio_location_t expect)
{
	GError *err = NULL;
	struct service_info_s *svc0 = NULL;
	err = service_info_load_json(source0, &svc0, TRUE);
	g_assert_no_error(err);

	struct oio_lb_item_s *item0 = g_alloca(sizeof(struct oio_lb_item_s));
	service_info_to_lb_item(svc0, item0);

	g_assert_cmpuint(78u, ==, item0->weight);
	g_assert_cmpuint(expect, ==, item0->location);

	service_info_clean(svc0);
}

static void
test_lb_item_loc_user(void)
{
	const char *source0 = "{\
		\"addr\": \"127.0.0.1:6015\",\
		\"score\": 78,\
		\"tags\": {\
			\"tag.loc\": \"abcd.hem.oio.vol8\",\
			\"tag.slots\": \"rawx,rawx-even\",\
			\"tag.up\": true,\
			\"tag.vol\": \"/home/fvennetier/.oio/sds/data/NS-rawx-8\"\
		}\
	}";
	return _test_service_info_to_lb_item(source0, 0xEE4F7ABF990CAA8Eu);
}

static void
test_lb_item_loc_user_long(void)
{
	const char *source0 = "{\
		\"addr\": \"127.0.0.1:6015\",\
		\"score\": 78,\
		\"tags\": {\
			\"tag.loc\": \"hem.dc2.room1.rack2.server3.vol8\",\
			\"tag.slots\": \"rawx,rawx-even\",\
			\"tag.up\": true,\
			\"tag.vol\": \"/home/fvennetier/.oio/sds/data/NS-rawx-8\"\
		}\
	}";
	// "rack2.server3.vol8" is considered as one block
	return _test_service_info_to_lb_item(source0, 0x7ABF693EAE13F707u);
}

static void
test_lb_item_loc_hex(void)
{
	const char *source1 = "{\
		\"addr\": \"127.0.0.1:6015\",\
		\"score\": 78,\
		\"tags\": {\
			\"tag.loc\": \"0xEE4F7ABF990CAA8E\",\
			\"tag.slots\": \"rawx,rawx-even\",\
			\"tag.up\": true,\
			\"tag.vol\": \"/home/fvennetier/.oio/sds/data/NS-rawx-8\"\
		}\
	}";
	return _test_service_info_to_lb_item(source1, 0xEE4F7ABF990CAA8Eu);
}

static void
test_lb_item_loc_ipv4(void)
{
	const char *source2 = "{\
		\"addr\": \"127.0.0.1:6015\",\
		\"score\": 78,\
		\"tags\": {\
			\"tag.slots\": \"rawx,rawx-even\",\
			\"tag.up\": true,\
			\"tag.vol\": \"/home/fvennetier/.oio/sds/data/NS-rawx-8\"\
		}\
	}";
	return _test_service_info_to_lb_item(source2, 0x00007F000001177Fu);
}

static void
test_lb_item_loc_ipv6(void)
{
	const char *source3 = "{\
		\"addr\": \"[dead:beef:feed:face:cafe:babe:baad:c0de]:51966\",\
		\"score\": 78,\
		\"tags\": {\
			\"tag.slots\": \"rawx,rawx-even\",\
			\"tag.up\": true,\
			\"tag.vol\": \"/home/fvennetier/.oio/sds/data/NS-rawx-8\"\
		}\
	}";
	return _test_service_info_to_lb_item(source3, 0xBABEBAADC0DECAFEu);
}

static void
_add_repartition_test(int services, int slots, int targets)
{
	char name[128] = {0};
	snprintf(name, sizeof(name), "/core/lb/global_repartition/%dservices_%dslots_%dtargets",
			services, slots, targets);
	struct repartition_test_s *test_data = \
			g_malloc0(sizeof(struct repartition_test_s));
	test_data->services = services;
	test_data->slots = slots;
	test_data->targets = targets;
	g_test_add_data_func_full(name, test_data,
			test_uniform_repartition, g_free);
}

static void
_add_level_repartition_test2(const char **locations, const char *config,
		int targets, gboolean is_balanced)
{
	char name[128] = {0};
	snprintf(name, sizeof(name),
			"/core/lb/level_repartition/%dlocations/%s/%dtargets",
			g_strv_length((char**)locations), config, targets);
	struct level_repartition_test_s *test_data = \
			g_malloc0(sizeof(struct level_repartition_test_s));
	test_data->locations = locations;
	test_data->targets = targets;
	test_data->is_balanced = is_balanced;
	g_test_add_data_func_full(name, test_data,
			test_uniform_level_repartition,
			(GDestroyNotify)level_repartition_test_free);
}

static void
_add_level_repartition_test(const char **locations, const char *config, int targets)
{
	_add_level_repartition_test2(locations, config, targets, TRUE);
}

static void
_add_level_repartition_test_file(const char *service_file, int targets)
{
	char name[128] = {0};
	snprintf(name, sizeof(name),
			"/core/lb/level_repartition/%s/%dtargets",
			service_file, targets);
	struct level_repartition_test_s *test_data = \
			g_malloc0(sizeof(struct level_repartition_test_s));
	test_data->file = service_file;
	test_data->targets = targets;
	test_data->is_balanced = FALSE;
	g_test_add_data_func_full(name, test_data,
			test_uniform_level_repartition,
			(GDestroyNotify)level_repartition_test_free);
}

static void
_add_tests_from_files(const char *dir_path)
{
	GError *err = NULL;
	GDir *dir = g_dir_open(dir_path, 0, &err);
	if (err) {
		GRID_ERROR("Failed to open dir %s", dir_path);
		return;
	}

	const gchar *entry = NULL;
	while ((entry = g_dir_read_name(dir))) {
		if (g_str_has_prefix(entry, "lb-")) {
			gchar *full_path = g_build_filename(dir_path, entry, NULL);
			// FIXME(FVE): get target count from file name,
			_add_level_repartition_test_file(full_path, 12);
			full_path = g_build_filename(dir_path, entry, NULL);
			_add_level_repartition_test_file(full_path, 3);
		} else {
			GRID_DEBUG("Ignoring %s", entry);
		}
	}
	g_dir_close(dir);
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/metautils/lb/item/user", test_lb_item_loc_user);
	g_test_add_func("/metautils/lb/item/user_long", test_lb_item_loc_user_long);
	g_test_add_func("/metautils/lb/item/hex", test_lb_item_loc_hex);
	g_test_add_func("/metautils/lb/item/ipv4", test_lb_item_loc_ipv4);
	g_test_add_func("/metautils/lb/item/ipv6", test_lb_item_loc_ipv6);
	g_test_add_func("/core/lb/local/world", test_local_world);
	g_test_add_func("/core/lb/local/pool", test_local_pool);
	g_test_add_func("/core/lb/local/weird_pool", test_weird_pool_configurations);
	g_test_add_func("/core/lb/local/feed", test_local_feed);
	g_test_add_func("/core/lb/local/feed_twice", test_local_feed_twice);
	g_test_add_func("/core/lb/local/feed_zero_scored",
			test_local_feed_zero_scored);
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

	const char *lrt0[13] = {
			"rack0.srv0", "rack0.srv1", "rack0.srv2", "rack0.srv3",
			"rack1.srv4", "rack1.srv5", "rack1.srv6", "rack1.srv7",
			"rack2.srv8", "rack2.srv9", "rack2.srv10", "rack2.srv11",
			NULL
	};
	_add_level_repartition_test(lrt0, "3x4", 4);
	_add_level_repartition_test(lrt0, "3x4", 5);
	_add_level_repartition_test(lrt0, "3x4", 6);
	_add_level_repartition_test2(lrt0, "3x4", 7, FALSE);
	_add_level_repartition_test2(lrt0, "3x4", 8, FALSE);
	_add_level_repartition_test(lrt0, "3x4", 9);
	_add_level_repartition_test2(lrt0, "3x4", 10, FALSE);
	_add_level_repartition_test2(lrt0, "3x4", 11, FALSE);
	_add_level_repartition_test(lrt0, "3x4", 12);

	const char *lrt1[13] = {
			"rack0.srv0", "rack0.srv1", "rack0.srv2",
			"rack1.srv3", "rack1.srv4", "rack1.srv5",
			"rack2.srv6", "rack2.srv7", "rack2.srv8",
			"rack3.srv9", "rack3.srv10", "rack3.srv11",
			NULL
	};
	_add_level_repartition_test(lrt1, "4x3", 5);
	_add_level_repartition_test(lrt1, "4x3", 6);
	_add_level_repartition_test(lrt1, "4x3", 7);
	_add_level_repartition_test(lrt1, "4x3", 8);
	_add_level_repartition_test2(lrt1, "4x3", 9, FALSE);
	_add_level_repartition_test2(lrt1, "4x3", 10, FALSE);
	_add_level_repartition_test2(lrt1, "4x3", 11, FALSE);

	const char *lrt2[13] = {
			"rack0.srv0", "rack0.srv1",
			"rack1.srv2", "rack1.srv3",
			"rack2.srv4", "rack2.srv5",
			"rack3.srv6", "rack3.srv7",
			"rack4.srv8", "rack4.srv9",
			"rack5.srv10", "rack5.srv11",
			NULL
	};
	_add_level_repartition_test(lrt2, "6x2", 7);
	_add_level_repartition_test(lrt2, "6x2", 8);
	_add_level_repartition_test(lrt2, "6x2", 9);
	_add_level_repartition_test(lrt2, "6x2", 10);
	_add_level_repartition_test(lrt2, "6x2", 11);

	const char *lrt3[13] = {
			"room0.rack0.srv0", "room0.rack1.srv3",
			"room0.rack0.srv1", "room0.rack1.srv4",
			"room0.rack0.srv2", "room0.rack1.srv5",

			"room1.rack2.srv6", "room1.rack3.srv9",
			"room1.rack2.srv7", "room1.rack3.srv10",
			"room1.rack2.srv8", "room1.rack3.srv11",
			NULL
	};
	_add_level_repartition_test(lrt3, "2x2x3", 4);
	_add_level_repartition_test(lrt3, "2x2x3", 5);
	_add_level_repartition_test(lrt3, "2x2x3", 6);
	_add_level_repartition_test(lrt3, "2x2x3", 7);
	_add_level_repartition_test(lrt3, "2x2x3", 8);
	_add_level_repartition_test2(lrt3, "2x2x3", 9, FALSE);
	_add_level_repartition_test(lrt3, "2x2x3", 10);
	_add_level_repartition_test2(lrt3, "2x2x3", 11, FALSE);

	const char *lrt4[721] = {
		"bay0.rack0.srv0", "bay0.rack0.srv1", "bay0.rack0.srv2", "bay0.rack0.srv3",
		"bay0.rack1.srv0", "bay0.rack1.srv1", "bay0.rack1.srv2", "bay0.rack1.srv3",
		"bay0.rack2.srv0", "bay0.rack2.srv1", "bay0.rack2.srv2", "bay0.rack2.srv3",
		"bay0.rack3.srv0", "bay0.rack3.srv1", "bay0.rack3.srv2", "bay0.rack3.srv3",
		"bay0.rack4.srv0", "bay0.rack4.srv1", "bay0.rack4.srv2", "bay0.rack4.srv3",
		"bay0.rack5.srv0", "bay0.rack5.srv1", "bay0.rack5.srv2", "bay0.rack5.srv3",
		"bay0.rack6.srv0", "bay0.rack6.srv1", "bay0.rack6.srv2", "bay0.rack6.srv3",
		"bay0.rack7.srv0", "bay0.rack7.srv1", "bay0.rack7.srv2", "bay0.rack7.srv3",
		"bay0.rack8.srv0", "bay0.rack8.srv1", "bay0.rack8.srv2", "bay0.rack8.srv3",
		"bay0.rack9.srv0", "bay0.rack9.srv1", "bay0.rack9.srv2", "bay0.rack9.srv3",
		"bay0.rack10.srv0", "bay0.rack10.srv1", "bay0.rack10.srv2", "bay0.rack10.srv3",
		"bay0.rack11.srv0", "bay0.rack11.srv1", "bay0.rack11.srv2", "bay0.rack11.srv3",
		"bay0.rack12.srv0", "bay0.rack12.srv1", "bay0.rack12.srv2", "bay0.rack12.srv3",
		"bay0.rack13.srv0", "bay0.rack13.srv1", "bay0.rack13.srv2", "bay0.rack13.srv3",
		"bay0.rack14.srv0", "bay0.rack14.srv1", "bay0.rack14.srv2", "bay0.rack14.srv3",
		"bay0.rack15.srv0", "bay0.rack15.srv1", "bay0.rack15.srv2", "bay0.rack15.srv3",
		"bay0.rack16.srv0", "bay0.rack16.srv1", "bay0.rack16.srv2", "bay0.rack16.srv3",
		"bay0.rack17.srv0", "bay0.rack17.srv1", "bay0.rack17.srv2", "bay0.rack17.srv3",
		"bay0.rack18.srv0", "bay0.rack18.srv1", "bay0.rack18.srv2", "bay0.rack18.srv3",
		"bay0.rack19.srv0", "bay0.rack19.srv1", "bay0.rack19.srv2", "bay0.rack19.srv3",
		"bay0.rack20.srv0", "bay0.rack20.srv1", "bay0.rack20.srv2", "bay0.rack20.srv3",
		"bay0.rack21.srv0", "bay0.rack21.srv1", "bay0.rack21.srv2", "bay0.rack21.srv3",
		"bay0.rack22.srv0", "bay0.rack22.srv1", "bay0.rack22.srv2", "bay0.rack22.srv3",
		"bay0.rack23.srv0", "bay0.rack23.srv1", "bay0.rack23.srv2", "bay0.rack23.srv3",
		"bay0.rack24.srv0", "bay0.rack24.srv1", "bay0.rack24.srv2", "bay0.rack24.srv3",
		"bay0.rack25.srv0", "bay0.rack25.srv1", "bay0.rack25.srv2", "bay0.rack25.srv3",
		"bay0.rack26.srv0", "bay0.rack26.srv1", "bay0.rack26.srv2", "bay0.rack26.srv3",
		"bay0.rack27.srv0", "bay0.rack27.srv1", "bay0.rack27.srv2", "bay0.rack27.srv3",
		"bay0.rack28.srv0", "bay0.rack28.srv1", "bay0.rack28.srv2", "bay0.rack28.srv3",
		"bay0.rack29.srv0", "bay0.rack29.srv1", "bay0.rack29.srv2", "bay0.rack29.srv3",

		"bay1.rack0.srv0", "bay1.rack0.srv1", "bay1.rack0.srv2", "bay1.rack0.srv3",
		"bay1.rack1.srv0", "bay1.rack1.srv1", "bay1.rack1.srv2", "bay1.rack1.srv3",
		"bay1.rack2.srv0", "bay1.rack2.srv1", "bay1.rack2.srv2", "bay1.rack2.srv3",
		"bay1.rack3.srv0", "bay1.rack3.srv1", "bay1.rack3.srv2", "bay1.rack3.srv3",
		"bay1.rack4.srv0", "bay1.rack4.srv1", "bay1.rack4.srv2", "bay1.rack4.srv3",
		"bay1.rack5.srv0", "bay1.rack5.srv1", "bay1.rack5.srv2", "bay1.rack5.srv3",
		"bay1.rack6.srv0", "bay1.rack6.srv1", "bay1.rack6.srv2", "bay1.rack6.srv3",
		"bay1.rack7.srv0", "bay1.rack7.srv1", "bay1.rack7.srv2", "bay1.rack7.srv3",
		"bay1.rack8.srv0", "bay1.rack8.srv1", "bay1.rack8.srv2", "bay1.rack8.srv3",
		"bay1.rack9.srv0", "bay1.rack9.srv1", "bay1.rack9.srv2", "bay1.rack9.srv3",
		"bay1.rack10.srv0", "bay1.rack10.srv1", "bay1.rack10.srv2", "bay1.rack10.srv3",
		"bay1.rack11.srv0", "bay1.rack11.srv1", "bay1.rack11.srv2", "bay1.rack11.srv3",
		"bay1.rack12.srv0", "bay1.rack12.srv1", "bay1.rack12.srv2", "bay1.rack12.srv3",
		"bay1.rack13.srv0", "bay1.rack13.srv1", "bay1.rack13.srv2", "bay1.rack13.srv3",
		"bay1.rack14.srv0", "bay1.rack14.srv1", "bay1.rack14.srv2", "bay1.rack14.srv3",
		"bay1.rack15.srv0", "bay1.rack15.srv1", "bay1.rack15.srv2", "bay1.rack15.srv3",
		"bay1.rack16.srv0", "bay1.rack16.srv1", "bay1.rack16.srv2", "bay1.rack16.srv3",
		"bay1.rack17.srv0", "bay1.rack17.srv1", "bay1.rack17.srv2", "bay1.rack17.srv3",
		"bay1.rack18.srv0", "bay1.rack18.srv1", "bay1.rack18.srv2", "bay1.rack18.srv3",
		"bay1.rack19.srv0", "bay1.rack19.srv1", "bay1.rack19.srv2", "bay1.rack19.srv3",
		"bay1.rack20.srv0", "bay1.rack20.srv1", "bay1.rack20.srv2", "bay1.rack20.srv3",
		"bay1.rack21.srv0", "bay1.rack21.srv1", "bay1.rack21.srv2", "bay1.rack21.srv3",
		"bay1.rack22.srv0", "bay1.rack22.srv1", "bay1.rack22.srv2", "bay1.rack22.srv3",
		"bay1.rack23.srv0", "bay1.rack23.srv1", "bay1.rack23.srv2", "bay1.rack23.srv3",
		"bay1.rack24.srv0", "bay1.rack24.srv1", "bay1.rack24.srv2", "bay1.rack24.srv3",
		"bay1.rack25.srv0", "bay1.rack25.srv1", "bay1.rack25.srv2", "bay1.rack25.srv3",
		"bay1.rack26.srv0", "bay1.rack26.srv1", "bay1.rack26.srv2", "bay1.rack26.srv3",
		"bay1.rack27.srv0", "bay1.rack27.srv1", "bay1.rack27.srv2", "bay1.rack27.srv3",
		"bay1.rack28.srv0", "bay1.rack28.srv1", "bay1.rack28.srv2", "bay1.rack28.srv3",
		"bay1.rack29.srv0", "bay1.rack29.srv1", "bay1.rack29.srv2", "bay1.rack29.srv3",

		"bay2.rack0.srv0", "bay2.rack0.srv1", "bay2.rack0.srv2", "bay2.rack0.srv3",
		"bay2.rack1.srv0", "bay2.rack1.srv1", "bay2.rack1.srv2", "bay2.rack1.srv3",
		"bay2.rack2.srv0", "bay2.rack2.srv1", "bay2.rack2.srv2", "bay2.rack2.srv3",
		"bay2.rack3.srv0", "bay2.rack3.srv1", "bay2.rack3.srv2", "bay2.rack3.srv3",
		"bay2.rack4.srv0", "bay2.rack4.srv1", "bay2.rack4.srv2", "bay2.rack4.srv3",
		"bay2.rack5.srv0", "bay2.rack5.srv1", "bay2.rack5.srv2", "bay2.rack5.srv3",
		"bay2.rack6.srv0", "bay2.rack6.srv1", "bay2.rack6.srv2", "bay2.rack6.srv3",
		"bay2.rack7.srv0", "bay2.rack7.srv1", "bay2.rack7.srv2", "bay2.rack7.srv3",
		"bay2.rack8.srv0", "bay2.rack8.srv1", "bay2.rack8.srv2", "bay2.rack8.srv3",
		"bay2.rack9.srv0", "bay2.rack9.srv1", "bay2.rack9.srv2", "bay2.rack9.srv3",
		"bay2.rack10.srv0", "bay2.rack10.srv1", "bay2.rack10.srv2", "bay2.rack10.srv3",
		"bay2.rack11.srv0", "bay2.rack11.srv1", "bay2.rack11.srv2", "bay2.rack11.srv3",
		"bay2.rack12.srv0", "bay2.rack12.srv1", "bay2.rack12.srv2", "bay2.rack12.srv3",
		"bay2.rack13.srv0", "bay2.rack13.srv1", "bay2.rack13.srv2", "bay2.rack13.srv3",
		"bay2.rack14.srv0", "bay2.rack14.srv1", "bay2.rack14.srv2", "bay2.rack14.srv3",
		"bay2.rack15.srv0", "bay2.rack15.srv1", "bay2.rack15.srv2", "bay2.rack15.srv3",
		"bay2.rack16.srv0", "bay2.rack16.srv1", "bay2.rack16.srv2", "bay2.rack16.srv3",
		"bay2.rack17.srv0", "bay2.rack17.srv1", "bay2.rack17.srv2", "bay2.rack17.srv3",
		"bay2.rack18.srv0", "bay2.rack18.srv1", "bay2.rack18.srv2", "bay2.rack18.srv3",
		"bay2.rack19.srv0", "bay2.rack19.srv1", "bay2.rack19.srv2", "bay2.rack19.srv3",
		"bay2.rack20.srv0", "bay2.rack20.srv1", "bay2.rack20.srv2", "bay2.rack20.srv3",
		"bay2.rack21.srv0", "bay2.rack21.srv1", "bay2.rack21.srv2", "bay2.rack21.srv3",
		"bay2.rack22.srv0", "bay2.rack22.srv1", "bay2.rack22.srv2", "bay2.rack22.srv3",
		"bay2.rack23.srv0", "bay2.rack23.srv1", "bay2.rack23.srv2", "bay2.rack23.srv3",
		"bay2.rack24.srv0", "bay2.rack24.srv1", "bay2.rack24.srv2", "bay2.rack24.srv3",
		"bay2.rack25.srv0", "bay2.rack25.srv1", "bay2.rack25.srv2", "bay2.rack25.srv3",
		"bay2.rack26.srv0", "bay2.rack26.srv1", "bay2.rack26.srv2", "bay2.rack26.srv3",
		"bay2.rack27.srv0", "bay2.rack27.srv1", "bay2.rack27.srv2", "bay2.rack27.srv3",
		"bay2.rack28.srv0", "bay2.rack28.srv1", "bay2.rack28.srv2", "bay2.rack28.srv3",
		"bay2.rack29.srv0", "bay2.rack29.srv1", "bay2.rack29.srv2", "bay2.rack29.srv3",

		"bay3.rack0.srv0", "bay3.rack0.srv1", "bay3.rack0.srv2", "bay3.rack0.srv3",
		"bay3.rack1.srv0", "bay3.rack1.srv1", "bay3.rack1.srv2", "bay3.rack1.srv3",
		"bay3.rack2.srv0", "bay3.rack2.srv1", "bay3.rack2.srv2", "bay3.rack2.srv3",
		"bay3.rack3.srv0", "bay3.rack3.srv1", "bay3.rack3.srv2", "bay3.rack3.srv3",
		"bay3.rack4.srv0", "bay3.rack4.srv1", "bay3.rack4.srv2", "bay3.rack4.srv3",
		"bay3.rack5.srv0", "bay3.rack5.srv1", "bay3.rack5.srv2", "bay3.rack5.srv3",
		"bay3.rack6.srv0", "bay3.rack6.srv1", "bay3.rack6.srv2", "bay3.rack6.srv3",
		"bay3.rack7.srv0", "bay3.rack7.srv1", "bay3.rack7.srv2", "bay3.rack7.srv3",
		"bay3.rack8.srv0", "bay3.rack8.srv1", "bay3.rack8.srv2", "bay3.rack8.srv3",
		"bay3.rack9.srv0", "bay3.rack9.srv1", "bay3.rack9.srv2", "bay3.rack9.srv3",
		"bay3.rack10.srv0", "bay3.rack10.srv1", "bay3.rack10.srv2", "bay3.rack10.srv3",
		"bay3.rack11.srv0", "bay3.rack11.srv1", "bay3.rack11.srv2", "bay3.rack11.srv3",
		"bay3.rack12.srv0", "bay3.rack12.srv1", "bay3.rack12.srv2", "bay3.rack12.srv3",
		"bay3.rack13.srv0", "bay3.rack13.srv1", "bay3.rack13.srv2", "bay3.rack13.srv3",
		"bay3.rack14.srv0", "bay3.rack14.srv1", "bay3.rack14.srv2", "bay3.rack14.srv3",
		"bay3.rack15.srv0", "bay3.rack15.srv1", "bay3.rack15.srv2", "bay3.rack15.srv3",
		"bay3.rack16.srv0", "bay3.rack16.srv1", "bay3.rack16.srv2", "bay3.rack16.srv3",
		"bay3.rack17.srv0", "bay3.rack17.srv1", "bay3.rack17.srv2", "bay3.rack17.srv3",
		"bay3.rack18.srv0", "bay3.rack18.srv1", "bay3.rack18.srv2", "bay3.rack18.srv3",
		"bay3.rack19.srv0", "bay3.rack19.srv1", "bay3.rack19.srv2", "bay3.rack19.srv3",
		"bay3.rack20.srv0", "bay3.rack20.srv1", "bay3.rack20.srv2", "bay3.rack20.srv3",
		"bay3.rack21.srv0", "bay3.rack21.srv1", "bay3.rack21.srv2", "bay3.rack21.srv3",
		"bay3.rack22.srv0", "bay3.rack22.srv1", "bay3.rack22.srv2", "bay3.rack22.srv3",
		"bay3.rack23.srv0", "bay3.rack23.srv1", "bay3.rack23.srv2", "bay3.rack23.srv3",
		"bay3.rack24.srv0", "bay3.rack24.srv1", "bay3.rack24.srv2", "bay3.rack24.srv3",
		"bay3.rack25.srv0", "bay3.rack25.srv1", "bay3.rack25.srv2", "bay3.rack25.srv3",
		"bay3.rack26.srv0", "bay3.rack26.srv1", "bay3.rack26.srv2", "bay3.rack26.srv3",
		"bay3.rack27.srv0", "bay3.rack27.srv1", "bay3.rack27.srv2", "bay3.rack27.srv3",
		"bay3.rack28.srv0", "bay3.rack28.srv1", "bay3.rack28.srv2", "bay3.rack28.srv3",
		"bay3.rack29.srv0", "bay3.rack29.srv1", "bay3.rack29.srv2", "bay3.rack29.srv3",

		"bay4.rack0.srv0", "bay4.rack0.srv1", "bay4.rack0.srv2", "bay4.rack0.srv3",
		"bay4.rack1.srv0", "bay4.rack1.srv1", "bay4.rack1.srv2", "bay4.rack1.srv3",
		"bay4.rack2.srv0", "bay4.rack2.srv1", "bay4.rack2.srv2", "bay4.rack2.srv3",
		"bay4.rack3.srv0", "bay4.rack3.srv1", "bay4.rack3.srv2", "bay4.rack3.srv3",
		"bay4.rack4.srv0", "bay4.rack4.srv1", "bay4.rack4.srv2", "bay4.rack4.srv3",
		"bay4.rack5.srv0", "bay4.rack5.srv1", "bay4.rack5.srv2", "bay4.rack5.srv3",
		"bay4.rack6.srv0", "bay4.rack6.srv1", "bay4.rack6.srv2", "bay4.rack6.srv3",
		"bay4.rack7.srv0", "bay4.rack7.srv1", "bay4.rack7.srv2", "bay4.rack7.srv3",
		"bay4.rack8.srv0", "bay4.rack8.srv1", "bay4.rack8.srv2", "bay4.rack8.srv3",
		"bay4.rack9.srv0", "bay4.rack9.srv1", "bay4.rack9.srv2", "bay4.rack9.srv3",
		"bay4.rack10.srv0", "bay4.rack10.srv1", "bay4.rack10.srv2", "bay4.rack10.srv3",
		"bay4.rack11.srv0", "bay4.rack11.srv1", "bay4.rack11.srv2", "bay4.rack11.srv3",
		"bay4.rack12.srv0", "bay4.rack12.srv1", "bay4.rack12.srv2", "bay4.rack12.srv3",
		"bay4.rack13.srv0", "bay4.rack13.srv1", "bay4.rack13.srv2", "bay4.rack13.srv3",
		"bay4.rack14.srv0", "bay4.rack14.srv1", "bay4.rack14.srv2", "bay4.rack14.srv3",
		"bay4.rack15.srv0", "bay4.rack15.srv1", "bay4.rack15.srv2", "bay4.rack15.srv3",
		"bay4.rack16.srv0", "bay4.rack16.srv1", "bay4.rack16.srv2", "bay4.rack16.srv3",
		"bay4.rack17.srv0", "bay4.rack17.srv1", "bay4.rack17.srv2", "bay4.rack17.srv3",
		"bay4.rack18.srv0", "bay4.rack18.srv1", "bay4.rack18.srv2", "bay4.rack18.srv3",
		"bay4.rack19.srv0", "bay4.rack19.srv1", "bay4.rack19.srv2", "bay4.rack19.srv3",
		"bay4.rack20.srv0", "bay4.rack20.srv1", "bay4.rack20.srv2", "bay4.rack20.srv3",
		"bay4.rack21.srv0", "bay4.rack21.srv1", "bay4.rack21.srv2", "bay4.rack21.srv3",
		"bay4.rack22.srv0", "bay4.rack22.srv1", "bay4.rack22.srv2", "bay4.rack22.srv3",
		"bay4.rack23.srv0", "bay4.rack23.srv1", "bay4.rack23.srv2", "bay4.rack23.srv3",
		"bay4.rack24.srv0", "bay4.rack24.srv1", "bay4.rack24.srv2", "bay4.rack24.srv3",
		"bay4.rack25.srv0", "bay4.rack25.srv1", "bay4.rack25.srv2", "bay4.rack25.srv3",
		"bay4.rack26.srv0", "bay4.rack26.srv1", "bay4.rack26.srv2", "bay4.rack26.srv3",
		"bay4.rack27.srv0", "bay4.rack27.srv1", "bay4.rack27.srv2", "bay4.rack27.srv3",
		"bay4.rack28.srv0", "bay4.rack28.srv1", "bay4.rack28.srv2", "bay4.rack28.srv3",
		"bay4.rack29.srv0", "bay4.rack29.srv1", "bay4.rack29.srv2", "bay4.rack29.srv3",

		"bay5.rack0.srv0", "bay5.rack0.srv1", "bay5.rack0.srv2", "bay5.rack0.srv3",
		"bay5.rack1.srv0", "bay5.rack1.srv1", "bay5.rack1.srv2", "bay5.rack1.srv3",
		"bay5.rack2.srv0", "bay5.rack2.srv1", "bay5.rack2.srv2", "bay5.rack2.srv3",
		"bay5.rack3.srv0", "bay5.rack3.srv1", "bay5.rack3.srv2", "bay5.rack3.srv3",
		"bay5.rack4.srv0", "bay5.rack4.srv1", "bay5.rack4.srv2", "bay5.rack4.srv3",
		"bay5.rack5.srv0", "bay5.rack5.srv1", "bay5.rack5.srv2", "bay5.rack5.srv3",
		"bay5.rack6.srv0", "bay5.rack6.srv1", "bay5.rack6.srv2", "bay5.rack6.srv3",
		"bay5.rack7.srv0", "bay5.rack7.srv1", "bay5.rack7.srv2", "bay5.rack7.srv3",
		"bay5.rack8.srv0", "bay5.rack8.srv1", "bay5.rack8.srv2", "bay5.rack8.srv3",
		"bay5.rack9.srv0", "bay5.rack9.srv1", "bay5.rack9.srv2", "bay5.rack9.srv3",
		"bay5.rack10.srv0", "bay5.rack10.srv1", "bay5.rack10.srv2", "bay5.rack10.srv3",
		"bay5.rack11.srv0", "bay5.rack11.srv1", "bay5.rack11.srv2", "bay5.rack11.srv3",
		"bay5.rack12.srv0", "bay5.rack12.srv1", "bay5.rack12.srv2", "bay5.rack12.srv3",
		"bay5.rack13.srv0", "bay5.rack13.srv1", "bay5.rack13.srv2", "bay5.rack13.srv3",
		"bay5.rack14.srv0", "bay5.rack14.srv1", "bay5.rack14.srv2", "bay5.rack14.srv3",
		"bay5.rack15.srv0", "bay5.rack15.srv1", "bay5.rack15.srv2", "bay5.rack15.srv3",
		"bay5.rack16.srv0", "bay5.rack16.srv1", "bay5.rack16.srv2", "bay5.rack16.srv3",
		"bay5.rack17.srv0", "bay5.rack17.srv1", "bay5.rack17.srv2", "bay5.rack17.srv3",
		"bay5.rack18.srv0", "bay5.rack18.srv1", "bay5.rack18.srv2", "bay5.rack18.srv3",
		"bay5.rack19.srv0", "bay5.rack19.srv1", "bay5.rack19.srv2", "bay5.rack19.srv3",
		"bay5.rack20.srv0", "bay5.rack20.srv1", "bay5.rack20.srv2", "bay5.rack20.srv3",
		"bay5.rack21.srv0", "bay5.rack21.srv1", "bay5.rack21.srv2", "bay5.rack21.srv3",
		"bay5.rack22.srv0", "bay5.rack22.srv1", "bay5.rack22.srv2", "bay5.rack22.srv3",
		"bay5.rack23.srv0", "bay5.rack23.srv1", "bay5.rack23.srv2", "bay5.rack23.srv3",
		"bay5.rack24.srv0", "bay5.rack24.srv1", "bay5.rack24.srv2", "bay5.rack24.srv3",
		"bay5.rack25.srv0", "bay5.rack25.srv1", "bay5.rack25.srv2", "bay5.rack25.srv3",
		"bay5.rack26.srv0", "bay5.rack26.srv1", "bay5.rack26.srv2", "bay5.rack26.srv3",
		"bay5.rack27.srv0", "bay5.rack27.srv1", "bay5.rack27.srv2", "bay5.rack27.srv3",
		"bay5.rack28.srv0", "bay5.rack28.srv1", "bay5.rack28.srv2", "bay5.rack28.srv3",
		"bay5.rack29.srv0", "bay5.rack29.srv1", "bay5.rack29.srv2", "bay5.rack29.srv3",
		NULL,
	};

	_add_level_repartition_test2(lrt4, "6x30x4", 15, FALSE); // 12+3
	_add_level_repartition_test2(lrt4, "6x30x4", 18, TRUE); // 14+4

	const char *lrt5[181] = {
		"bay0.rack0",
		"bay0.rack1",
		"bay0.rack2",
		"bay0.rack3",
		"bay0.rack4",
		"bay0.rack5",
		"bay0.rack6",
		"bay0.rack7",
		"bay0.rack8",
		"bay0.rack9",
		"bay0.rack10",
		"bay0.rack11",
		"bay0.rack12",
		"bay0.rack13",
		"bay0.rack14",
		"bay0.rack15",
		"bay0.rack16",
		"bay0.rack17",
		"bay0.rack18",
		"bay0.rack19",
		"bay0.rack20",
		"bay0.rack21",
		"bay0.rack22",
		"bay0.rack23",
		"bay0.rack24",
		"bay0.rack25",
		"bay0.rack26",
		"bay0.rack27",
		"bay0.rack28",
		"bay0.rack29",

		"bay1.rack0",
		"bay1.rack1",
		"bay1.rack2",
		"bay1.rack3",
		"bay1.rack4",
		"bay1.rack5",
		"bay1.rack6",
		"bay1.rack7",
		"bay1.rack8",
		"bay1.rack9",
		"bay1.rack10",
		"bay1.rack11",
		"bay1.rack12",
		"bay1.rack13",
		"bay1.rack14",
		"bay1.rack15",
		"bay1.rack16",
		"bay1.rack17",
		"bay1.rack18",
		"bay1.rack19",
		"bay1.rack20",
		"bay1.rack21",
		"bay1.rack22",
		"bay1.rack23",
		"bay1.rack24",
		"bay1.rack25",
		"bay1.rack26",
		"bay1.rack27",
		"bay1.rack28",
		"bay1.rack29",

		"bay2.rack0",
		"bay2.rack1",
		"bay2.rack2",
		"bay2.rack3",
		"bay2.rack4",
		"bay2.rack5",
		"bay2.rack6",
		"bay2.rack7",
		"bay2.rack8",
		"bay2.rack9",
		"bay2.rack10",
		"bay2.rack11",
		"bay2.rack12",
		"bay2.rack13",
		"bay2.rack14",
		"bay2.rack15",
		"bay2.rack16",
		"bay2.rack17",
		"bay2.rack18",
		"bay2.rack19",
		"bay2.rack20",
		"bay2.rack21",
		"bay2.rack22",
		"bay2.rack23",
		"bay2.rack24",
		"bay2.rack25",
		"bay2.rack26",
		"bay2.rack27",
		"bay2.rack28",
		"bay2.rack29",

		"bay3.rack0",
		"bay3.rack1",
		"bay3.rack2",
		"bay3.rack3",
		"bay3.rack4",
		"bay3.rack5",
		"bay3.rack6",
		"bay3.rack7",
		"bay3.rack8",
		"bay3.rack9",
		"bay3.rack10",
		"bay3.rack11",
		"bay3.rack12",
		"bay3.rack13",
		"bay3.rack14",
		"bay3.rack15",
		"bay3.rack16",
		"bay3.rack17",
		"bay3.rack18",
		"bay3.rack19",
		"bay3.rack20",
		"bay3.rack21",
		"bay3.rack22",
		"bay3.rack23",
		"bay3.rack24",
		"bay3.rack25",
		"bay3.rack26",
		"bay3.rack27",
		"bay3.rack28",
		"bay3.rack29",

		"bay4.rack0",
		"bay4.rack1",
		"bay4.rack2",
		"bay4.rack3",
		"bay4.rack4",
		"bay4.rack5",
		"bay4.rack6",
		"bay4.rack7",
		"bay4.rack8",
		"bay4.rack9",
		"bay4.rack10",
		"bay4.rack11",
		"bay4.rack12",
		"bay4.rack13",
		"bay4.rack14",
		"bay4.rack15",
		"bay4.rack16",
		"bay4.rack17",
		"bay4.rack18",
		"bay4.rack19",
		"bay4.rack20",
		"bay4.rack21",
		"bay4.rack22",
		"bay4.rack23",
		"bay4.rack24",
		"bay4.rack25",
		"bay4.rack26",
		"bay4.rack27",
		"bay4.rack28",
		"bay4.rack29",

		"bay5.rack0",
		"bay5.rack1",
		"bay5.rack2",
		"bay5.rack3",
		"bay5.rack4",
		"bay5.rack5",
		"bay5.rack6",
		"bay5.rack7",
		"bay5.rack8",
		"bay5.rack9",
		"bay5.rack10",
		"bay5.rack11",
		"bay5.rack12",
		"bay5.rack13",
		"bay5.rack14",
		"bay5.rack15",
		"bay5.rack16",
		"bay5.rack17",
		"bay5.rack18",
		"bay5.rack19",
		"bay5.rack20",
		"bay5.rack21",
		"bay5.rack22",
		"bay5.rack23",
		"bay5.rack24",
		"bay5.rack25",
		"bay5.rack26",
		"bay5.rack27",
		"bay5.rack28",
		"bay5.rack29",

		NULL,
	};

	_add_level_repartition_test2(lrt5, "6x30", 15, FALSE); // 12+3
	_add_level_repartition_test2(lrt5, "6x30", 18, TRUE); // 14+4

	// Balanced platform: 3 racks, 5 host in each
	const char *lrt6[16] = {
			"rack0.srv0", "rack0.srv1", "rack0.srv2", "rack0.srv3", "rack0.srv4",
			"rack1.srv4", "rack1.srv5", "rack1.srv6", "rack1.srv7", "rack1.srv5",
			"rack2.srv8", "rack2.srv9", "rack2.srv10", "rack2.srv11", "rack2.srv12",
			NULL
	};
	_add_level_repartition_test(lrt6, "3x5", 12); // 7+5

	/* Unbalanced platform: 3 hosts in each rack except the last one. */
	const char *lrt7[26] = {
			"rack0.srv0", "rack0.srv1", "rack0.srv2",
			"rack1.srv0", "rack1.srv1", "rack1.srv2",
			"rack2.srv0", "rack2.srv1", "rack2.srv2",
			"rack3.srv0", "rack3.srv1", "rack3.srv2",
			"rack4.srv0", "rack4.srv1", "rack4.srv2",
			"rack5.srv0", "rack5.srv1", "rack5.srv2",
			"rack6.srv0", "rack6.srv1", "rack6.srv2",
			"rack7.srv0", "rack7.srv1", "rack7.srv2",
			"rack8.srv0",
			NULL,
	};
	_add_level_repartition_test2(lrt7, "8x3+1x1", 15, FALSE); // 12+3
	_add_level_repartition_test2(lrt7, "8x3+1x1", 16, FALSE); // 12+4
	_add_level_repartition_test2(lrt7, "8x3+1x1", 18, FALSE); // 14+4

	_add_tests_from_files(LB_TESTS_DATASETS);

	return g_test_run();
};
