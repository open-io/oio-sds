/*
OpenIO SDS conscience client
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

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

#include <core/oio_core.h>
#include <core/oio_sds.h>
#include <core/internals.h>
#include <metautils/lib/metautils.h>

#undef GQ
#define GQ() g_quark_from_static_string("oio.core")

/* TODO(jfs): get the variables from the environment */
const char *ns = "NS";
const char *srvtype = "echo";

/* loop on create/destroy to raise a leak */
static void
test_proxied_init (void)
{
	for (int i=0; i<16 ;++i) {
		struct oio_cs_client_s *cs = oio_cs_client__create_proxied (ns);
		g_assert_nonnull (cs);
		oio_cs_client__destroy (cs);
	}
}

/* loop on the push (with various parameters) to attempt raising memleaks */
static void
test_proxied_push (void)
{
	struct oio_cs_registration_s reg = {
		.id = "klkqd",
		.url = "127.0.0.1:5000",
		.kv_tags = NULL,
	};
	const char *tags1[] = { "stat.cpu", NULL };
	const char *tags2[] = { "stat.cpu", "100.0", NULL };
	const char *tags3[] = { "stat.cpu", "invalid but should work", NULL };
	GError *err;

	struct oio_cs_client_s *cs = oio_cs_client__create_proxied (ns);
	g_assert_nonnull (cs);
	for (int i=0; i<8 ;++i) {
		err = oio_cs_client__register_service (cs, srvtype, NULL);
		g_assert_error (err, GQ(), CODE_BAD_REQUEST);
		g_clear_error (&err);
		reg.kv_tags = NULL;
		err = oio_cs_client__register_service (cs, srvtype, &reg);
		g_assert_no_error (err);
		reg.kv_tags = tags1;
		err = oio_cs_client__register_service (cs, srvtype, &reg);
		g_assert_no_error (err);
		reg.kv_tags = tags2;
		err = oio_cs_client__register_service (cs, srvtype, &reg);
		g_assert_no_error (err);
		reg.kv_tags = tags3;
		err = oio_cs_client__register_service (cs, srvtype, &reg);
		g_assert_no_error (err);
	}
	oio_cs_client__destroy (cs);
}

/* loop on the push (with various parameters) to attempt raising memleaks */
static void
test_proxied_deregister (void)
{
	struct oio_cs_registration_s reg = {
		.id = "klkqd",
		.url = "127.0.0.1:5000",
		.kv_tags = NULL,
	};
	const char *tags[] = { "stat.cpu", "100.0", NULL };
	GError *err;

	struct oio_cs_client_s *cs = oio_cs_client__create_proxied (ns);
	g_assert_nonnull (cs);
	for (int i=0; i<8 ;++i) {
		err = oio_cs_client__flush_services (cs, srvtype);
		g_assert_no_error (err);
		reg.kv_tags = tags;
		err = oio_cs_client__register_service (cs, srvtype, &reg);
		g_assert_no_error (err);
		void on_reg (const struct oio_cs_registration_s *preg) {
			GRID_DEBUG("turn=%d id=%s url=%s", i, preg->id, preg->url);
		}
		err = oio_cs_client__list_services (cs, srvtype, on_reg);
		g_assert_no_error (err);
		err = oio_cs_client__flush_services (cs, srvtype);
		g_assert_no_error (err);
	}
	oio_cs_client__destroy (cs);
}

static void
test_proxied_list (void)
{
	GError *err;
	struct oio_cs_client_s *cs = oio_cs_client__create_proxied (ns);
	g_assert_nonnull (cs);
	for (int i=0; i<8 ;++i) {
		err = oio_cs_client__list_services (cs, NULL, NULL);
		g_assert_error (err, GQ(), CODE_BAD_REQUEST);
		g_clear_error (&err);
		err = oio_cs_client__list_services (cs, "", NULL);
		g_assert_error (err, GQ(), CODE_BAD_REQUEST);
		g_clear_error (&err);
		err = oio_cs_client__list_services (cs, "xXxXxXxXx", NULL);
		g_assert_error (err, GQ(), CODE_SRVTYPE_NOTMANAGED);
		g_clear_error (&err);
		err = oio_cs_client__list_services (cs, srvtype, NULL);
		g_assert_no_error (err);
	}
	oio_cs_client__destroy (cs);
}

static void
test_proxied_types (void)
{
	GError *err;
	struct oio_cs_client_s *cs = oio_cs_client__create_proxied (ns);
	g_assert_nonnull (cs);
	for (int i=0; i<8 ;++i) {
		void on_type (const char *st) {
			GRID_DEBUG("turn=%d type=%s", i, st);
		}
		err = oio_cs_client__list_types (cs, on_type);
		g_assert_no_error (err);
	}
	oio_cs_client__destroy (cs);
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/cs/proxy/init", test_proxied_init);
	g_test_add_func("/cs/proxy/push", test_proxied_push);
	g_test_add_func("/cs/proxy/list", test_proxied_list);
	g_test_add_func("/cs/proxy/types", test_proxied_types);
	g_test_add_func("/cs/proxy/deregister", test_proxied_deregister);
	return g_test_run();
}
