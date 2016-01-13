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

#include <core/oiolog.h>
#include <core/oiocs.h>
#include <core/internals.h>

#undef GQ
#define GQ() g_quark_from_static_string("oio.core")

/* TODO(jfs): get the variables from the environment */
const char *ns = "NS";
const char *srvtype = "echo";

static void
test_proxied_init (void)
{
	for (int i=0; i<8 ;++i) {
		struct oio_cs_client_s *cs = oio_cs_client__create_proxied (ns);
		oio_cs_client__destroy (cs);
	}
}

static void
test_proxied_push (void)
{
	struct oio_cs_registration_s reg0 = {
		.id = "klkqd",
		.url = "127.0.0.1:5000",
		.kv_tags = NULL,
	};
	const char *tags1[] = {
		"stat.cpu", "100.0",
		NULL
	};
	struct oio_cs_registration_s reg1 = {
		.id = "klkqd",
		.url = "127.0.0.1:5000",
		.kv_tags = tags1,
	};
	GError *err;
	struct oio_cs_client_s *cs = oio_cs_client__create_proxied (ns);
	for (int i=0; i<8 ;++i) {
		err = oio_cs_client__register_service (cs, srvtype, NULL);
		g_assert_error (err, GQ(), CODE_BAD_REQUEST);
		err = oio_cs_client__register_service (cs, srvtype, &reg0);
		g_assert_no_error (err);
		err = oio_cs_client__register_service (cs, srvtype, &reg1);
		g_assert_no_error (err);
	}
	oio_cs_client__destroy (cs);
}

int
main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	oio_log_lazy_init ();
	oio_log_init_level(GRID_LOGLVL_INFO);
	g_log_set_default_handler(oio_log_stderr, NULL);

	g_test_add_func("/cs/proxy/init", test_proxied_init);
	g_test_add_func("/cs/proxy/push", test_proxied_push);
	return g_test_run();
}


