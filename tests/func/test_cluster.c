/*
OpenIO SDS conscience client
Copyright (C) 2017 OpenIO, as part of OpenIO Software Defined Storage

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

#include <core/oioext.h>
#include <core/internals.h>
#include <cluster/lib/gridcluster.h>

#undef GQ
#define GQ() g_quark_from_static_string("oio.cluster.lib")

const char *ns = NULL;
const char *srvtype = NULL;

static void
test_cluster_push_errors (void)
{
	do {
		struct service_info_s srv = {{0}};
		g_strlcpy(srv.ns_name, ns, sizeof(srv.ns_name));
		g_strlcpy(srv.type, srvtype, sizeof(srv.type));
		GError *err = conscience_push_service(ns, &srv);
		g_assert_error(err, GQ(), CODE_BAD_REQUEST);
		g_clear_error(&err);
	} while (0);
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_assert_nonnull (g_getenv ("OIO_NS"));
	ns = g_getenv ("OIO_NS");
	srvtype = g_getenv ("OIO_TEST_SRVTYPE");
	if (!srvtype) srvtype = "echo";

	g_test_add_func("/cluster/push/errors", test_cluster_push_errors);

	return g_test_run();
}

