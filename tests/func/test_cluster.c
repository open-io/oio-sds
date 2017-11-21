/*
OpenIO SDS functional tests
Copyright (C) 2017 OpenIO SAS, as part of OpenIO SDS

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
#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>

#define GQ_CLUSTER() g_quark_from_static_string("oio.cluster.lib")
#define GQ_CORE() g_quark_from_static_string("oio.core")

const char *ns = NULL;
const char *srvtype = NULL;

static void
test_cluster_info_success (void)
{
	struct namespace_info_s *nsi = NULL;
	GError *err = conscience_get_namespace(ns, &nsi);
	g_assert_no_error(err);
	g_assert_nonnull(nsi);
	namespace_info_free(nsi);
}

static void
test_cluster_info_errors (void)
{
	struct namespace_info_s *nsi = NULL;
	GError *err = conscience_get_namespace("kjhkjhoiulkd", &nsi);
	g_assert_error(err, GQ_CORE(), CODE_NAMESPACE_NOTMANAGED);
	g_clear_error(&err);
	g_assert_null(nsi);
}

static void
test_cluster_info_abort_no_ns (void)
{
	if (g_test_subprocess()) {
		struct namespace_info_s *out = NULL;
		conscience_get_namespace(NULL, &out);
	} else {
		g_test_trap_subprocess (NULL, 0, 0);
		g_test_trap_assert_failed ();
	}
}

static void
test_cluster_info_abort_no_out (void)
{
	if (g_test_subprocess()) {
		conscience_get_namespace(ns, NULL);
	} else {
		g_test_trap_subprocess (NULL, 0, 0);
		g_test_trap_assert_failed ();
	}
}

static void
test_cluster_list_success (void)
{
	GSList *out = NULL;
	GError *err = conscience_get_services(ns, srvtype, FALSE, &out, 0);
	g_assert_no_error(err);
	g_slist_free_full(out, (GDestroyNotify) service_info_clean);
}

static void
test_cluster_list_errors (void)
{
	GError *err = NULL;
	GSList *out = NULL;

	err = conscience_get_services(ns, "XxXXxXXxx", FALSE, &out, 0);
	g_assert_error(err, GQ_CORE(), CODE_SRVTYPE_NOTMANAGED);
	g_clear_error(&err);
	g_assert_null(out);

	err = conscience_get_services("lqoaioxjlqkmxjslqkjx", srvtype, FALSE, &out, 0);
	g_assert_error(err, GQ_CORE(), CODE_NAMESPACE_NOTMANAGED);
	g_clear_error(&err);
	g_assert_null(out);

	err = conscience_get_services("lqoaioxjlqkmxjslqkjx", "XxXXxXXxx", FALSE, &out, 0);
	g_assert_error(err, GQ_CORE(), CODE_NAMESPACE_NOTMANAGED);
	g_clear_error(&err);
	g_assert_null(out);
}

static void
test_cluster_list_abort_no_ns (void)
{
	if (g_test_subprocess ()) {
		conscience_get_services(NULL, srvtype, FALSE, NULL, 0);
	} else {
		g_test_trap_subprocess (NULL, 0, 0);
		g_test_trap_assert_failed ();
	}
}

static void
test_cluster_list_abort_no_type (void)
{
	if (g_test_subprocess ()) {
		GSList *out = NULL;
		conscience_get_services(ns, NULL, FALSE, &out, 0);
	} else {
		g_test_trap_subprocess (NULL, 0, 0);
		g_test_trap_assert_failed ();
	}
}

static void
test_cluster_list_abort_no_out (void)
{
	if (g_test_subprocess ()) {
		conscience_get_services(ns, srvtype, FALSE, NULL, 0);
	} else {
		g_test_trap_subprocess (NULL, 0, 0);
		g_test_trap_assert_failed ();
	}
}

static void
test_cluster_types_success (void)
{
	GSList *out = NULL;
	GError *err = conscience_get_types(ns, &out);
	g_assert_no_error(err);
	g_assert_nonnull(out);
	g_assert_cmpuint(0, <, g_slist_length(out));
	g_slist_free_full(out, g_free);
}

static void
test_cluster_types_errors (void)
{
	GSList *out = NULL;
	GError *err = NULL;

	err = conscience_get_types("b,yugjghcfcdjghbv", &out);
	g_assert_error(err, GQ_CORE(), CODE_NAMESPACE_NOTMANAGED);
	g_clear_error(&err);
	g_assert_null(out);
}

static void
test_cluster_types_abort_no_ns (void)
{
	if (g_test_subprocess()) {
		GSList *out = NULL;
		conscience_get_types(NULL, &out);
	} else {
		g_test_trap_subprocess (NULL, 0, 0);
		g_test_trap_assert_failed ();
	}
}

static void
test_cluster_types_abort_no_out (void)
{
	if (g_test_subprocess()) {
		conscience_get_types(ns, NULL);
	} else {
		g_test_trap_subprocess (NULL, 0, 0);
		g_test_trap_assert_failed ();
	}
}

static void
test_cluster_push_abort_no_ns (void)
{
	if (g_test_subprocess()) {
		struct service_info_s si = {{0}};
		conscience_push_service(NULL, &si);
	} else {
		g_test_trap_subprocess (NULL, 0, 0);
		g_test_trap_assert_failed ();
	}
}

static void
test_cluster_push_abort_no_srv (void)
{
	if (g_test_subprocess()) {
		conscience_push_service(ns, NULL);
	} else {
		g_test_trap_subprocess (NULL, 0, 0);
		g_test_trap_assert_failed ();
	}
}

static void
test_cluster_push_errors (void)
{
	do {
		struct service_info_s srv = {{0}};
		GError *err = conscience_push_service(ns, &srv);
		g_assert_error(err, GQ_CLUSTER(), CODE_BAD_REQUEST);
		g_clear_error(&err);
	} while (0);

	do {
		struct service_info_s srv = {{0}};
		g_strlcpy(srv.ns_name, ns, sizeof(srv.ns_name));
		g_strlcpy(srv.type, srvtype, sizeof(srv.type));
		GError *err = conscience_push_service(ns, &srv);
		g_assert_error(err, GQ_CLUSTER(), CODE_BAD_REQUEST);
		g_clear_error(&err);
	} while (0);
}

static void
test_cluster_register_success (void)
{
	do {  /* without even an array for the tags */
		struct service_info_s srv = {{0}};
		g_strlcpy(srv.ns_name, ns, sizeof(srv.ns_name));
		g_strlcpy(srv.type, srvtype, sizeof(srv.type));
		grid_string_to_addrinfo("127.0.0.1:80", &srv.addr);
		GError *err = register_namespace_service(&srv);
		g_assert_no_error(err);
	} while (0);

	do {  /* without tags */
		struct service_info_s srv = {{0}};
		g_strlcpy(srv.ns_name, ns, sizeof(srv.ns_name));
		g_strlcpy(srv.type, srvtype, sizeof(srv.type));
		grid_string_to_addrinfo("127.0.0.1:80", &srv.addr);
		srv.tags = g_ptr_array_new();
		GError *err = register_namespace_service(&srv);
		g_assert_no_error(err);
		g_ptr_array_set_free_func(srv.tags, g_free);
		g_ptr_array_free(srv.tags, TRUE);
	} while (0);

	do {  /* with a string tag for the volume */
		struct service_info_s srv = {{0}};
		g_strlcpy(srv.ns_name, ns, sizeof(srv.ns_name));
		g_strlcpy(srv.type, srvtype, sizeof(srv.type));
		grid_string_to_addrinfo("127.0.0.1:80", &srv.addr);
		srv.tags = g_ptr_array_new();
		service_tag_set_value_string(
				service_info_ensure_tag(srv.tags, "tag.vol"), "/tmp");
		GError *err = register_namespace_service(&srv);
		g_assert_no_error(err);
		g_ptr_array_set_free_func(srv.tags, g_free);
		g_ptr_array_free(srv.tags, TRUE);
	} while (0);

	do {  /* with a non-string tag for the volume */
		struct service_info_s srv = {{0}};
		g_strlcpy(srv.ns_name, ns, sizeof(srv.ns_name));
		g_strlcpy(srv.type, srvtype, sizeof(srv.type));
		grid_string_to_addrinfo("127.0.0.1:80", &srv.addr);
		srv.tags = g_ptr_array_new();
		service_tag_set_value_float(
				service_info_ensure_tag(srv.tags, "tag.vol"), 0.1);
		GError *err = register_namespace_service(&srv);
		g_assert_no_error(err);
		g_ptr_array_set_free_func(srv.tags, g_free);
		g_ptr_array_free(srv.tags, TRUE);
	} while (0);
}

static void
test_cluster_register_abort_no_srv (void)
{
	if (g_test_subprocess()) {
		register_namespace_service(NULL);
	} else {
		g_test_trap_subprocess (NULL, 0, 0);
		g_test_trap_assert_failed ();
	}
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_assert_nonnull (g_getenv ("OIO_NS"));
	ns = g_getenv ("OIO_NS");
	srvtype = g_getenv ("OIO_TEST_SRVTYPE");
	if (!srvtype) srvtype = "echo";

	g_test_add_func("/cluster/info/success", test_cluster_info_success);
	g_test_add_func("/cluster/info/errors", test_cluster_info_errors);
	g_test_add_func("/cluster/info/abort/no_ns", test_cluster_info_abort_no_ns);
	g_test_add_func("/cluster/info/abort/no_out", test_cluster_info_abort_no_out);
	g_test_add_func("/cluster/types/success", test_cluster_types_success);
	g_test_add_func("/cluster/types/errors", test_cluster_types_errors);
	g_test_add_func("/cluster/types/abort/no_ns", test_cluster_types_abort_no_ns);
	g_test_add_func("/cluster/types/abort/no_out", test_cluster_types_abort_no_out);
	g_test_add_func("/cluster/list/success", test_cluster_list_success);
	g_test_add_func("/cluster/list/errors", test_cluster_list_errors);
	g_test_add_func("/cluster/list/abort/no_ns", test_cluster_list_abort_no_ns);
	g_test_add_func("/cluster/list/abort/no_type", test_cluster_list_abort_no_type);
	g_test_add_func("/cluster/list/abort/no_out", test_cluster_list_abort_no_out);
	g_test_add_func("/cluster/push/errors", test_cluster_push_errors);
	g_test_add_func("/cluster/push/abort/no_ns", test_cluster_push_abort_no_ns);
	g_test_add_func("/cluster/push/abort/no_srv", test_cluster_push_abort_no_srv);
	g_test_add_func("/cluster/register/success", test_cluster_register_success);
	g_test_add_func("/cluster/register/abort/no_srv", test_cluster_register_abort_no_srv);

	return g_test_run();
}

