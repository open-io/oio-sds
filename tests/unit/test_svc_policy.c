/*
OpenIO SDS unit tests
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

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
#include <unistd.h>

#include <metautils/lib/metautils.h>

#undef GQ
#define GQ() g_quark_from_static_string("oio.utils")

static void
test_tags(const gchar *str, ...)
{
	struct service_update_policies_s *svcpol;
	va_list args;
	GError *err;

	svcpol = service_update_policies_create();
	g_assert(svcpol != NULL);

	err = service_update_reconfigure(svcpol, str);
	g_assert_no_error(err);

	va_start(args, str);
	for (;;) {
		char *_t, *_n, *_v;

		if (!(_t = va_arg(args, char*)))
			break;
		if (!(_n = va_arg(args, char*)))
			break;
		if (!(_v = va_arg(args, char*)))
			break;

		g_debug("check %s (%s,%s)", _t, _n, _v);
		gchar *n = NULL, *v = NULL;

		if (*_n) {
			gboolean expected = service_update_tagfilter(svcpol, _t, &n, &v);
			g_assert_true(expected);
			g_assert(n != NULL);
			g_assert(v != NULL);
			g_assert(0 == strcmp(n, _n));
			g_assert(0 == strcmp(v, _v));
		}
		else {
			gboolean expected = service_update_tagfilter(svcpol, _t, &n, &v);
			g_assert_false(expected);
			g_assert(n == NULL);
			g_assert(v == NULL);
		}

		oio_str_clean (&n);
		oio_str_clean (&v);
	}
	va_end(args);

	service_update_policies_destroy(svcpol);
}

static void
test_replicas(const gchar *str, ...)
{
	struct service_update_policies_s *svcpol;
	va_list args;
	GError *err;

	svcpol = service_update_policies_create();
	g_assert(svcpol != NULL);

	err = service_update_reconfigure(svcpol, str);
	g_assert_no_error(err);

	va_start(args, str);
	for (;;) {
		char *type;
		guint nb, expected;

		if (!(type = va_arg(args, char*)))
			break;
		nb = va_arg(args, guint);

		expected = service_howmany_replicas(svcpol, type);
		g_debug("str=[%s] type=[%s] ns=%u expected=%u",
				str, type, nb, expected);
		g_assert(nb == expected);
	}
	va_end(args);

	service_update_policies_destroy(svcpol);
}

static void
test_configure_str(gboolean expected, const gchar *str)
{
	struct service_update_policies_s *svcpol = service_update_policies_create();
	g_assert(svcpol != NULL);

	for (int i=0; i<16 ;++i) {
		GError *err = service_update_reconfigure(svcpol, str);
		if (expected) {
			g_assert_no_error(err);
			gchar *dump = service_update_policies_dump(svcpol);
			g_test_message("DUMP: %s", dump);
			g_free(dump);
		}
		else {
			g_assert_error(err, GQ(), 0);
			g_test_message("Expected error : (%d) %s",
					err->code, err->message);
			g_clear_error(&err);
		}
	}

	service_update_policies_destroy(svcpol);
}

static void
test_create_destroy(void)
{
	struct service_update_policies_s *svcpol;
	svcpol = service_update_policies_create();
	g_assert(svcpol != NULL);
	service_update_policies_destroy(svcpol);
}

static void
test_configure_valid(void)
{
	test_configure_str(TRUE, "");
	test_configure_str(TRUE, " ");
	test_configure_str(TRUE, ";");
	test_configure_str(TRUE, " ;; ");
	test_configure_str(TRUE, "; ;");
	test_configure_str(TRUE, " ; ; ");
	test_configure_str(TRUE, "SVC0=KEEP|1;SVC1=APPEND|2;SVC2=REPLACE|3");
	test_configure_str(TRUE, "SVC0=KEEP;SVC1=APPEND;SVC2=REPLACE");
	test_configure_str(TRUE, "SVC0=KEEP;SVC0=APPEND;SVC0=REPLACE");
	test_configure_str(TRUE, ";SVC=KEEP; SVC=REPLACE;SVC=APPEND ;; ; ");

	test_replicas("SVC0=KEEP|1;SVC1=APPEND|2;SVC2=REPLACE|3",
			"SVC0", 1U,
			"SVC1", 2U,
			"SVC2", 3U,
			NULL);

	test_replicas("SVC7=KEEP|1;SVC8=APPEND|2;SVC7=REPLACE|3",
			"SVC7", 3U,
			"SVC8", 2U,
			NULL);

	test_tags("SVC9=KEEP|7|1|tag.name=tag.value;SVC10=KEEP|2|3|tag.name=tag.value;SVC10=KEEP|1",
			"SVC9", "tag.name", "tag.value",
			"SVC10", "", "",
			NULL);
}

static void
test_configure_invalid(void)
{
	test_configure_str(FALSE, ";=; ");
	test_configure_str(FALSE, "SVC=APPEND|0;");
	test_configure_str(FALSE, "SVC=APPEND|-1;");
	test_configure_str(FALSE, "SVC=PREPEND");
	test_configure_str(FALSE, "=APPEND");
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/metautils/svc_policy/create_destroy",
			test_create_destroy);
	g_test_add_func("/metautils/svc_policy/configure/valid",
			test_configure_valid);
	g_test_add_func("/metautils/svc_policy/configure/invalid",
			test_configure_invalid);
	return g_test_run();
}

