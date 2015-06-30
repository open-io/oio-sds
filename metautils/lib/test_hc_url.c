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

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metautils.url"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "metautils_loggers.h"
#include "hc_url.h"
#include "common_main.h"

struct test_data_s {
	const char *url;
	const char *whole;

	const char *ns;
	const char *account;
	const char *ref;
	const char *type;
	const char *path;

	const char *hexa;
};

#define TEST_END {NULL,NULL, NULL,NULL,NULL,NULL,NULL, NULL}

static void
_test_field (const char *v, struct hc_url_s *u, enum hc_url_field_e f)
{
	if (v) {
		g_assert (hc_url_has (u, f));
		g_assert (!strcmp (v, hc_url_get (u, f)));
	} else {
		g_assert (!hc_url_has (u, f));
		g_assert (NULL == hc_url_get (u, f));
	}
}

static void
_test_url (guint idx, struct hc_url_s *u, struct test_data_s *td)
{
	(void) idx;
	_test_field (td->whole, u, HCURL_WHOLE);
	_test_field (td->ns, u, HCURL_NS);
	_test_field (td->account, u, HCURL_ACCOUNT);
	_test_field (td->ref, u, HCURL_USER);
	_test_field (td->type, u, HCURL_TYPE);
	_test_field (td->path, u, HCURL_PATH);
	if (td->hexa) {
		g_assert (hc_url_has (u, HCURL_HEXID));
		g_assert (NULL != hc_url_get_id (u));
		g_assert (!g_ascii_strcasecmp (hc_url_get (u, HCURL_HEXID), td->hexa));
	} else {
		g_assert (!hc_url_has (u, HCURL_HEXID));
		g_assert (NULL == hc_url_get_id (u));
		g_assert (NULL == hc_url_get (u, HCURL_HEXID));
	}
}

static struct hc_url_s *
_init_url (struct test_data_s *td)
{
	struct hc_url_s *url = hc_url_empty ();
	if (td->ns) hc_url_set (url, HCURL_NS, td->ns);
	if (td->account) hc_url_set (url, HCURL_ACCOUNT, td->account);
	if (td->ref) hc_url_set (url, HCURL_USER, td->ref);
	if (td->type) hc_url_set (url, HCURL_TYPE, td->type);
	if (td->path) hc_url_set (url, HCURL_PATH, td->path);
	return url;
}

static void
test_configure_valid (void)
{
	static struct test_data_s tab[] = {
		{ "/NS//JFS",
			"NS//JFS/",
			"NS", HCURL_DEFAULT_ACCOUNT, "JFS", HCURL_DEFAULT_TYPE, NULL,
			"C3F36084054557E6DBA6F001C41DAFBFEF50FCC83DB2B3F782AE414A07BB3A7A"},

		{ "NS//JFS//1.",
			"NS//JFS//1.",
			"NS", HCURL_DEFAULT_ACCOUNT, "JFS", HCURL_DEFAULT_TYPE, "1.",
			"C3F36084054557E6DBA6F001C41DAFBFEF50FCC83DB2B3F782AE414A07BB3A7A"},

		TEST_END
	};

	guint idx = 0;
	for (struct test_data_s *th=tab; th->url ;th++) {
		struct hc_url_s *url;

		url = hc_url_init(th->url);
		g_assert(url != NULL);
		_test_url (idx++, url, th);
		hc_url_pclean (&url);

		url = _init_url (th);
		g_assert(url != NULL);
		_test_url (idx++, url, th);
		hc_url_pclean (&url);
	}
}

static void
test_configure_valid_old(void)
{
	static struct test_data_s tab[] = {
		{ "/NS/JFS",
			"NS//JFS/",
			"NS", HCURL_DEFAULT_ACCOUNT, "JFS", HCURL_DEFAULT_TYPE, NULL,
			"C3F36084054557E6DBA6F001C41DAFBFEF50FCC83DB2B3F782AE414A07BB3A7A"},

		{ "/NS/JFS/1.",
			"NS//JFS//1.",
			"NS", HCURL_DEFAULT_ACCOUNT, "JFS", HCURL_DEFAULT_TYPE, "1.",
			"C3F36084054557E6DBA6F001C41DAFBFEF50FCC83DB2B3F782AE414A07BB3A7A"},

		{ "NS//JFS//1.",
			"NS//JFS//%2F1.",
			"NS", HCURL_DEFAULT_ACCOUNT, "JFS", HCURL_DEFAULT_TYPE, "/1.",
			"C3F36084054557E6DBA6F001C41DAFBFEF50FCC83DB2B3F782AE414A07BB3A7A"},

		TEST_END
	};

	guint idx = 0;
	for (struct test_data_s *th=tab; th->url ;th++) {
		struct hc_url_s *url;

		url = hc_url_oldinit(th->url);
		g_assert(url != NULL);
		_test_url (idx++, url, th);
		hc_url_pclean (&url);

		url = _init_url (th);
		g_assert(url != NULL);
		_test_url (idx++, url, th);
		hc_url_pclean (&url);
	}
}

static void
test_configure_invalid(void)
{
	struct hc_url_s *url;

	url = hc_url_oldinit("");
	g_assert(url == NULL);

	url = hc_url_oldinit("/");
	g_assert(url == NULL);
}

static void
test_options (void)
{
	struct hc_url_s *url = hc_url_empty();
	hc_url_set(url, HCURL_NS, "NS");
	hc_url_set(url, HCURL_USER, "REF");
	hc_url_set(url, HCURL_PATH, "PATH");

	const gchar *v;

	hc_url_set_option(url, "k", "v");
	v = hc_url_get_option_value(url, "k");
	g_assert(0 == strcmp(v, "v"));

	hc_url_set_option(url, "k", "v0");
	v = hc_url_get_option_value(url, "k");
	g_assert(0 == strcmp(v, "v0"));

	hc_url_clean(url);
	url = NULL;
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/metautils/hc_url/configure/valid_old",
			test_configure_valid_old);
	g_test_add_func("/metautils/hc_url/configure/valid",
			test_configure_valid);
	g_test_add_func("/metautils/hc_url/configure/invalid",
			test_configure_invalid);
	g_test_add_func("/metautils/hc_url/options", test_options);
	return g_test_run();
}

