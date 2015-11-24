/*
OpenIO SDS core library
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "oio_core.h"

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
_test_field (const char *v, struct oio_url_s *u, enum oio_url_field_e f)
{
	const char *found = oio_url_get (u, f);
	if (v) {
		g_assert (oio_url_has (u, f));
		g_assert (!strcmp (v, found));
	} else {
		g_assert (!oio_url_has (u, f));
		g_assert (NULL == found);
	}
}

static void
_test_url (guint idx, struct oio_url_s *u, struct test_data_s *td)
{
	(void) idx;
	_test_field (td->whole, u, OIOURL_WHOLE);
	_test_field (td->ns, u, OIOURL_NS);
	_test_field (td->account, u, OIOURL_ACCOUNT);
	_test_field (td->ref, u, OIOURL_USER);
	_test_field (td->type, u, OIOURL_TYPE);
	_test_field (td->path, u, OIOURL_PATH);
	if (td->hexa) {
		g_assert (oio_url_has (u, OIOURL_HEXID));
		g_assert (NULL != oio_url_get_id (u));
		g_assert (!g_ascii_strcasecmp (oio_url_get (u, OIOURL_HEXID), td->hexa));
	} else {
		g_assert (!oio_url_has (u, OIOURL_HEXID));
		g_assert (NULL == oio_url_get_id (u));
		g_assert (NULL == oio_url_get (u, OIOURL_HEXID));
	}
}

static struct oio_url_s *
_init_url (struct test_data_s *td)
{
	struct oio_url_s *url = oio_url_empty ();
	if (td->ns) oio_url_set (url, OIOURL_NS, td->ns);
	if (td->account) oio_url_set (url, OIOURL_ACCOUNT, td->account);
	if (td->ref) oio_url_set (url, OIOURL_USER, td->ref);
	if (td->type) oio_url_set (url, OIOURL_TYPE, td->type);
	if (td->path) oio_url_set (url, OIOURL_PATH, td->path);
	return url;
}

static void
test_configure_valid (void)
{
	static struct test_data_s tab[] = {
		{ "/NS/ACCT/JFS",
			"NS/ACCT/JFS/",
			"NS", "ACCT", "JFS", OIOURL_DEFAULT_TYPE, NULL,
			"9006CE70B59E5777D6BB410C57944812EB05FCDB5BA85D520A14B3051D1D094F"},

		{ "NS/ACCT/JFS//1.",
			"NS/ACCT/JFS//1.",
			"NS", "ACCT", "JFS", OIOURL_DEFAULT_TYPE, "1.",
			"9006CE70B59E5777D6BB410C57944812EB05FCDB5BA85D520A14B3051D1D094F"},

		TEST_END
	};

	guint idx = 0;
	for (struct test_data_s *th=tab; th->url ;th++) {
		struct oio_url_s *url;

		url = oio_url_init(th->url);
		g_assert(url != NULL);
		_test_url (idx++, url, th);
		oio_url_pclean (&url);

		url = _init_url (th);
		g_assert(url != NULL);
		_test_url (idx++, url, th);
		oio_url_pclean (&url);
	}
}

static void
test_configure_invalid(void)
{
	struct oio_url_s *url;

	url = oio_url_init("");
	g_assert(url == NULL);

	url = oio_url_init("/");
	g_assert(url == NULL);
}

/* Plays a set of duplication/free roundtrips. */
static void
_round_dup_cleanup (struct oio_url_s *u0)
{
	for (guint i=0; i<64 ;++i)
		oio_url_clean (oio_url_dup (u0));
}

/* Plays rounds of allocations/librations on partial URL */
static void
test_dup (void)
{
	struct oio_url_s *u0 = oio_url_empty ();

	oio_url_set (u0, OIOURL_NS, "NS");
	_round_dup_cleanup (u0);

	oio_url_set (u0, OIOURL_ACCOUNT, "ACCT");
	_round_dup_cleanup (u0);

	oio_url_set (u0, OIOURL_USER, "JFS");
	_round_dup_cleanup (u0);

	(void) oio_url_get_id (u0);
	(void) oio_url_get_id_size (u0);
	_round_dup_cleanup (u0);

	oio_url_set (u0, OIOURL_TYPE, "mail");
	_round_dup_cleanup (u0);

	oio_url_set (u0, OIOURL_PATH, "path");
	_round_dup_cleanup (u0);

	oio_url_set (u0, OIOURL_CONTENTID, "XYZT");
	_round_dup_cleanup (u0);

	oio_url_set (u0, OIOURL_CONTENTID, "0000");
	_round_dup_cleanup (u0);

	oio_url_set (u0, OIOURL_VERSION, "0");
	_round_dup_cleanup (u0);

	oio_url_pclean (&u0);
}

int
main(int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);
	oio_log_lazy_init ();
	oio_log_init_level(GRID_LOGLVL_INFO);
	g_log_set_default_handler(oio_log_stderr, NULL);

	g_test_add_func("/core/url/configure/valid",
			test_configure_valid);
	g_test_add_func("/core/url/configure/invalid",
			test_configure_invalid);
	g_test_add_func("/core/url/dup", test_dup);
	return g_test_run();
}

