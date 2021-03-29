/*
OpenIO SDS unit tests
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#include <core/oio_core.h>
#include <core/url_ext.h>
#include <metautils/lib/common_main.h>
#include <core/internals.h>

#undef GQ
#define GQ() g_quark_from_static_string("oio.core")

struct test_data_s {
	const char *url; /* to be decoded */
	const char *whole; /* expected packed result */

	const char *ns;
	const char *account;
	const char *ref;
	const char *path;

	const char *hexa;
};

#define TEST_END {NULL,NULL, NULL,NULL,NULL,NULL, NULL}

static void
_test_field (const char *expected, struct oio_url_s *u, enum oio_url_field_e f)
{
	if (expected) {
		g_assert_true (oio_url_has (u, f));
		g_assert_cmpstr (oio_url_get (u, f), ==, expected);
	} else {
		g_assert_false (oio_url_has (u, f));
		g_assert_null (oio_url_get (u, f));
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
	_test_field (td->path, u, OIOURL_PATH);
	if (td->hexa) {
		g_assert_true (oio_url_has (u, OIOURL_HEXID));
		g_assert_nonnull (oio_url_get_id (u));
		g_assert_nonnull (oio_url_get (u, OIOURL_HEXID));
		g_assert_cmpstr (oio_url_get (u, OIOURL_HEXID), ==, td->hexa);
	} else {
		g_assert_false (oio_url_has (u, OIOURL_HEXID));
		g_assert_null (oio_url_get_id (u));
		g_assert_null (oio_url_get (u, OIOURL_HEXID));
	}
}

static struct oio_url_s *
_init_url (struct test_data_s *td)
{
	struct oio_url_s *url = oio_url_empty ();
	if (td->ns) oio_url_set (url, OIOURL_NS, td->ns);
	if (td->account) oio_url_set (url, OIOURL_ACCOUNT, td->account);
	if (td->ref) oio_url_set (url, OIOURL_USER, td->ref);
	if (td->path) oio_url_set (url, OIOURL_PATH, td->path);
	return url;
}

static void
test_configure_valid (void)
{
	static struct test_data_s tab[] = {
		{ "/NS/ACCT/JFS", "NS/ACCT/JFS/",
			"NS", "ACCT", "JFS", NULL,
			"9006CE70B59E5777D6BB410C57944812EB05FCDB5BA85D520A14B3051D1D094F"},

		{ "NS/ACCT/JFS//1.", "NS/ACCT/JFS//1.",
			"NS", "ACCT", "JFS", "1.",
			"9006CE70B59E5777D6BB410C57944812EB05FCDB5BA85D520A14B3051D1D094F"},

		{ "NS/ACCT/JFS//x x", "NS/ACCT/JFS//x%20x",
			"NS", "ACCT", "JFS", "x x",
			"9006CE70B59E5777D6BB410C57944812EB05FCDB5BA85D520A14B3051D1D094F"},

		{ "NS/ACCT/JFS//x%20x", "NS/ACCT/JFS//x%20x",
			"NS", "ACCT", "JFS", "x x",
			"9006CE70B59E5777D6BB410C57944812EB05FCDB5BA85D520A14B3051D1D094F"},

		/* if no ACCOUNT is set, no hexa ID can be computed */
		{ NULL, "NS", "NS", NULL, "JFS", NULL, NULL},
		{ NULL, "NS", "NS", NULL, "JFS", "x", NULL},

		/* if no USER is set, no hexa ID can be computed */
		{ NULL, "NS/ACCT", "NS", "ACCT", NULL, NULL, NULL},
		{ NULL, "NS/ACCT", "NS", "ACCT", NULL, "x", NULL},

		{ NULL, "NS/ACCT/JFS/",
			"NS", "ACCT", "JFS", NULL,
			"9006CE70B59E5777D6BB410C57944812EB05FCDB5BA85D520A14B3051D1D094F"},

		TEST_END
	};

	guint idx = 0;
	for (struct test_data_s *th=tab; th->url ;th++) {
		struct oio_url_s *url;

		if (th->url) {
			url = oio_url_init(th->url);
			g_assert_nonnull (url);
			g_assert_true(oio_url_check(url, th->ns, NULL));
			_test_url (idx++, url, th);
			oio_url_pclean (&url);
		}

		url = _init_url (th);
		g_assert_nonnull (url);
		g_assert_true(oio_url_check(url, th->ns, NULL));
		_test_url (idx++, url, th);
		oio_url_pclean (&url);
	}
}

static void
test_configure_invalid(void)
{
	struct oio_url_s *url;
	const gchar *err;
	g_assert_null (oio_url_init(""));
	g_assert_null (oio_url_init("/"));

	url = oio_url_init("badNS/ACCT/MB//thisisparta");
	g_assert_false(oio_url_check(url, "NS", &err));
	g_assert_cmpstr(err, ==, "'namespace'");
	oio_url_pclean (&url);

	url = oio_url_init("NS/ACCT/MB//thisisparta");
	g_assert_true(oio_url_check(url, "NS", &err));
	oio_url_set(url, OIOURL_VERSION, "aabbcc");
	g_assert_false(oio_url_check(url, "NS", &err));
	g_assert_cmpstr(err, ==, "'version', not a number");
	oio_url_pclean (&url);

	url = oio_url_init("NS/ACCT/Beno\xEEt//obj");
	g_assert_false(oio_url_check(url, "NS", &err));
	g_assert_cmpstr(err, ==, "'user', not UTF-8");
	oio_url_pclean (&url);

	url = oio_url_init("NS/ACCT/MB//\x33\x44\x55\x66\x77\x88");
	g_assert_false(oio_url_check(url, "NS", &err));
	g_assert_cmpstr(err, ==, "'path', not UTF-8");
	oio_url_pclean (&url);

	url = oio_url_init("NS/ACCT/MB//PATH");
	g_assert_true(oio_url_check(url, "NS", &err));
	oio_url_set(url, OIOURL_PATH, "\x33\x44\x55\x66\x77\x88");
	g_assert_false(oio_url_check(url, "NS", &err));
	g_assert_cmpstr(err, ==, "'path', not UTF-8");
	oio_url_pclean (&url);
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

/* Test the generation of chunk IDs depending on object name */
static void
test_chunk_id_generation(void)
{
	char buf[65] = {0};
	struct oio_url_s *url = oio_url_init("NS/ACCT/FVE/1/obj");
	const char expected_id[] =
			"9EA177B73CDE093ED3530DA1A06BA7DA1F038327FA5F2A56B5417140B8A616BD";
	const char expected_id_1[] =
			"A69598A38612D0B126EA0BD55A538362D454BAE6555F8348251A1C3D1F5EDF42";
	const char expected_id_2[] =
			"F67A7270D181449C6DDC547A4233AF29B6C9C2055DCBF9326322AB8C118C7942";

	g_assert_no_error(
			oio_url_compute_chunk_id(url, "0", "SINGLE", buf, sizeof(buf)));
	g_assert_cmpint(64, ==, strlen(buf));
	g_assert_cmpstr(expected_id, ==, buf);

	/* Short buffer */
	g_assert_no_error(
		oio_url_compute_chunk_id(url, "0", "SINGLE", buf, 33));
	g_assert_cmpint(32, ==, strlen(buf));
	g_assert_cmpstr("9EA177B73CDE093ED3530DA1A06BA7DA", ==, buf);

	/* Different position */
	g_assert_no_error(
		oio_url_compute_chunk_id(url, "1", "SINGLE", buf, 33));
	g_assert_cmpint(32, ==, strlen(buf));
	g_assert_cmpstr("9EA177B73CDE093ED3530DA1A06BA7DA", !=, buf);
	g_assert_no_error(
		oio_url_compute_chunk_id(url, "0.1", "SINGLE", buf, 33));
	g_assert_cmpint(32, ==, strlen(buf));
	g_assert_cmpstr("9EA177B73CDE093ED3530DA1A06BA7DA", !=, buf);
	g_assert_no_error(
		oio_url_compute_chunk_id(url, "11.11", "SINGLE", buf, 33));
	g_assert_cmpint(32, ==, strlen(buf));
	g_assert_cmpstr("9EA177B73CDE093ED3530DA1A06BA7DA", !=, buf);

	/* Different policy */
	g_assert_no_error(
		oio_url_compute_chunk_id(url, "0", "DUP", buf, 33));
	g_assert_cmpint(32, ==, strlen(buf));
	g_assert_cmpstr("9EA177B73CDE093ED3530DA1A06BA7DA", !=, buf);
	g_assert_no_error(
		oio_url_compute_chunk_id(url, "0", "THREECOPIES", buf, 33));
	g_assert_cmpint(32, ==, strlen(buf));
	g_assert_cmpstr("9EA177B73CDE093ED3530DA1A06BA7DA", !=, buf);

	/* Different version */
	oio_url_set(url, OIOURL_VERSION, "2");
	g_assert_no_error(
		oio_url_compute_chunk_id(url, "0", "SINGLE", buf, sizeof(buf)));
	g_assert_cmpint(64, ==, strlen(buf));
	g_assert_cmpstr(expected_id_1, ==, buf);

	oio_url_set(url, OIOURL_VERSION, "3");
	g_assert_no_error(
		oio_url_compute_chunk_id(url, "0", "SINGLE", buf, sizeof(buf)));
	g_assert_cmpint(64, ==, strlen(buf));
	g_assert_cmpstr(expected_id_2, ==, buf);

	oio_url_pclean (&url);
}

static void
test_chunk_id_generation_invalid_input(void)
{
	char buf[33] = {0};
	struct oio_url_s *url = NULL;
	GError *err = NULL;

	/* URL without object name */
	url = oio_url_init("NS/ACCT/FVE");
	err = oio_url_compute_chunk_id(url, "0", "SINGLE", buf, sizeof(buf));
	g_assert_error(err, GQ(), CODE_BAD_REQUEST);
	g_assert_nonnull(g_strstr_len(err->message, -1, "object alias"));
	g_clear_error(&err);
	oio_url_pclean(&url);

	/* No version */
	url = oio_url_init("NS/ACCT/FVE//obj");
	err = oio_url_compute_chunk_id(url, NULL, "SINGLE", buf, sizeof(buf));
	g_assert_error(err, GQ(), CODE_BAD_REQUEST);
	g_assert_nonnull(g_strstr_len(err->message, -1, "object version"));
	g_clear_error(&err);
	oio_url_pclean(&url);

	/* No position */
	url = oio_url_init("NS/ACCT/FVE/1/obj");
	err = oio_url_compute_chunk_id(url, NULL, "SINGLE", buf, sizeof(buf));
	g_assert_error(err, GQ(), CODE_BAD_REQUEST);
	g_assert_nonnull(g_strstr_len(err->message, -1, "chunk position"));
	g_clear_error(&err);

	/* No storage policy */
	err = oio_url_compute_chunk_id(url, "0", NULL, buf, sizeof(buf));
	g_assert_error(err, GQ(), CODE_BAD_REQUEST);
	g_assert_nonnull(g_strstr_len(err->message, -1, "storage policy"));
	g_clear_error(&err);
	oio_url_pclean(&url);

	/* Empty URL */
	url = oio_url_empty();
	err = oio_url_compute_chunk_id(url, "0", "SINGLE", buf, sizeof(buf));
	g_assert_error(err, GQ(), CODE_BAD_REQUEST);
	g_assert_nonnull(g_strstr_len(err->message, -1, "container ID"));
	g_clear_error(&err);
	oio_url_pclean(&url);
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/core/url/configure/valid", test_configure_valid);
	g_test_add_func("/core/url/configure/invalid", test_configure_invalid);
	g_test_add_func("/core/url/dup", test_dup);
	g_test_add_func("/core/url/chunkid/valid", test_chunk_id_generation);
	g_test_add_func("/core/url/chunkid/invalid",
			test_chunk_id_generation_invalid_input);
	return g_test_run();
}

