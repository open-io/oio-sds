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

#include <metautils/lib/metautils.h>

static void
test_transform(gchar* (*T) (const gchar*), const gchar *s0, const gchar *sN)
{
	gchar *s = T(s0);
	g_assert(0 == g_strcmp0(sN,s));
	g_free(s);
}

static void
test_via_gba(void)
{
	const char *src = "255.255.255.255:6789";
	GByteArray *gba = metautils_gba_from_string(src);
	gchar *copy = g_strndup((gchar*)gba->data, gba->len);
	g_assert_cmpstr(src, ==, copy);
	g_free(copy);
	g_byte_array_free(gba, TRUE);
}

static void
test_via_message(void)
{
	const char *src = "255.255.255.255:6789";
	MESSAGE msg = metautils_message_create_named("plop", 0);
	metautils_message_add_body_unref(msg, metautils_gba_from_string(src));
	gchar *copy = NULL;
	GError *err = metautils_message_extract_body_string(msg, &copy);
	g_assert_no_error(err);
	g_assert_cmpstr(src, ==, copy);
	g_free(copy);
	metautils_message_destroy(msg);
}

/* ------------------------------------------------------------------------- */

static void
test_reuse (void)
{
	gchar *s0 = g_strdup ("A"), *s1 = g_strdup ("B");
	oio_str_reuse (&s0, s1);
	g_assert (s0 == s1);

	oio_str_clean (&s1);
	g_assert (s1 == NULL);
}

static void
test_replace (void)
{
	gchar *s0 = g_strdup ("A");
	oio_str_replace (&s0, "B");
	g_assert (!strcmp(s0, "B"));

	oio_str_clean (&s0);
	g_assert (s0 == NULL);
}

static void
test_is_hexa (void)
{
	/* test the length */
	g_assert (!oio_str_ishexa1 (""));
	g_assert (!oio_str_ishexa1 ("A"));
	g_assert ( oio_str_ishexa1 ("AA"));
	g_assert (!oio_str_ishexa1 ("AAA"));

	/* test invalid characters */
	g_assert (!oio_str_ishexa1 ("AG"));
	g_assert (!oio_str_ishexa1 ("0xAA"));

	g_assert (!oio_str_ishexa ("", 0));
	g_assert (!oio_str_ishexa ("A", 1));
	g_assert ( oio_str_ishexa ("AA", 2));
}

static void
test_bin (void)
{
	guint8 buf[64];
	gchar str[129];

	g_assert_false (oio_str_hex2bin ("0", buf, sizeof(buf)));
	g_assert_false (oio_str_hex2bin ("x", buf, sizeof(buf)));

	g_assert_false (oio_str_hex2bin ("0x", buf, sizeof(buf)));

	g_assert_true  (oio_str_hex2bin ("00", buf, 1));
	g_assert_false (oio_str_hex2bin ("0000", buf, 1));

	g_assert_true (oio_str_hex2bin ("00", buf, sizeof(buf)));
	g_assert_true (buf[0] == 0);
	g_assert (2 == oio_str_bin2hex (buf, 1, str, sizeof(str)));
	g_assert (!g_ascii_strcasecmp(str, "00"));
}

static void
test_autocontainer (void)
{
	guint64 nb0 = 0, nb8 = 0;
	for (unsigned int i0=0; i0<256 ;i0++) {
		for (unsigned int i1=0; i1<256 ;i1++) {
			for (unsigned int i2=0; i2<256 ;i2++) {
				guint8 bin[] = {i0, i1, i2, 0, 0};
				gchar dst[65];

				const char *s = oio_buf_prefix (bin, sizeof(bin), dst, 17);
				g_assert (s != NULL);
				gchar last = s[strlen(s)-1];
				g_assert (last == '0' || last == '8');
				if (last == '0') ++nb0; else ++nb8;
			}
		}
	}
	g_assert (nb0 == nb8);
}

static void
test_clean(void)
{
	gchar *s0 = g_strdup("");
	oio_str_clean(&s0);
	g_assert(NULL == s0);
}

static void
test_upper(void)
{
	gchar * _trans(const gchar *s0) {
		gchar *s = g_strdup(s0);
		metautils_str_upper(s);
		return s;
	}
	test_transform(_trans, "", "");
	test_transform(_trans, "a", "A");
	test_transform(_trans, "A", "A");
	test_transform(_trans, "Aa", "AA");
}

static void
test_lower(void)
{
	gchar * _trans(const gchar *s0) {
		gchar *s = g_strdup(s0);
		metautils_str_lower(s);
		return s;
	}
	test_transform(_trans, "", "");
	test_transform(_trans, "a", "a");
	test_transform(_trans, "A", "a");
	test_transform(_trans, "Aa", "aa");
}

static void
test_prefix (void)
{
	g_assert (oio_str_caseprefixed("X", "X"));
	g_assert (oio_str_caseprefixed("X", "x"));
	g_assert (oio_str_caseprefixed("Xa", "X"));
	g_assert (oio_str_caseprefixed("Xa", "x"));

	g_assert (!oio_str_caseprefixed("X", "Y"));
	g_assert (!oio_str_caseprefixed("X", "y"));
	g_assert (!oio_str_caseprefixed("Xa", "Y"));
	g_assert (!oio_str_caseprefixed("Xa", "y"));

	g_assert (!oio_str_caseprefixed("X", "Xa"));
}

#define test_V_cycle(Kind,Input,Expected) do { \
	GString *encoded = Kind##_encode_gstr(Input); \
	g_assert_nonnull (encoded); \
	gchar **output = NULL; \
	GError *err = Kind##_decode_buffer ((guint8*)encoded->str, encoded->len, &output); \
	g_string_free(encoded, TRUE); \
	g_assert((err != NULL) ^ (output != NULL)); \
	g_assert_no_error(err); \
	g_assert_cmpuint(g_strv_length(Expected), ==, g_strv_length(output)); \
	for (guint i=0,max=g_strv_length(Expected); i<max ; i++) \
		g_assert_cmpstr(Expected[i], ==, output[i]); \
	g_strfreev(output); \
} while (0)

static void
test_STRV_cycle (gchar **input, gchar **expected)
{
	test_V_cycle(STRV, input, expected);
}

static void
test_KV_cycle (gchar **input, gchar **expected)
{
	test_V_cycle(KV, input, expected);
}

static void
test_STRV_ok (void)
{
	gchar *input[] = {"A", "B", "C", NULL}, *output[] = {"A", "B", "C", NULL};
	for (gint i=3; i>=0 ;i--) {
		input[i] = output[i] = NULL;
		test_STRV_cycle(input, output);
	}
}

static void
test_KV_ok (void)
{
	gchar *input[] = {"A", "B", "C", NULL}, *output[] = {"A", "B", "C", NULL};
	for (gint i=3; i>=0 ;i--) {
		input[i] = output[i - (i%2)] = NULL;
		test_KV_cycle(input, output);
	}
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);

	g_test_add_func("/core/str/reuse", test_reuse);
	g_test_add_func("/core/str/replace", test_replace);
	g_test_add_func("/core/str/ishexa", test_is_hexa);
	g_test_add_func("/core/str/bin", test_bin);
	g_test_add_func("/core/str/kv", test_KV_ok);
	g_test_add_func("/core/str/strv", test_STRV_ok);
	g_test_add_func("/core/str/autocontainer", test_autocontainer);

	g_test_add_func("/metautils/str/gba", test_via_gba);
	g_test_add_func("/metautils/str/message", test_via_message);
	g_test_add_func("/metautils/str/clean", test_clean);
	g_test_add_func("/metautils/str/upper", test_upper);
	g_test_add_func("/metautils/str/lower", test_lower);
	g_test_add_func("/metautils/str/prefix", test_prefix);

	return g_test_run();
}

