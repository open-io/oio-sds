#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "str.test"
#endif

#include "./metautils.h"

static void
test_transform(gchar* (*T) (const gchar*), const gchar *s0, const gchar *sN)
{
	gchar *s = T(s0);
	g_assert(0 == g_strcmp0(sN,s));
	g_free(s);
}

/* ------------------------------------------------------------------------- */

static void
test_reuse(void)
{
	gchar *s0 = g_strdup("");
	gchar *s1 = g_strdup("");
	metautils_str_reuse(&s0, s1);
	g_assert(s0 == s1);
	g_free(s1);
}

static void
test_replace(void)
{
	gchar *s0 = g_strdup("");
	gchar *s1 = g_strdup("");
	metautils_str_replace(&s0, s1);
	g_assert(0 == g_strcmp0(s0, s1));
	g_free(s0);
	g_free(s1);
}

static void
test_clean(void)
{
	gchar *s0 = g_strdup("");
	metautils_str_clean(&s0);
	g_assert(NULL == s0);
}

static void
test_strlcpy_pns(void)
{
	gchar * _trans(const gchar *s0) {
		gchar *s = g_strdup(s0);
		metautils_strlcpy_physical_ns(s, s0, strlen(s0)+1);
		return s;
	}
	test_transform(_trans, "", "");
	test_transform(_trans, "....", "");
	test_transform(_trans, "N", "N");
	test_transform(_trans, "N.P", "N");
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
test_lstrip(void)
{
	gchar * _trans(const gchar *s0) {
		return g_strdup(metautils_lstrip(s0,'@'));
	}
	test_transform(_trans, "", "");
	test_transform(_trans, "@", "");
	test_transform(_trans, "A@", "A@");
	test_transform(_trans, "@A", "A");
}

static void
test_rstrip(void)
{
	gchar * _trans(const gchar *s0) {
		gchar *s = g_strdup(s0);
		metautils_rstrip(s,'@');
		return s;
	}
	test_transform(_trans, "", "");
	test_transform(_trans, "@", "");
	test_transform(_trans, "A@", "A");
	test_transform(_trans, "@A", "@A");
}

static void
test_ishexa(void)
{
	// not hexa
	g_assert(!metautils_str_ishexa("g",1));
	// wrong size
	g_assert(!metautils_str_ishexa("g",0));
	g_assert(!metautils_str_ishexa("0",0));
	g_assert(metautils_str_ishexa("0",1));
	g_assert(metautils_str_ishexa("",0));
	// validate hexa chars
	g_assert(metautils_str_ishexa("0123456789ABCDEFabcdef",22));
}

static void
test_strlen_len(void)
{
	gsize len(const gchar *s, gsize l) {
		return strlen_len((guint8*)s, l);
	}
	g_assert(len("plop", strlen("plop")) == strlen("plop"));
	for (guint i=0; i < sizeof("plopplop")+1; ++i)
		g_assert(len("plopplop", i) == MIN(i,sizeof("plopplop")-1));
}

static void
test_hex2bin(void)
{
	gboolean check(const guint8 *s, gsize slen, const gchar *t0) {
		gsize tlen = 2 + (slen * 2);
		gchar *t = g_malloc0(tlen);
		buffer2str(s, slen, t, tlen);
		return 0 == g_strcmp0(t, t0);
	}
	#define CHECK(B,T) check((guint8*)(B),sizeof(B)-1,(T))
	g_assert(CHECK("\x01\x10","0110"));
}

int
main(int argc, char **argv)
{
	HC_PROC_INIT(argv, GRID_LOGLVL_TRACE2);
	g_test_init (&argc, &argv, NULL);
	g_test_add_func("/metautils/str/reuse", test_reuse);
	g_test_add_func("/metautils/str/replace", test_replace);
	g_test_add_func("/metautils/str/clean", test_clean);
	g_test_add_func("/metautils/str/strlcpy_pns", test_strlcpy_pns);
	g_test_add_func("/metautils/str/upper", test_upper);
	g_test_add_func("/metautils/str/lower", test_lower);
	g_test_add_func("/metautils/str/lstrip", test_lstrip);
	g_test_add_func("/metautils/str/rstrip", test_rstrip);
	g_test_add_func("/metautils/str/ishexa", test_ishexa);
	g_test_add_func("/metautils/str/strlen", test_strlen_len);
	g_test_add_func("/metautils/str/hex2bin", test_hex2bin);
	return g_test_run();
}

