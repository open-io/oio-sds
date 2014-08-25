#ifndef redcurrant__metautils_lib_test_addr_h
#define redcurrant__metautils_lib_test_addr_h 1

static gchar *bad_urls[] =
{
	"",
	"6000",
	":6000",
	"127.0.0.1",
	"127.0.0.1:6000:",
	" 127.0.0.1:6000",
	"127.0.0.1:6000 ",
	"127.0.0.1 :6000",
	"127.0.0.1: 6000",
	":127.0.0.1:6000:",
	":127.0.0.1:6000",
	"127.0.0.1::6000",
	"127.0.0.1:0",
	"0.0.0.0:0",
	"0.0.0.0:6000",
	"1|meta2|127.0.0.1:6000|",
	"1|meta2|127.0.0.1:6000",

	"::",
	"[:::0",
	"::]:6000",
	"::]:0",
	"[::]:6000",
	"[::] :6000",
	"[::] :6000",
	"[::]: 6000 ",
	" [::]: 6000",
	" [::]: 6000 ",
	" [::] : 6000 ",
	" [::]:6000 ",

	NULL
};

static gchar *good_urls[] =
{
	"127.0.0.1:6000",
	"[::1]:6000",

	NULL
};

static inline void
test_on_urlv(gchar **urlv, void (*test)(const gchar *))
{
	for (; *urlv ;++urlv)
		test(*urlv);
}

#define URL_ASSERT(C) do { \
	if (!BOOL(C)) \
		g_error("<%s> Failed with [%s]", pProc, url); \
} while (0)

#endif
