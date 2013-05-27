/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metautils.url"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <glib.h>

#include "./loggers.h"
#include "./hc_url.h"

static void
test_configure_valid(void)
{
	struct hc_url_s *url;

	/* plain URL */
	url = hc_url_init("hc://NS/REF/PATH");
	
	g_assert(url != NULL);
	g_assert(hc_url_has(url, HCURL_NS));
	g_assert(hc_url_has(url, HCURL_NSPHYS));
	g_assert(!hc_url_has(url, HCURL_NSVIRT));
	g_assert(hc_url_has(url, HCURL_REFERENCE));
	g_assert(hc_url_has(url, HCURL_PATH));
	
	g_assert(!strcmp("NS", hc_url_get(url, HCURL_NS)));
	g_assert(!strcmp("NS", hc_url_get(url, HCURL_NSPHYS)));
	g_assert(NULL == hc_url_get(url, HCURL_NSVIRT));
	g_assert(!strcmp("REF", hc_url_get(url, HCURL_REFERENCE)));
	g_assert(!strcmp("PATH", hc_url_get(url, HCURL_PATH)));
	hc_url_clean(url);

	/* partial URL */
	url = hc_url_init("hc://NS/REF");
	
	g_assert(url != NULL);
	g_assert(hc_url_has(url, HCURL_NS));
	g_assert(hc_url_has(url, HCURL_NSPHYS));
	g_assert(!hc_url_has(url, HCURL_NSVIRT));
	g_assert(hc_url_has(url, HCURL_REFERENCE));
	g_assert(!hc_url_has(url, HCURL_PATH));
	
	g_assert(!strcmp("NS", hc_url_get(url, HCURL_NS)));
	g_assert(!strcmp("NS", hc_url_get(url, HCURL_NSPHYS)));
	g_assert(NULL == hc_url_get(url, HCURL_NSVIRT));
	g_assert(!strcmp("REF", hc_url_get(url, HCURL_REFERENCE)));
	
	hc_url_clean(url);

	/* partial with trailing slashes */
	url = hc_url_init("hc:////NS///REF///");
	
	g_assert(url != NULL);
	g_assert(hc_url_has(url, HCURL_NS));
	g_assert(hc_url_has(url, HCURL_NSPHYS));
	g_assert(!hc_url_has(url, HCURL_NSVIRT));
	g_assert(hc_url_has(url, HCURL_REFERENCE));
	g_assert(!hc_url_has(url, HCURL_PATH));
	
	g_assert(!strcmp("NS", hc_url_get(url, HCURL_NS)));
	g_assert(!strcmp("NS", hc_url_get(url, HCURL_NSPHYS)));
	g_assert(NULL == hc_url_get(url, HCURL_NSVIRT));
	g_assert(!strcmp("REF", hc_url_get(url, HCURL_REFERENCE)));
	
	hc_url_clean(url);

	/* partial with trailing slashes */
	url = hc_url_init("hc:////NS///REF///PATH");
	
	g_assert(url != NULL);
	g_assert(hc_url_has(url, HCURL_NS));
	g_assert(hc_url_has(url, HCURL_NSPHYS));
	g_assert(!hc_url_has(url, HCURL_NSVIRT));
	g_assert(hc_url_has(url, HCURL_REFERENCE));
	g_assert(hc_url_has(url, HCURL_PATH));
	
	g_assert(!strcmp("NS", hc_url_get(url, HCURL_NS)));
	g_assert(!strcmp("NS", hc_url_get(url, HCURL_NSPHYS)));
	g_assert(NULL == hc_url_get(url, HCURL_NSVIRT));
	g_assert(!strcmp("REF", hc_url_get(url, HCURL_REFERENCE)));
	g_assert(!strcmp("PATH", hc_url_get(url, HCURL_PATH)));
	
	hc_url_clean(url);

}

static void
test_configure_invalid(void)
{
	struct hc_url_s *url;

	url = hc_url_init("");
	g_assert(url == NULL);
}

struct test_hash_s {
	const char *url;
	const char *hexa;
};

static struct test_hash_s hash_data[] = 
{
	{ "/NS/JFS",
		"C3F36084054557E6DBA6F001C41DAFBFEF50FCC83DB2B3F782AE414A07BB3A7A"},
	{NULL, NULL}
};

static void
test_hash(void)
{
	struct test_hash_s *th;

	for (th=hash_data; th->url ;th++) {
		struct hc_url_s *url;

		url = hc_url_init(th->url);
		g_assert(url != NULL);
		g_assert(NULL != hc_url_get_id(url));
		g_assert(!g_ascii_strcasecmp(hc_url_get(url, HCURL_HEXID), th->hexa));
		hc_url_clean(url);
	}
}

static void
test_hexid(void)
{
	struct test_hash_s *th;

	for (th=hash_data; th->url ;th++) {
		struct hc_url_s *url;

		url = hc_url_empty();
		g_assert(url != NULL);
		g_assert(NULL != hc_url_set(url, HCURL_NS, "NS"));
		g_assert(NULL != hc_url_set(url, HCURL_HEXID, th->hexa));
		hc_url_dump(url);
		g_assert(NULL != hc_url_get_id(url));
		g_assert(NULL != hc_url_get(url, HCURL_HEXID));
		g_assert(!g_ascii_strcasecmp(hc_url_get(url, HCURL_HEXID), th->hexa));
		hc_url_clean(url);
	}
}

int
main(int argc, char **argv)
{
	if (!g_thread_supported())
		g_thread_init(NULL);
	g_set_prgname(argv[0]);
	g_log_set_default_handler(logger_stderr, NULL);
	g_test_init (&argc, &argv, NULL);

	g_test_add_func("/metautils/hc_url/configure/valid",
			test_configure_valid);

	g_test_add_func("/metautils/hc_url/configure/invalid",
			test_configure_invalid);

	g_test_add_func("/metautils/hc_url/hexid", test_hexid);

	g_test_add_func("/metautils/hc_url/hash", test_hash);

	return g_test_run();
}

