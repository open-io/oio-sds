/*
OpenIO SDS core library
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

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

#include <glib.h>
#include <curl/curl.h>

#include "oio_core.h"
#include "oio_sds.h"

static const char *
_check_ns (const char *ns)
{
	static char errbuf[1024];
	const char *errmsg = NULL;
	struct curl_slist *headers = NULL;
	gchar *proxy = NULL, *url = NULL;
	CURL *h = NULL;
	int rc;

	if (!(proxy = oio_cfg_get_proxy_conscience (ns))) {
		errmsg = "no proxy configured";
		goto out;
	}

	if (!(url = g_strdup_printf ("http://%s/"PROXYD_PREFIX"/cs/%s", proxy, ns))) {
		errmsg = "memory allocation failure";
		goto out;
	}

	/* XXX JFS: the proxy has a simplistic HTTP management and doesn't honor Expect */
	headers = curl_slist_append (headers, "Expect: ");
	headers = curl_slist_append (headers, "Connection: close");

	if (!(h = curl_easy_init ())) {
		errmsg = "CURL init failure";
		goto out;
	}

	curl_easy_setopt (h, CURLOPT_USERAGENT, "OpenIO-SDS/SDK-2.0/test");
	curl_easy_setopt (h, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt (h, CURLOPT_CUSTOMREQUEST, "HEAD");
	curl_easy_setopt (h, CURLOPT_URL, url);
	curl_easy_setopt (h, CURLOPT_HTTPHEADER, headers);
	if (CURLE_OK != (rc = curl_easy_perform (h))) {
		errmsg = curl_easy_strerror (rc);
		goto out;
	}
	long code = 0;
	if (CURLE_OK != (rc = curl_easy_getinfo (h, CURLINFO_RESPONSE_CODE, &code))) {
		errmsg = curl_easy_strerror (rc);
		goto out;
	}
	if ((code/100) != 2) {
		g_snprintf (errbuf, sizeof(errbuf), "HTTP status %ld", code);
		errmsg = errbuf;
		goto out;
	}

out:
	if (h) curl_easy_cleanup (h);
	if (headers) curl_slist_free_all (headers);
	if (proxy) g_free (proxy);
	if (url) g_free (url);
	return errmsg;
}

static int
_check_ns_and_print (const char *ns)
{
	const char *errmsg = _check_ns (ns);
	if (errmsg) {
		g_print ("%s error: %s\n", ns, errmsg);
		return 0;
	} else {
		g_print ("%s OK\n", ns);
		return ~0;
	}
}

int
main (int argc, char **argv)
{
	if (argc < 2) {
		g_printerr ("Usage: %s -a\n", argv[0]);
		g_printerr ("Usage: %s NS [NS...]\n", argv[0]);
		return 1;
	}

	int ok = ~0;
	if (argc == 2 && !strcmp(argv[1], "-a")) {
		gchar **tab_ns = oio_cfg_list_ns ();
		for (gchar **p=tab_ns; p && *p ;++p)
			ok &= _check_ns_and_print (*p);
		g_strfreev (tab_ns);
	} else {
		for (int i=1; i<argc ;i++)
			ok &= _check_ns_and_print (argv[i]);
	}

	return ok ? 0 : 2;
}


