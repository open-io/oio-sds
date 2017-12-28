/*
OpenIO SDS core library
Copyright (C) 2017-2018 OpenIO SAS, as part of OpenIO SDS

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

#include <errno.h>

#include <curl/curl.h>
#include <curl/curlver.h>

#include <metautils/lib/metautils.h>

#include "http_del.h"
#include "http_internals.h"

static GError *
_chunks_removal_step(CURLM *mhandle, gboolean *next)
{
	fd_set fdread, fdwrite, fdexcep;
	int maxfd = -1;

	*next = FALSE;

	/* Prepare the select() call */
	FD_ZERO(&fdread);
	FD_ZERO(&fdwrite);
	FD_ZERO(&fdexcep);
	curl_multi_fdset(mhandle, &fdread, &fdwrite, &fdexcep, &maxfd);
	GRID_WARN("maxfd %d", maxfd);
	if (maxfd < 0) {
		GRID_TRACE("No pending I/O");
	} else {
		long timeout = 0;
		curl_multi_timeout (mhandle, &timeout);
		struct timeval tv = {};
		tv.tv_sec = timeout / 1000;
		tv.tv_usec = (timeout % 1000) * 1000;

		/* Wait for events to happen */
		int rc = select(maxfd+1, &fdread, &fdwrite, &fdexcep, &tv);
		if (rc < 0 && errno != EINTR && errno != EAGAIN)
			return SYSERR("select() error: (%d) %s", errno, strerror(errno));
	}

	int nb = 0;
	curl_multi_perform(mhandle, &nb);

	/* run those pool of operations */
	for (;;) {
		int msgs_left = 0;
		CURLMsg *msg = curl_multi_info_read(mhandle, &msgs_left);
		if (!msg && !msgs_left)
			break;
		if (msg->msg != CURLMSG_DONE) {
			GRID_TRACE("Unexpected CURL event");
		} else {
			long http_ret = 0;
			gchar *url = NULL;
			CURLcode curl_ret = msg->data.result;
			CURL *handle = msg->easy_handle;
			g_assert_nonnull(handle);
			curl_easy_getinfo(handle, CURLINFO_PRIVATE, &url);
			g_assert_nonnull(url);
			curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &http_ret);

			if (curl_ret != CURLE_OK) {
				GRID_WARN("curl error code=%u strerror=%s",
						curl_ret, curl_easy_strerror(curl_ret));
			}

			if (http_ret / 100 == 2) {
				GRID_DEBUG("Deleted [%s] code=%ld strerror=%s",
						url, http_ret, curl_easy_strerror(curl_ret));
			} else {
				GRID_WARN("Delete error [%s] code=%ld strerror=%s",
						url, http_ret, curl_easy_strerror(curl_ret));
			}

			const CURLMcode mrc =
				curl_multi_remove_handle(mhandle, handle);
			g_assert_cmpint(mrc, ==, CURLM_OK);
		}
	}

	*next = (nb != 0);
	return NULL;
}

GError *
http_poly_delete (gchar **urlv)
{
	CURLM *mhandle = curl_multi_init();
	if (!mhandle)
		return SYSERR("CURL multi allocation error");

	GSList *handles = NULL;

	/* Prepare the multiplexed curl operations */
	for (gchar **purl=urlv; urlv && *purl ;++purl) {
		CURL *handle = _curl_get_handle_blob();
		curl_easy_setopt(handle, CURLOPT_CUSTOMREQUEST, "DELETE");
		curl_easy_setopt(handle, CURLOPT_URL, *purl);
		curl_easy_setopt(handle, CURLOPT_PRIVATE, *purl);
		const CURLMcode rc = curl_multi_add_handle(mhandle, handle);
		g_assert_cmpint(rc, ==, CURLM_OK);

		handles = g_slist_prepend(handles, handle);
	}

	/* Loop until there is no pending call */
	for (gboolean next=TRUE; next; ) {
		GError *err = _chunks_removal_step(mhandle, &next);
		if (err) {
			GRID_WARN("CURL error while removing chunks: (%d) %s",
					err->code, err->message);
			break;
		}
	}

	curl_multi_cleanup(mhandle);

	for (GSList *l=handles; l ;l=l->next)
		curl_easy_cleanup(l->data);
	g_slist_free(handles);

	return NULL;
}
