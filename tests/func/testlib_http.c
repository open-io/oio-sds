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

#include <stdarg.h>

#include <core/oiolog.h>
#include <core/oio_sds.h>
#include <core/http_put.h>

void setup (void);
void test_upload_ok (int errors, int size, ...);

/* -------------------------------------------------------------------------- */

void
setup (void)
{
	oio_log_to_stderr();
	for (int i=0; i<5 ;i++)
		oio_log_more ();
}

void
test_upload_ok (int errors, int size, ...)
{
	GRID_DEBUG("++++++++++++++++ %s errors %d size %d", __FUNCTION__, errors, size);

	GError *err = NULL;
	gint64 content_length = size;
	struct http_put_s *p = http_put_create (NULL, NULL, content_length);
	g_assert (p != NULL);

	GSList *dests = NULL;
	va_list args;
	va_start(args, size);
	for (guint i=1; ;++i) {
		struct http_put_dest_s *d;
		char *k = va_arg(args, char *);
		if (!k) break;
		d = http_put_add_dest (p, k, GINT_TO_POINTER(i));
		dests = g_slist_prepend (dests, d);
	}
	va_end(args);

	if (size < 0)
		size = 128;
	int fed = 0;
	while (!http_put_done(p)) {
		if (fed < size) {
			http_put_feed (p, g_bytes_new((guint8*)"00000000", 8));
			fed += 8;
		} else {
			http_put_feed (p, g_bytes_new((guint8*)"", 0));
		}
		err = http_put_step (p);
		g_assert_no_error (err);
		err = http_put_step (p);
		g_assert_no_error (err);
	}

	g_slist_free (dests);

	int count_errors = http_put_get_failure_number (p);
	g_assert (count_errors == errors);

	http_put_destroy (p);
}

