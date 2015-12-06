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

#ifndef OIO_SDS__metautils__lib__test_addr_h
# define OIO_SDS__metautils__lib__test_addr_h 1

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

#endif /*OIO_SDS__metautils__lib__test_addr_h*/