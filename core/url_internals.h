/*
OpenIO SDS core library
Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021 OVH SAS

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

#ifndef OIO_SDS__metautils__lib__oio_url_internals_h
# define OIO_SDS__metautils__lib__oio_url_internals_h 1

#include <core/oiourl.h>

struct oio_url_s
{
	/* primary */
	gchar ns[LIMIT_LENGTH_NSNAME];
	gchar account[LIMIT_LENGTH_ACCOUNTNAME];
	gchar user[LIMIT_LENGTH_USER];
	gchar version[LIMIT_LENGTH_VERSION];

	gchar *path;
	gchar *content;

	/* secondary */
	gchar *whole;
	gchar *fullpath;
	guint8 id[32];
	gchar hexid[65];
	gchar root_hexid[65];
	guint8 flags;
};

#endif /*OIO_SDS__metautils__lib__oio_url_internals_h*/
