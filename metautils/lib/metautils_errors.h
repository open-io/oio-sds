/*
OpenIO SDS metautils
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

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

#ifndef OIO_SDS__metautils__lib__metautils_errors_h
# define OIO_SDS__metautils__lib__metautils_errors_h 1

#include <glib.h>

# define GSETCODE(e,C,FMT,...) g_error_trace (e, G_LOG_DOMAIN, (C), __LINE__, __FUNCTION__, __FILE__, FMT, ##__VA_ARGS__)
# define GSETERROR(e,FMT,...)  g_error_trace (e, G_LOG_DOMAIN, 0,   __LINE__, __FUNCTION__, __FILE__, FMT, ##__VA_ARGS__)
# define GSETRAW(e,CODE,MSG)  g_error_trace (e, G_LOG_DOMAIN, CODE, 0,0,0 , "%s", MSG)

/** Sets the error structure pointed by the first argument, keeping trace of the
 * previous content of this structure. */
void g_error_trace(GError ** e, const char *dom, int code,
		int line, const char *func, const char *file,
		const char *fmt, ...) __attribute__ ((format (printf, 7, 8)));

void g_error_transmit(GError **err, GError *e);

/** Returns the internal error code of <err> or 0 if <err> is NULL */
gint gerror_get_code(GError * err);

/** Returns the internal error message of <err> or NULL if <err> is NULL */
const gchar *gerror_get_message(GError * err);

#endif /*OIO_SDS__metautils__lib__metautils_errors_h*/
