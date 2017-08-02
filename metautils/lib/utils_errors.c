/*
OpenIO SDS metautils
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

#include "metautils_errors.h"

void
g_error_trace(GError ** e, const char *dom, int code,
		int line, const char *func, const char *file,
		const char *fmt, ...)
{
	(void) line, (void) func, (void) file;
	if (!e)
		return;

	GString *gstr = g_string_sized_new(128);
#ifdef HAVE_EXTRA_DEBUG
	if (line && func && file)
		g_string_printf(gstr, "(code=%i) %s,%d ", (code?code:(*e?(*e)->code:0)), func, line);
	else
#endif
		g_string_printf(gstr, "(code=%i) - ", (code?code:(*e?(*e)->code:0)));

	va_list localVA;
	va_start(localVA, fmt);
	g_string_append_vprintf(gstr, fmt, localVA);
	va_end(localVA);

	if (!*e)
		*e = g_error_new(g_quark_from_static_string(dom), code, "%s", gstr->str);
	else {
		g_string_append_c(gstr, ' ');
		g_prefix_error(e, "%s", gstr->str);
		if (code)
			(*e)->code = code;
	}

	g_string_free(gstr, TRUE);
}

void
g_error_transmit(GError **err, GError *e)
{
	if (err) {
		if (!*err) {
			g_propagate_error(err, e);
		} else {
			GSETRAW(err, e->code, e->message);
			g_error_free(e);
		}
	} else {
		g_error_free(e);
	}
}

gint
gerror_get_code(GError * err)
{
	return err ? err->code : 0;
}

const gchar *
gerror_get_message(GError * err)
{
	if (!err)
		return "no error";
	if (!err->message)
		return "no error message";
	return err->message;
}

