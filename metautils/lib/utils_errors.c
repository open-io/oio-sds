#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metautils"
#endif

#include "metautils_errors.h"

void
g_error_prefix_place(GError **e, const gchar *file, const gchar *func,
		int line)
{
	(void) file;
	gchar *tag = g_strdup_printf("(code=%d) [%s:%d]\n\t", (*e)->code, func, line);
	g_prefix_error(e, tag);
	g_free(tag);
}

void
g_error_trace(GError ** e, const char *dom, int code,
		int line, const char *func, const char *file,
		const char *fmt, ...)
{
	GString *gstr;
	va_list localVA;

	if (!e)
		return;

	gstr = g_string_new("");

	if (line && func && file)
		g_string_printf(gstr, "(code=%i) [%s:%d] ", (code?code:(*e?(*e)->code:0)), func, line);

	va_start(localVA, fmt);
	g_string_append_vprintf(gstr, fmt, localVA);
	va_end(localVA);

	if (!*e)
		*e = g_error_new(g_quark_from_static_string(dom), code, gstr->str);
	else {
		g_string_append(gstr, "\n\t");
		g_prefix_error(e, gstr->str);
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
		}
		else {
			GSETMARK(err);
			GSETRAW(err, e->code, e->message);
			g_clear_error(&e);
		}
	}
	else {
		g_clear_error(&e);
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

