/*
OpenIO SDS core library
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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>

#include <glib.h>

#include "oiolog.h"
#include "oioext.h"

int oio_log_level_default = 0x7F;

int oio_log_level = 0x7F;

int oio_log_flags = LOG_FLAG_TRIM_DOMAIN
		| LOG_FLAG_PURIFY | LOG_FLAG_COLUMNIZE;

guint16
oio_log_thread_id(GThread *thread)
{
	union {
		void *p;
		guint16 u[4];
	} bulk;
	bulk.u[0] = bulk.u[1] = bulk.u[2] = bulk.u[3] = 0;
	bulk.p = thread;
	return (bulk.u[0] ^ bulk.u[1]) ^ (bulk.u[2] ^ bulk.u[3]);
}

guint16
oio_log_current_thread_id(void)
{
	return oio_log_thread_id(g_thread_self());
}

static const gchar*
glvl_to_str(GLogLevelFlags lvl)
{
	switch (lvl & G_LOG_LEVEL_MASK) {
		case G_LOG_LEVEL_ERROR:
			return "ERR";
		case G_LOG_LEVEL_CRITICAL:
			return "CRI";
		case G_LOG_LEVEL_WARNING:
			return "WRN";
		case G_LOG_LEVEL_MESSAGE:
			return "NOT";
		case G_LOG_LEVEL_INFO:
			return "INF";
		case G_LOG_LEVEL_DEBUG:
			return "DBG";
	}

	switch (lvl >> G_LOG_LEVEL_USER_SHIFT) {
		case 0:
		case 1:
			return "ERR";
		case 2:
			return "WRN";
		case 4:
			return "NOT";
		case 8:
			return "INF";
		case 16:
			return "DBG";
		case 32:
			return "TR0";
		default:
			return "TR1";
	}
}

static int
glvl_to_lvl(GLogLevelFlags lvl)
{
	switch (lvl & G_LOG_LEVEL_MASK) {
		case G_LOG_LEVEL_ERROR:
			return LOG_ERR;
		case G_LOG_LEVEL_CRITICAL:
			return LOG_ERR;
		case G_LOG_LEVEL_WARNING:
			return LOG_WARNING;
		case G_LOG_LEVEL_MESSAGE:
			return LOG_NOTICE;
		case G_LOG_LEVEL_INFO:
		case G_LOG_LEVEL_DEBUG:
			return LOG_INFO;
		default:
			break;
	}

	switch (lvl >> G_LOG_LEVEL_USER_SHIFT) {
		case 0:
		case 1:
			return LOG_ERR;
		case 2:
			return LOG_WARNING;
		case 4:
			return LOG_NOTICE;
		case 8:
			return LOG_INFO;
		default:
			return LOG_DEBUG;
	}
}

static int
get_facility(const gchar *dom)
{
	return (dom && *dom == 'a' && !strcmp(dom, "access")) ? LOG_LOCAL1 : 0;
}

#define REAL_LEVEL(L)   (guint32)((L) >> G_LOG_LEVEL_USER_SHIFT)
#define ALLOWED_LEVEL() REAL_LEVEL(oio_log_level)

static gboolean
glvl_allowed(register GLogLevelFlags lvl)
{
	return (lvl & 0x7F)
		|| (ALLOWED_LEVEL() >= REAL_LEVEL(lvl));
}

static void
_purify(register gchar *s)
{
	static guint8 invalid[256] = {0};
	if (!invalid[0]) {
		for (int i=0; i<256 ;i++)
			invalid[i] = g_ascii_isspace(i) || !g_ascii_isprint(i);
	}

	for (gchar c; (c=*s) ; s++) {
		if (invalid[(guint8)c])
			*s = ' ';
	}
	*(s-1) = '\n';
}

static void
_append_message(GString *gstr, const gchar *msg)
{
	if (!msg)
		return;

	// skip leading blanks
	for (; *msg && g_ascii_isspace(*msg) ;msg++) {}

	g_string_append(gstr, msg);
}

void
oio_log_noop(const gchar *log_domain, GLogLevelFlags log_level,
		const gchar *message, gpointer user_data)
{
	(void) log_domain;
	(void) log_level;
	(void) message;
	(void) user_data;
}

void
oio_log_syslog(const gchar *log_domain, GLogLevelFlags log_level,
		const gchar *message, gpointer user_data)
{
	(void) user_data;

	if (!glvl_allowed(log_level))
		return;

	GString *gstr = g_string_new("");

	g_string_append_printf(gstr, "%d %04X", getpid(), oio_log_current_thread_id());

	if (LOG_LOCAL1 == get_facility(log_domain)) {
		g_string_append(gstr, " access ");
		g_string_append(gstr, glvl_to_str(log_level));
	}
	else {
		if (!log_domain || !*log_domain)
			log_domain = "-";
		g_string_append(gstr, " log ");
		g_string_append(gstr, glvl_to_str(log_level));
		g_string_append_c(gstr, ' ');
		g_string_append(gstr, log_domain);
	}

	g_string_append_c(gstr, ' ');

	_append_message(gstr, message);

	syslog(get_facility(log_domain)|glvl_to_lvl(log_level), "%s", gstr->str);
	g_string_free(gstr, TRUE);
}

static void
_logger_stderr(const gchar *log_domain, GLogLevelFlags log_level,
		const gchar *message, gpointer user_data)
{
	static guint longest_prefix = 38;
	GString *gstr = g_string_sized_new(256);
	(void) user_data;

	g_string_append_printf(gstr, "%"G_GINT64_FORMAT" %d %04X ",
			g_get_monotonic_time () / G_TIME_SPAN_MILLISECOND,
			getpid(), oio_log_current_thread_id());

	if (!log_domain || !*log_domain)
		log_domain = "-";

	if (LOG_LOCAL1 == get_facility(log_domain)) {
		g_string_append_printf(gstr, "acc %s ", glvl_to_str(log_level));
	} else {
		g_string_append_printf(gstr, "log %s ", glvl_to_str(log_level));

		/* print the domain */
		if (!(oio_log_flags & LOG_FLAG_TRIM_DOMAIN))
			g_string_append(gstr, log_domain);
		else {
			const gchar *p = log_domain;
			while (p && *p) {
				g_string_append_c(gstr, *p);
				p = strchr(p, '.');
				if (p) {
					g_string_append_c(gstr, '.');
					p ++;
				}
			}
		}
	}

	/* prefix done, print a separator */
	if (oio_log_flags & LOG_FLAG_COLUMNIZE) {
		longest_prefix = MAX(gstr->len+1,longest_prefix);
		do {
			g_string_append_c(gstr, ' ');
		} while (gstr->len < longest_prefix);
	}
	else
		g_string_append_c(gstr, ' ');

	/* now append the message */
	_append_message(gstr, message);
	g_string_append_c(gstr, '\n');

	if (oio_log_flags & LOG_FLAG_PURIFY)
		_purify(gstr->str);

	/* send the buffer */
	fwrite(gstr->str, gstr->len, 1, stderr);
	g_string_free(gstr, TRUE);
}

void
oio_log_stderr(const gchar *log_domain, GLogLevelFlags log_level,
		const gchar *message, gpointer user_data)
{
	if (!glvl_allowed(log_level))
		return;
	_logger_stderr(log_domain, log_level, message, user_data);
}

void
oio_log_verbose(void)
{
	oio_log_level = (oio_log_level*2)+1;
}

void
oio_log_verbose_default(void)
{
	oio_log_level_default = (oio_log_level_default * 2) + 1;
	oio_log_level = oio_log_level_default;
}

void
oio_log_init_level(int l)
{
	oio_log_level_default = oio_log_level = (l?(l|0x7F):0);
}

void
oio_log_init_level_from_env(const gchar *k)
{
	const gchar *v = g_getenv(k);
	if (v) {
		switch (g_ascii_toupper(*v)) {
			case 'T':
				oio_log_init_level(GRID_LOGLVL_TRACE2);
				return;
			case 'D':
				oio_log_init_level(GRID_LOGLVL_DEBUG);
				return;
			case 'I':
				oio_log_init_level(GRID_LOGLVL_INFO);
				return;
			case 'N':
				oio_log_init_level(GRID_LOGLVL_NOTICE);
				return;
			case 'W':
				oio_log_init_level(GRID_LOGLVL_WARN);
				return;
			case 'E':
				oio_log_init_level(GRID_LOGLVL_ERROR);
				return;
		}
	}
}

void
oio_log_reset_level(void)
{
	oio_log_level = oio_log_level_default;
}

void
oio_log_quiet(void)
{
	oio_log_init_level(0);
}

void
oio_log_lazy_init (void)
{
	static volatile guint lazy_init = 1;
	if (lazy_init) {
		if (g_atomic_int_compare_and_exchange(&lazy_init, 1, 0)) {
			g_log_set_default_handler(oio_log_noop, NULL);
			oio_log_init_level(GRID_LOGLVL_ERROR);
		}
	}
}

