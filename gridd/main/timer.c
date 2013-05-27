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

#ifndef LOG_DOMAIN
#define LOG_DOMAIN "server.timer"
#endif

#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include <glib.h>

#include <metautils.h>

#include "./srvtimer.h"

static GStaticRWLock rw_lock = G_STATIC_RW_LOCK_INIT;

static GSList *timers_regular = NULL;

#define ST_NAMELEN 32

struct srvtimer_s
{
	guint64 ticks;
	guint64 freq;
	srvtimer_f fire;
	srvtimer_f close;
	gpointer u;
	char name[ST_NAMELEN];
};


/* ------------------------------------------------------------------------- */


gboolean
srvtimer_register_regular(const char *name, srvtimer_f fire, srvtimer_f close_cb, gpointer udata, guint64 freq)
{
	struct srvtimer_s *st;
	st = g_try_malloc0(sizeof(struct srvtimer_s));

	if (!name) {
		WARN("'name' parameter cannot be NULL");
		return FALSE;
	}

	st->fire = fire;
	st->close = close_cb;
	st->u = udata;
	st->freq = freq;
	st->ticks = 0;
	g_strlcpy(st->name, name, ST_NAMELEN);

	g_static_rw_lock_writer_lock(&rw_lock);
	timers_regular = g_slist_prepend(timers_regular, st);
	g_static_rw_lock_writer_unlock(&rw_lock);

	return TRUE;
}


void
srvtimer_init(void)
{
	INFO("timers initialization done");
}


void
srvtimer_fini(void)
{
	DEBUG("about to free the timers");

	void func_free(gpointer d, gpointer u)
	{
		(void) u;
		if (d) {
			TRACE("freeing timer '%s'", ((struct srvtimer_s *) d)->name);
			g_free(d);
		}
	}

	g_static_rw_lock_writer_lock(&rw_lock);
	g_slist_foreach(timers_regular, func_free, NULL);
	g_slist_free(timers_regular);
	timers_regular = NULL;
	g_static_rw_lock_writer_unlock(&rw_lock);

	INFO("timers freed");
}


void
srvtimer_fire(guint64 ticks)
{
	void timers_iterator(gpointer d, gpointer u)
	{
		struct srvtimer_s *st;

		(void) u;
		if (!d) {
			WARN("invalid parameter");
			return;
		}

		st = (struct srvtimer_s *) d;

		if (st->ticks <= ticks) {
			if (st->fire)
				st->fire(st->u);
			st->ticks = ticks + st->freq;
		}

	}

	DEBUG("Firing the timers...");
	g_static_rw_lock_reader_lock(&rw_lock);
	g_slist_foreach(timers_regular, timers_iterator, NULL);
	g_static_rw_lock_reader_unlock(&rw_lock);
	DEBUG("Timers fired");
}
