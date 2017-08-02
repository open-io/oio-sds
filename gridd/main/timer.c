/*
OpenIO SDS gridd
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include <metautils/lib/metautils.h>

#include "./srvtimer.h"

static GRWLock rw_lock;

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

void
srvtimer_register_regular(const char *name, srvtimer_f fire, srvtimer_f close_cb, gpointer udata, guint64 freq)
{
	EXTRA_ASSERT(name != NULL);
	struct srvtimer_s *st = g_malloc0(sizeof(struct srvtimer_s));
	st->fire = fire;
	st->close = close_cb;
	st->u = udata;
	st->freq = freq;
	st->ticks = 0;
	g_strlcpy(st->name, name, ST_NAMELEN);

	g_rw_lock_writer_lock(&rw_lock);
	timers_regular = g_slist_prepend(timers_regular, st);
	g_rw_lock_writer_unlock(&rw_lock);
}

void
srvtimer_init(void)
{
	GRID_INFO("timers initialization done");
	memset(&rw_lock, 0, sizeof(rw_lock));
	g_rw_lock_init(&rw_lock);
}

void
srvtimer_fini(void)
{
	GRID_DEBUG("about to free the timers");

	void func_free(gpointer d, gpointer u)
	{
		(void) u;
		if (d) {
			GRID_TRACE("freeing timer '%s'", ((struct srvtimer_s *) d)->name);
			g_free(d);
		}
	}

	g_rw_lock_writer_lock(&rw_lock);
	g_slist_foreach(timers_regular, func_free, NULL);
	g_slist_free(timers_regular);
	timers_regular = NULL;
	g_rw_lock_writer_unlock(&rw_lock);

	GRID_INFO("timers freed");
}

void
srvtimer_fire(guint64 ticks)
{
	void timers_iterator(gpointer d, gpointer u)
	{
		g_assert_nonnull (d);
		(void) u;
		struct srvtimer_s *st = (struct srvtimer_s *) d;
		if (st->ticks <= ticks) {
			if (st->fire)
				st->fire(st->u);
			st->ticks = ticks + st->freq;
		}
	}

	g_rw_lock_reader_lock(&rw_lock);
	g_slist_foreach(timers_regular, timers_iterator, NULL);
	g_rw_lock_reader_unlock(&rw_lock);
}
