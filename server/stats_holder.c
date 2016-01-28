/*
OpenIO SDS server
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

#include <metautils/lib/metautils.h>

#include "internals.h"
#include "stats_holder.h"

enum {
	/*! If set, when there is no activity, the untouched slots are filled
	 * with zeros. If not set (default), the previous value is repeated. */
	RRD_FLAG_SHIFT_SET = 0x01,
};

struct grid_single_rrd_s
{
	time_t last;
	time_t period;
	guint32 flags;
	guint64 def;
	guint64 l0[];
};

struct grid_single_rrd_s*
grid_single_rrd_create(time_t now, time_t period)
{
	struct grid_single_rrd_s *gsr;

	EXTRA_ASSERT(period > 1);

	gsr = g_malloc0(sizeof(struct grid_single_rrd_s)
			+ (period * sizeof(guint64)));
	gsr->last = now;
	gsr->period = period;

	return gsr;
}

void
grid_single_rrd_destroy(struct grid_single_rrd_s *gsr)
{
	if (gsr)
		g_free(gsr);
}

void
grid_single_rrd_set_default(struct grid_single_rrd_s *gsr, guint64 v)
{
	gsr->def = v;
	gsr->flags |= RRD_FLAG_SHIFT_SET;
}

static void
_rrd_set(struct grid_single_rrd_s *gsr, guint64 v)
{
	gsr->l0[gsr->last % gsr->period] = v;
}

static guint64
_rrd_get(struct grid_single_rrd_s *gsr, time_t at)
{
	return gsr->l0[at % gsr->period];
}

static guint64
_rrd_current(struct grid_single_rrd_s *gsr)
{
	return _rrd_get(gsr, gsr->last);
}

static guint64
_rrd_past(struct grid_single_rrd_s *gsr, time_t period)
{
	return _rrd_get(gsr, gsr->last - period);
}

static void
_gsr_manage_timeshift(struct grid_single_rrd_s *gsr, time_t now)
{
	if (now == gsr->last)
		return ;

	guint64 v = (gsr->flags & RRD_FLAG_SHIFT_SET) ? gsr->def : _rrd_current(gsr);
	for (time_t i=0; gsr->last != now && i++ < gsr->period ;) {
		gsr->last ++;
		_rrd_set(gsr,v);
	}
	gsr->last = now;
}

void
grid_single_rrd_push(struct grid_single_rrd_s *gsr, time_t now, guint64 v)
{
	_gsr_manage_timeshift(gsr, now);
	_rrd_set(gsr, v);
}

void
grid_single_rrd_pushifmax(struct grid_single_rrd_s *gsr, time_t now, guint64 v)
{
	_gsr_manage_timeshift(gsr, now);
	guint64 v0 = _rrd_current(gsr);
	_rrd_set(gsr, MAX(v0,v));
}

guint64
grid_single_rrd_get(struct grid_single_rrd_s *gsr, time_t now)
{
	_gsr_manage_timeshift(gsr, now);
	return _rrd_current(gsr);
}

guint64
grid_single_rrd_get_delta(struct grid_single_rrd_s *gsr,
		time_t now, time_t period)
{
	EXTRA_ASSERT(period <= gsr->period);
	_gsr_manage_timeshift(gsr, now);
	return _rrd_current(gsr) - _rrd_past(gsr, period);
}

guint64
grid_single_rrd_get_max(struct grid_single_rrd_s *gsr,
		time_t now, time_t period)
{
	EXTRA_ASSERT(period <= gsr->period);
	_gsr_manage_timeshift(gsr, now);
	guint64 maximum = 0;
	for (time_t i=0; i<period ;i++) {
		guint64 m = _rrd_past(gsr,i);
		maximum = MAX(maximum,m);
	}
	return maximum;
}

void
grid_single_rrd_get_allmax(struct grid_single_rrd_s *gsr,
		time_t now, time_t period, guint64 *out)
{
	EXTRA_ASSERT(period <= gsr->period);
	_gsr_manage_timeshift(gsr, now);
	guint64 maximum = 0;
	for (time_t i=0; i<period ;i++) {
		guint64 m = _rrd_past(gsr,i);
		out[i] = maximum = MAX(maximum,m);
	}
}

