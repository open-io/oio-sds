/*
OpenIO SDS rainx
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include <time.h>

#include <apr.h>
#include <apr_strings.h>
#include <apr_shm.h>
#include <apr_global_mutex.h>
#include <apr_time.h>
#include <apr_atomic.h>

#include <httpd.h>
#include <http_log.h>
#include <http_config.h>

#include "rainx_stats_rrd.h"

static void
_copy_tab_values(struct rainx_stats_rrd_s *src, struct rainx_stats_rrd_s *dst)
{
	for (time_t i = 0; i < src->period; i++)
		dst->ten[i] = src->ten[i];
}

static void
_init_tab_values(struct rainx_stats_rrd_s *rrd, time_t period)
{
	for (time_t i = 0; i < period; i++)
		rrd->ten[i] = 0;
}

struct rainx_stats_rrd_s *
rainx_stats_rrd_create(apr_pool_t *pool, time_t period)
{
	struct rainx_stats_rrd_s *result = NULL;

	if(period <= 1)
		return NULL;

	result = apr_palloc(pool, sizeof(struct rainx_stats_rrd_s) +(period * (sizeof(apr_uint32_t))));
	result->last = time(0);
	result->period = period;
	_init_tab_values(result, period);

	return result;
}

void
rainx_stats_rrd_init(struct rainx_stats_rrd_s *rsr)
{
	rsr->lock = 0;
	rsr->last = time(0);
	rsr->period = 8;
	_init_tab_values(rsr, 8);
}

void
rainx_stats_rrd_lock(struct rainx_stats_rrd_s *rsr)
{
	do {
		if (0 == apr_atomic_cas32(&(rsr->lock), 1, 0))
			return;
			apr_sleep(100);
	} while (1);
}

void
rainx_stats_rrd_unlock(struct rainx_stats_rrd_s *rsr)
{
	apr_atomic_cas32(&(rsr->lock), 0, 1);
}

struct rainx_stats_rrd_s *
rainx_stats_rrd_dup(apr_pool_t *pool, struct rainx_stats_rrd_s *rrd)
{
	if(!rrd)
		return NULL;

	struct rainx_stats_rrd_s *result = NULL;

	result = apr_palloc(pool, sizeof(struct rainx_stats_rrd_s) +(rrd->period * (sizeof(apr_uint32_t))));
	result->last = rrd->last;
	result->period = rrd->period;
	_copy_tab_values(rrd, result);

	return result;
}

static void
_rsr_blank_empty_slots(struct rainx_stats_rrd_s *rsr, apr_uint32_t v, time_t now)
{
	apr_time_t i;
	for (i = rsr->last; i < now;)
		rsr->ten[(++i) % rsr->period] = v;
	rsr->last = now;
}

void
rainx_stats_rrd_push(struct rainx_stats_rrd_s *rsr, apr_uint32_t v)
{
	apr_time_t now;

	rainx_stats_rrd_lock(rsr);

	if ((now = time(0)) != rsr->last)
		_rsr_blank_empty_slots(rsr, rsr->ten[rsr->last % rsr->period], now);

	rsr->ten[now % rsr->period] = v;
	rsr->last = now;

	rainx_stats_rrd_unlock(rsr);
}

apr_uint32_t
rainx_stats_rrd_get(struct rainx_stats_rrd_s *rsr)
{
	apr_time_t now;
	apr_uint32_t result;

	rainx_stats_rrd_lock(rsr);

	if ((now = time(0)) != rsr->last)
		_rsr_blank_empty_slots(rsr, rsr->ten[rsr->last % rsr->period], now);

	result = rsr->ten[now % rsr->period];

	rainx_stats_rrd_unlock(rsr);

	return result;
}

apr_uint32_t
rainx_stats_rrd_get_delta(struct rainx_stats_rrd_s *rsr, time_t period)
{
	apr_time_t now;
	apr_uint32_t result;

	if (period >= rsr->period)
		return 0;

	rainx_stats_rrd_lock(rsr);

	if ((now = time(0)) != rsr->last)
		_rsr_blank_empty_slots(rsr, rsr->ten[rsr->last % rsr->period], now);

	result = rsr->ten[now % rsr->period] - rsr->ten[(now-period) % rsr->period];

	rainx_stats_rrd_unlock(rsr);

	return result;
}

static char *
_dump_rrd(struct rainx_stats_rrd_s *rsr, apr_pool_t *p)
{
	return apr_psprintf(p, "[\"last\": \"%li\", period\": \"%li\", ten\": %s] ",
			rsr->last, rsr->period, rainx_stats_rrd_dump_values(rsr, p));
}

struct delta_debug_s *
rainx_stats_rrd_debug_get_delta(struct rainx_stats_rrd_s *rsr, apr_pool_t *p, time_t period)
{
	time_t now;

	char *result = NULL;

	result = apr_psprintf(p, "%s | period: %li ", _dump_rrd(rsr,p), period);

	if (period >= rsr->period)
		return 0;

	if ((now = time(0)) != rsr->last)
		_rsr_blank_empty_slots(rsr, rsr->ten[rsr->last % rsr->period], now);

	apr_uint32_t op = rsr->ten[now % rsr->period] - rsr->ten[(now-period) % rsr->period];
	apr_uint32_t nrp = now % rsr->period;
	apr_uint32_t nprp = (now-period) % rsr->period;

	result = apr_psprintf(p, "%s| now: %li after bs: %s"
				"operation = rsr->ten[%li mod %li] - "
				"rsr->ten[(%li-%li) mod %li] "
				"(rsr->ten[%u] - rsr->ten[%u] "
				"(%u - %u (%u)))",
				result, now, _dump_rrd(rsr,p), now, rsr->period, now, period, rsr->period, nrp, 
				nprp, rsr->ten[nrp], rsr->ten[nprp], op);

	struct delta_debug_s *dd = apr_palloc(p, sizeof(struct delta_debug_s));
	dd->dump = result;
	dd->delta = op;

	return dd;
}

char *
rainx_stats_rrd_dump_values(struct rainx_stats_rrd_s *rsr, apr_pool_t *p)
{
	char *str = NULL;

	str = apr_psprintf(p, "[%u", rsr->ten[0]);
	for (time_t i = 1; i < rsr->period; i++) {
		str = apr_psprintf(p, "%s, %u", str, rsr->ten[i]);
	}
	str = apr_pstrcat(p, str, "]", NULL);

	return str;
}
