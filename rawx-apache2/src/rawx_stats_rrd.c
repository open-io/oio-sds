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

#include "rawx_stats_rrd.h"

static void
_copy_tab_values(struct rawx_stats_rrd_s *src, struct rawx_stats_rrd_s *dst)
{
	for(uint i = 0; i < src->period; i++)
		dst->ten[i] = src->ten[i];
}

static void
_init_tab_values(struct rawx_stats_rrd_s *rrd, time_t period)
{
	for(uint i = 0; i < period; i++)
		rrd->ten[i] = 0;
}

struct rawx_stats_rrd_s *
rawx_stats_rrd_create(apr_pool_t *pool, time_t period)
{
	struct rawx_stats_rrd_s *result = NULL;

	if(period <= 1)
		return NULL;

	result = apr_palloc(pool, sizeof(struct rawx_stats_rrd_s) +(period * (sizeof(apr_uint32_t))));
	result->last = time(0);
	result->period = period;
	_init_tab_values(result, period);

	return result;
}

void
rawx_stats_rrd_init(struct rawx_stats_rrd_s *rsr)
{
	rsr->lock = 0;
	rsr->last = time(0);
	rsr->period = 8;
	_init_tab_values(rsr, 8);
}

void
rawx_stats_rrd_lock(struct rawx_stats_rrd_s *rsr)
{
	do {
		if (0 == apr_atomic_cas32(&(rsr->lock), 1, 0))
			return;
		apr_sleep(100);
	} while (1);
}

void
rawx_stats_rrd_unlock(struct rawx_stats_rrd_s *rsr)
{
	 apr_atomic_cas32(&(rsr->lock), 0, 1);
}

struct rawx_stats_rrd_s *
rawx_stats_rrd_dup(apr_pool_t *pool, struct rawx_stats_rrd_s *rrd)
{
	if(!rrd)
		return NULL;

	struct rawx_stats_rrd_s *result = NULL;

	result = apr_palloc(pool, sizeof(struct rawx_stats_rrd_s) +(rrd->period * (sizeof(apr_uint32_t))));
	result->last = rrd->last;
	result->period = rrd->period;
	_copy_tab_values(rrd, result);

	return result;
}

static void
_rsr_blank_empty_slots(register struct rawx_stats_rrd_s *rsr, register apr_uint32_t v, register time_t now)
{
	register apr_time_t last;

	last = rsr->last % rsr->period;
	rsr->last = now;
	now = now % rsr->period;

	if (now - last >= rsr->period) {
		last = 0;
		now = rsr->period-1;
	}
	do {
		rsr->ten[last] = v;
		last = (last+1) % rsr->period;
	} while (last != now);
}

void
rawx_stats_rrd_push(struct rawx_stats_rrd_s *rsr, apr_uint32_t v)
{
	apr_time_t now;
	
	rawx_stats_rrd_lock(rsr);

	if ((now = time(0)) != rsr->last)
		_rsr_blank_empty_slots(rsr, rsr->ten[rsr->last % rsr->period], now);
	
	rsr->ten[now % rsr->period] = v;
	rsr->last = now;

	rawx_stats_rrd_unlock(rsr);
}

apr_uint32_t
rawx_stats_rrd_get(struct rawx_stats_rrd_s *rsr)
{
	apr_time_t now;
	apr_uint32_t result;

	rawx_stats_rrd_lock(rsr);

	if ((now = time(0)) != rsr->last)
		_rsr_blank_empty_slots(rsr, rsr->ten[rsr->last % rsr->period], now);
	result = rsr->ten[now % rsr->period];

	rawx_stats_rrd_unlock(rsr);

	return result;
}

apr_uint32_t
rawx_stats_rrd_get_delta(struct rawx_stats_rrd_s *rsr, time_t period)
{
	apr_time_t now;
	apr_uint32_t result;

	if (period >= rsr->period)
		return 0;

	rawx_stats_rrd_lock(rsr);

	if ((now = time(0)) != rsr->last)
		_rsr_blank_empty_slots(rsr, rsr->ten[rsr->last % rsr->period], now);
	result = rsr->ten[now % rsr->period] - rsr->ten[(now-period) % rsr->period];

	rawx_stats_rrd_unlock(rsr);

	return result;
}

static char *
_dump_rrd(struct rawx_stats_rrd_s *rsr, apr_pool_t *p)
{
	return apr_psprintf(p, "[\"last\": \"%li\", period\": \"%li\", ten\": %s] ",
			rsr->last, rsr->period, rawx_stats_rrd_dump_values(rsr, p));
}

struct delta_debug_s *
rawx_stats_rrd_debug_get_delta(struct rawx_stats_rrd_s *rsr, apr_pool_t *p, time_t period)
{
	time_t now;

	char *result = NULL;

	result = apr_psprintf(p, "%s | period : %li ", _dump_rrd(rsr,p), period);

	if (period >= rsr->period)
		return 0;

	if ((now = time(0)) != rsr->last)
		_rsr_blank_empty_slots(rsr, rsr->ten[rsr->last % rsr->period], now);

	apr_uint32_t op = rsr->ten[now % rsr->period] - rsr->ten[(now-period) % rsr->period];
	apr_uint32_t nrp = now % rsr->period;
	apr_uint32_t nprp = (now-period) % rsr->period;

	result = apr_psprintf(p, "%s| now : %li after bs: %s"
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
rawx_stats_rrd_dump_values(struct rawx_stats_rrd_s *rsr, apr_pool_t *p)
{
	char *str = NULL;

	str = apr_psprintf(p, "[%u", rsr->ten[0]);
	for(uint i = 1; i < rsr->period; i++) {
		str = apr_psprintf(p, "%s, %u", str, rsr->ten[i]);
	}
	str = apr_pstrcat(p, str, "]", NULL);

	return str;
}
