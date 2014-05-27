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

#include <httpd.h>
#include <http_log.h>
#include <http_config.h>

#include <glib.h>

#include "rainx_stats_rrd.h"

static void
_copy_tab_values(struct rainx_stats_rrd_s *src, struct rainx_stats_rrd_s *dst)
{
	for(uint i = 0; i < src->period; i++)
		dst->ten[i] = src->ten[i];
}

static void
_init_tab_values(struct rainx_stats_rrd_s *rrd, time_t period)
{
	for(uint i = 0; i < period; i++)
		rrd->ten[i] = 0;
}

struct rainx_stats_rrd_s *
rainx_stats_rrd_create(apr_pool_t *pool, time_t period)
{
	struct rainx_stats_rrd_s *result = NULL;

	if(period <= 1)
		return NULL;

	result = apr_palloc(pool, sizeof(struct rainx_stats_rrd_s) +(period * (sizeof(apr_uint64_t))));
	result->last = time(0);
	result->period = period;
	_init_tab_values(result, period);

	return result;
}

void
rainx_stats_rrd_init(struct rainx_stats_rrd_s *rsr)
{
	rsr->last = time(0);
	rsr->period = 8;
	_init_tab_values(rsr, 8);
}

struct rainx_stats_rrd_s *
rainx_stats_rrd_dup(apr_pool_t *pool, struct rainx_stats_rrd_s *rrd)
{
	if(!rrd)
		return NULL;

	struct rainx_stats_rrd_s *result = NULL;

	result = apr_palloc(pool, sizeof(struct rainx_stats_rrd_s) +(rrd->period * (sizeof(apr_uint64_t))));
	result->last = rrd->last;
	result->period = rrd->period;
	_copy_tab_values(rrd, result);

	return result;
}

static void
_rsr_blank_empty_slots(struct rainx_stats_rrd_s *rsr, apr_uint64_t v, time_t now)
{
	time_t i;
	for (i = rsr->last; i < now;)
		rsr->ten[(++i) % rsr->period] = v;
	rsr->last = now;
}

void
rainx_stats_rrd_push(struct rainx_stats_rrd_s *rsr, apr_uint64_t v)
{
	time_t now;
	
	if ((now = time(0)) != rsr->last)
		_rsr_blank_empty_slots(rsr, rsr->ten[rsr->last % rsr->period], now);
	
	rsr->ten[now % rsr->period] = v;
	rsr->last = now;
}

apr_uint64_t
rainx_stats_rrd_get(struct rainx_stats_rrd_s *rsr)
{
	apr_time_t now;

	if ((now = time(0)) != rsr->last)
		_rsr_blank_empty_slots(rsr, rsr->ten[rsr->last % rsr->period], now);
	
	return rsr->ten[now % rsr->period];
}

apr_uint64_t
rainx_stats_rrd_get_delta(struct rainx_stats_rrd_s *rsr, time_t period)
{
	time_t now;

	if (period >= rsr->period)
		return 0;

	if ((now = time(0)) != rsr->last)
		_rsr_blank_empty_slots(rsr, rsr->ten[rsr->last % rsr->period], now);

	return rsr->ten[now % rsr->period] - rsr->ten[(now-period) % rsr->period];
}

static char *
_dump_rrd(struct rainx_stats_rrd_s *rsr, apr_pool_t *p)
{
	return apr_psprintf(p, "[\"last\": \"%"G_GUINT64_FORMAT"\", period\": \"%"G_GUINT64_FORMAT"\", ten\": %s] ",
			rsr->last, rsr->period, rainx_stats_rrd_dump_values(rsr, p));
}

struct delta_debug_s *
rainx_stats_rrd_debug_get_delta(struct rainx_stats_rrd_s *rsr, apr_pool_t *p, time_t period)
{
	time_t now;

	char *result = NULL;

	result = apr_psprintf(p, "%s | period : %"G_GUINT64_FORMAT" ", _dump_rrd(rsr,p), period);

	if (period >= rsr->period)
		return 0;

	if ((now = time(0)) != rsr->last)
		_rsr_blank_empty_slots(rsr, rsr->ten[rsr->last % rsr->period], now);

	apr_uint64_t op = rsr->ten[now % rsr->period] - rsr->ten[(now-period) % rsr->period];
	apr_uint64_t nrp = now % rsr->period;
	apr_uint64_t nprp = (now-period) % rsr->period;

	result = apr_psprintf(p, "%s| now : %"G_GUINT64_FORMAT" after bs: %s"
				"operation = rsr->ten[%"G_GUINT64_FORMAT" mod %"G_GUINT64_FORMAT"] - "
				"rsr->ten[(%"G_GUINT64_FORMAT"-%"G_GUINT64_FORMAT") mod %"G_GUINT64_FORMAT"] "
				"(rsr->ten[%"G_GUINT64_FORMAT"] - rsr->ten[%"G_GUINT64_FORMAT"] "
				"(%"G_GUINT64_FORMAT" - %"G_GUINT64_FORMAT" (%"G_GUINT64_FORMAT")))",
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

	str = apr_psprintf(p, "[%"G_GUINT64_FORMAT, rsr->ten[0]);
	for(uint i = 1; i < rsr->period; i++) {
		str = apr_psprintf(p, "%s, %"G_GUINT64_FORMAT"", str, rsr->ten[i]);
	}
	str = apr_pstrcat(p, str, "]", NULL);

	return str;
}
