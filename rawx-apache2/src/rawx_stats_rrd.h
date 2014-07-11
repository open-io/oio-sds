#ifndef _RAWX_STATS_RRD_H_
#define _RAWX_STATS_RRD_H_

#include <apr.h>
#include <apr_time.h>

#define RAWX_STATNAME_REQ_ALL       "q0"
#define RAWX_STATNAME_REQ_CHUNKGET  "q1"
#define RAWX_STATNAME_REQ_CHUNKPUT  "q2"
#define RAWX_STATNAME_REQ_CHUNKDEL  "q3"
#define RAWX_STATNAME_REQ_STAT      "q4"
#define RAWX_STATNAME_REQ_INFO      "q5"
#define RAWX_STATNAME_REQ_RAW       "q6"
#define RAWX_STATNAME_REQ_OTHER     "q7"

#define RAWX_STATNAME_REP_2XX       "r1"
#define RAWX_STATNAME_REP_4XX       "r2"
#define RAWX_STATNAME_REP_5XX       "r3"
#define RAWX_STATNAME_REP_OTHER     "r4"
#define RAWX_STATNAME_REP_403       "r5"
#define RAWX_STATNAME_REP_404       "r6"
#define RAWX_STATNAME_REP_BREAD     "r7"
#define RAWX_STATNAME_REP_BWRITTEN  "r8"


struct rawx_stats_rrd_s
{
	time_t last;
	time_t period;
	apr_uint32_t ten[8];
	apr_uint32_t lock;
};

struct delta_debug_s
{
	apr_uint32_t delta;
	char *dump;
};

/**
 *
 *
 *
 */
struct rawx_stats_rrd_s * rawx_stats_rrd_create(apr_pool_t *pool, time_t period);

/**
 *
 *
 *
 */
void rawx_stats_rrd_init(struct rawx_stats_rrd_s *rsr);

void rawx_stats_rrd_lock(struct rawx_stats_rrd_s *rsr);

void rawx_stats_rrd_unlock(struct rawx_stats_rrd_s *rsr);

/**
 *
 *
 *
 */
struct rawx_stats_rrd_s * rawx_stats_rrd_dup(apr_pool_t *pool, struct rawx_stats_rrd_s *rrd);

/**
 *
 *
 *
 */
void rawx_stats_rrd_push(struct rawx_stats_rrd_s *rsr, apr_uint32_t v);

/**
 *
 *
 *
 */
apr_uint32_t rawx_stats_rrd_get(struct rawx_stats_rrd_s *rsr);

/**
 *
 *
 *
 */
apr_uint32_t rawx_stats_rrd_get_delta(struct rawx_stats_rrd_s *rsr, time_t period);

/**
 *
 *
 *
 */
struct delta_debug_s *rawx_stats_rrd_debug_get_delta(struct rawx_stats_rrd_s *rsr, apr_pool_t *p, time_t period);

char *rawx_stats_rrd_dump_values(struct rawx_stats_rrd_s *str, apr_pool_t *p);
#endif /*  _RAWX_STATS_RRD_H_ */
