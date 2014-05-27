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


struct rainx_stats_rrd_s
{
	time_t last;
	time_t period;
	apr_uint64_t ten[8];
};

struct delta_debug_s
{
	apr_uint64_t delta;
	char *dump;
};

/**
 *
 *
 *
 */
struct rainx_stats_rrd_s * rainx_stats_rrd_create(apr_pool_t *pool, time_t period);

/**
 *
 *
 *
 */
void rainx_stats_rrd_init(struct rainx_stats_rrd_s *rsr);

/**
 *
 *
 *
 */
struct rainx_stats_rrd_s * rainx_stats_rrd_dup(apr_pool_t *pool, struct rainx_stats_rrd_s *rrd);

/**
 *
 *
 *
 */
void rainx_stats_rrd_push(struct rainx_stats_rrd_s *rsr, apr_uint64_t v);

/**
 *
 *
 *
 */
apr_uint64_t rainx_stats_rrd_get(struct rainx_stats_rrd_s *rsr);

/**
 *
 *
 *
 */
apr_uint64_t rainx_stats_rrd_get_delta(struct rainx_stats_rrd_s *rsr, time_t period);

/**
 *
 *
 *
 */
struct delta_debug_s *rainx_stats_rrd_debug_get_delta(struct rainx_stats_rrd_s *rsr, apr_pool_t *p, time_t period);

char *rainx_stats_rrd_dump_values(struct rainx_stats_rrd_s *str, apr_pool_t *p);
#endif /*  _RAWX_STATS_RRD_H_ */
