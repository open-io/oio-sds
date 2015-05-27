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

#ifndef OIO_SDS__rainx__rainx_stats_rrd_h
# define OIO_SDS__rainx__rainx_stats_rrd_h 1

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
	apr_uint32_t ten[8];
	apr_uint32_t lock;
};

struct delta_debug_s
{
	apr_uint32_t delta;
	char *dump;
};

struct rainx_stats_rrd_s * rainx_stats_rrd_create(apr_pool_t *pool, time_t period);

void rainx_stats_rrd_init(struct rainx_stats_rrd_s *rsr);

void rainx_stats_rrd_lock(struct rainx_stats_rrd_s *rsr);

void rainx_stats_rrd_unlock(struct rainx_stats_rrd_s *rsr);

struct rainx_stats_rrd_s * rainx_stats_rrd_dup(apr_pool_t *pool, struct rainx_stats_rrd_s *rrd);

void rainx_stats_rrd_push(struct rainx_stats_rrd_s *rsr, apr_uint32_t v);

apr_uint32_t rainx_stats_rrd_get(struct rainx_stats_rrd_s *rsr);

apr_uint32_t rainx_stats_rrd_get_delta(struct rainx_stats_rrd_s *rsr, time_t period);

struct delta_debug_s *rainx_stats_rrd_debug_get_delta(struct rainx_stats_rrd_s *rsr, apr_pool_t *p, time_t period);

char *rainx_stats_rrd_dump_values(struct rainx_stats_rrd_s *str, apr_pool_t *p);

#endif /*OIO_SDS__rainx__rainx_stats_rrd_h*/
