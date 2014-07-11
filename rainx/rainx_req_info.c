#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "rainx"
#endif

#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#if APR_HAVE_STDIO_H
#include <stdio.h>              /* for sprintf() */
#endif

#include <sys/socket.h>
#include <netdb.h>

#include <apr.h>
#include <apr_file_io.h>
#include <apr_strings.h>
#include <apr_buckets.h>

#include <httpd.h>
#include <http_log.h>
#include <http_config.h>
#include <http_protocol.h>      /* for ap_set_* (in dav_rainx_set_headers) */
#include <http_request.h>       /* for ap_update_mtime() */

#include <mod_dav.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <rawx-lib/src/rawx.h>

#include <glib.h>

#include "mod_dav_rainx.h"
#include "rainx_internals.h"
#include "rainx_config.h"

/* ------------------------------------------------------------------------- */

typedef const char * (*generator_f)(const dav_resource *resource, apr_pool_t *pool);

enum request_type_e {

	STAT = 1,
	INFO,
};

struct dav_resource_private {
	apr_pool_t *pool;
	const request_rec *request;
	dav_rainx_server_conf *conf;
	generator_f generator;
	enum request_type_e type;
	
};

/* ------------------------------------------------------------------------- */

#define STR_KV(Field,Name) apr_psprintf(pool, "rainx."Name" %"APR_UINT64_T_FMT"\n", stats.Field)

static const char *
__gen_info(const dav_resource *resource, apr_pool_t *pool)
{
	dav_rainx_server_conf *conf;

	conf = resource->info->conf;

	return apr_pstrcat(pool, "namespace ", conf->ns_name, "\npath ", conf->docroot, "\n", NULL);
}

static const char *
__gen_stats(const dav_resource *resource, apr_pool_t *pool)
{
	struct rainx_stats_s stats;

	DAV_XDEBUG_POOL(pool, 0, "%s()", __FUNCTION__);

	bzero(&stats, sizeof(stats));
	dav_rainx_server_conf *c = NULL;
	c = resource_get_server_config(resource);
	server_getall_stat(c, pool, &stats);

	apr_uint64_t req = rainx_stats_rrd_get_delta(&(stats.rrd_req_sec), 4);
	apr_uint64_t reqavgtime = rainx_stats_rrd_get_delta(&(stats.rrd_duration), 4);
	apr_uint64_t req_put = rainx_stats_rrd_get_delta(&(stats.rrd_req_put_sec), 4);
	apr_uint64_t reqavgtime_put = rainx_stats_rrd_get_delta(&(stats.rrd_put_duration), 4);
	apr_uint64_t req_get = rainx_stats_rrd_get_delta(&(stats.rrd_req_get_sec), 4);
	apr_uint64_t reqavgtime_get = rainx_stats_rrd_get_delta(&(stats.rrd_get_duration), 4);
	apr_uint64_t req_del = rainx_stats_rrd_get_delta(&(stats.rrd_req_del_sec), 4);
	apr_uint64_t reqavgtime_del = rainx_stats_rrd_get_delta(&(stats.rrd_del_duration), 4);

	apr_uint64_t r_time = 0, r_put_time = 0, r_get_time = 0, r_del_time = 0;
	if(req > 0)
		r_time = reqavgtime / req;
	if(req_put > 0)
		r_put_time = reqavgtime_put / req_put;
	if(req_get > 0)
		r_get_time = reqavgtime_get / req_get;
	if(req_del > 0)
		r_del_time = reqavgtime_del / req_del;

	double r_rate = 0, r_put_rate = 0, r_get_rate = 0, r_del_rate = 0;
	r_rate = (double)req / 4;
	r_put_rate = (double)req_put / 4;
	r_get_rate = (double)req_get / 4;
	r_del_rate = (double)req_del / 4;

	return apr_pstrcat(pool, 
			STR_KV(req_all,       "req.all"),
			STR_KV(req_chunk_put, "req.put"),
			STR_KV(req_chunk_get, "req.get"),
			STR_KV(req_chunk_del, "req.del"),
			STR_KV(req_stat,      "req.stat"),
			STR_KV(req_info,      "req.info"),
			STR_KV(req_raw,       "req.raw"),
			STR_KV(req_other,     "req.other"),
			STR_KV(rep_2XX,       "rep.2xx"),
			STR_KV(rep_4XX,       "rep.4xx"),
			STR_KV(rep_5XX,       "rep.5xx"),
			STR_KV(rep_other,     "rep.other"),
			STR_KV(rep_403,       "rep.403"),
			STR_KV(rep_404,       "rep.404"),
			STR_KV(rep_bread,     "rep.bread"),
			STR_KV(rep_bwritten,  "rep.bwritten"),
			apr_psprintf(pool, "rainx.reqpersec %f\n", r_rate),
			apr_psprintf(pool, "rainx.avreqtime %"APR_UINT64_T_FMT"\n", r_time),
			apr_psprintf(pool, "rainx.reqputpersec %f\n", r_put_rate),
			apr_psprintf(pool, "rainx.avputreqtime %"APR_UINT64_T_FMT"\n", r_put_time),
			apr_psprintf(pool, "rainx.reqgetpersec %f\n", r_get_rate),
			apr_psprintf(pool, "rainx.avgetreqtime %"APR_UINT64_T_FMT"\n", r_get_time),
			apr_psprintf(pool, "rainx.reqdelpersec %f\n", r_del_rate),
			apr_psprintf(pool, "rainx.avdelreqtime %"APR_UINT64_T_FMT"\n", r_del_time),
			NULL);
}

static dav_resource*
__build_req_resource(const request_rec *r, const dav_hooks_repository *hooks, generator_f gen)
{
	dav_resource *resource;

	DAV_XDEBUG_REQ(r, 0, "%s(...)", __FUNCTION__);
	
	resource = apr_pcalloc(r->pool, sizeof(*resource));
	resource->type = DAV_RESOURCE_TYPE_PRIVATE;
	resource->hooks = hooks;
	resource->pool = r->pool;
	resource->exists = 1;
	resource->collection = 0;

	resource->info = apr_pcalloc(r->pool, sizeof(struct dav_resource_private));
	resource->info->generator = gen;
	resource->info->pool = r->pool;
	resource->info->conf = request_get_server_config(r);
	resource->info->request = r;

	return resource;
}

dav_error *
dav_rainx_stat_get_resource(request_rec *r, const char *root_dir, const char *label,
	int use_checked_in, dav_resource **result_resource)
{
	(void) root_dir;
	(void) label;
	(void) use_checked_in;

	DAV_XDEBUG_REQ(r, 0, "%s(...)", __FUNCTION__);
	*result_resource = NULL;

	if (r->method_number != M_GET)
		return server_create_and_stat_error(request_get_server_config(r), r->pool,
				HTTP_BAD_REQUEST, 0, apr_pstrdup(r->pool, "Invalid request method, only GET"));
	
	*result_resource = __build_req_resource(r, &dav_hooks_repository_rainxstat, __gen_stats);
	(*result_resource)->info->type = STAT;
	return NULL;
}

dav_error *
dav_rainx_info_get_resource(request_rec *r, const char *root_dir, const char *label,
	int use_checked_in, dav_resource **result_resource)
{
	(void) root_dir;
	(void) label;
	(void) use_checked_in;

	DAV_XDEBUG_REQ(r, 0, "%s(...)", __FUNCTION__);
	*result_resource = NULL;
	
	if (r->method_number != M_GET)
		return server_create_and_stat_error(request_get_server_config(r), r->pool,
				HTTP_BAD_REQUEST, 0, apr_pstrdup(r->pool, "Invalid request method, only GET"));

	*result_resource = __build_req_resource(r, &dav_hooks_repository_rainxinfo, __gen_info);
	(*result_resource)->info->type = INFO;
	return NULL;
}


static dav_error *
dav_rainx_get_parent_resource_SPECIAL(const dav_resource *resource, dav_resource **result_parent)
{
	DAV_XDEBUG_POOL(resource->info->pool, 0, "%s(...)", __FUNCTION__);
	*result_parent = __build_req_resource(resource->info->request,
		resource->hooks, resource->info->generator);
	return NULL;
}


static int
dav_rainx_is_same_resource_SPECIAL(const dav_resource *res1, const dav_resource *res2)
{
	(void) res1;
	(void) res2;

	DAV_XDEBUG_RES(res1, 0, "%s(...)", __FUNCTION__);
	return (res1->type == res2->type) && (res1->hooks == res2->hooks);
}


static int
dav_rainx_is_parent_resource_SPECIAL(const dav_resource *res1, const dav_resource *res2)
{
	DAV_XDEBUG_RES(res1, 0, "%s(...)", __FUNCTION__);
	return dav_rainx_is_same_resource_SPECIAL(res1, res2);
}


static dav_error *
dav_rainx_deliver_SPECIAL(const dav_resource *resource, ap_filter_t *output)
{
	const char *result;
	int result_len;
	apr_status_t status;
	apr_pool_t *pool;
	apr_bucket_brigade *bb;
	apr_bucket *bkt;

	DAV_XDEBUG_RES(resource, 0, "%s()", __FUNCTION__);
	pool = resource->info->request->pool;

	/* Check resource type */
	if (resource->type != DAV_RESOURCE_TYPE_PRIVATE)
		return server_create_and_stat_error(resource_get_server_config(resource), pool,
			HTTP_CONFLICT, 0, apr_pstrdup(pool, "Cannot GET this type of resource."));
	if (resource->collection)
		return server_create_and_stat_error(resource_get_server_config(resource), pool,
			HTTP_CONFLICT, 0, apr_pstrdup(pool,"No GET on collections"));

	/* Generate the output */
	result = resource->info->generator(resource, pool);
	result_len = strlen(result);

	/* We must reply a buffer */
	bkt = apr_bucket_heap_create(result, result_len, NULL, output->c->bucket_alloc);
	bb = apr_brigade_create(pool, output->c->bucket_alloc);
	APR_BRIGADE_INSERT_TAIL(bb, bkt);

	/* Nothing more to reply */
	bkt = apr_bucket_eos_create(output->c->bucket_alloc);
	APR_BRIGADE_INSERT_TAIL(bb, bkt);

	DAV_XDEBUG_RES(resource, 0, "%s : ready to deliver", __FUNCTION__);

	if ((status = ap_pass_brigade(output, bb)) != APR_SUCCESS)
		return server_create_and_stat_error(resource_get_server_config(resource), pool,
			HTTP_FORBIDDEN, 0, apr_pstrdup(pool,"Could not write contents to filter."));
	
	server_inc_stat(resource_get_server_config(resource), RAWX_STATNAME_REP_2XX, 0);

	/* HERE ADD request counter */
	switch(resource->info->type) {
		case STAT:
			server_inc_request_stat(resource_get_server_config(resource), RAWX_STATNAME_REQ_STAT,
				request_get_duration(resource->info->request));
			break;
		case INFO:
			server_inc_request_stat(resource_get_server_config(resource), RAWX_STATNAME_REQ_INFO,
				request_get_duration(resource->info->request));
			break;
		default:
			break;
	}

	return NULL;
}

static dav_error *
dav_rainx_set_headers_SPECIAL(request_rec *r, const dav_resource *resource)
{
	(void) r;
	(void) resource;
	return NULL;
}

static const char *
dav_rainx_stat_getetag(const dav_resource *resource)
{
	(void) resource;
	return apr_pstrdup(resource->info->request->pool, "rainx-stat");
}

static const char *
dav_rainx_info_getetag(const dav_resource *resource)
{
	(void) resource;
	return apr_pstrdup(resource->info->request->pool, "rainx-info");
}


const dav_hooks_repository dav_hooks_repository_rainxinfo =
{
	1,
	dav_rainx_info_get_resource,
	dav_rainx_get_parent_resource_SPECIAL,
	dav_rainx_is_same_resource_SPECIAL,
	dav_rainx_is_parent_resource_SPECIAL,
	NULL /*dav_rainx_info_open_stream*/,
	NULL /*dav_rainx_info_close_stream*/,
	NULL /*dav_rainx_info_write_stream*/,
	NULL /*dav_rainx_info_seek_stream*/,
	dav_rainx_set_headers_SPECIAL,
	dav_rainx_deliver_SPECIAL,
	NULL /* no collection creation */,
	NULL /* no copy of resources allowed */,
	NULL /* cannot move resources */,
	NULL /*dav_rainx_info_remove_resource*/,
	NULL /* no walk across the chunks */,
	dav_rainx_info_getetag,
	NULL, /* no module context */
#if MODULE_MAGIC_COOKIE == 0x41503234UL /* "AP24" */
	NULL,
	NULL,
#endif
};


const dav_hooks_repository dav_hooks_repository_rainxstat =
{
	1,
	dav_rainx_stat_get_resource,
	dav_rainx_get_parent_resource_SPECIAL,
	dav_rainx_is_same_resource_SPECIAL,
	dav_rainx_is_parent_resource_SPECIAL,
	NULL /*dav_rainx_stat_open_stream*/,
	NULL /*dav_rainx_stat_close_stream*/,
	NULL /*dav_rainx_stat_write_stream*/,
	NULL /*dav_rainx_stat_seek_stream*/,
	dav_rainx_set_headers_SPECIAL,
	dav_rainx_deliver_SPECIAL,
	NULL /* no collection creation */,
	NULL /* no copy of resources allowed */,
	NULL /* cannot move resources */,
	NULL /*dav_rainx_stat_remove_resource*/,
	NULL /* no walk across the chunks */,
	dav_rainx_stat_getetag,
	NULL, /* no module context */
#if MODULE_MAGIC_COOKIE == 0x41503234UL /* "AP24" */
	NULL,
	NULL,
#endif
};
