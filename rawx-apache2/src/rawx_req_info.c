/*
OpenIO SDS rawx-apache2
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
#include <apr_atomic.h>

#include <httpd.h>
#include <http_log.h>
#include <http_config.h>
#include <http_protocol.h>      /* for ap_set_* (in dav_rawx_set_headers) */
#include <http_request.h>       /* for ap_update_mtime() */
#include <mod_dav.h>

#include <glib.h>

#include <metautils/lib/metatypes.h>
#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <rawx-lib/src/rawx.h>

#include "mod_dav_rawx.h"
#include "rawx_internals.h"
#include "rawx_config.h"

/* ------------------------------------------------------------------------- */

typedef const char * (*generator_f)(const dav_resource *resource, apr_pool_t *pool);

enum request_type_e {

	STAT = 1,
	INFO,
};

struct dav_resource_private {
	apr_pool_t *pool;
	const request_rec *request;
	dav_rawx_server_conf *conf;
	generator_f generator;
	enum request_type_e type;
};

/* ------------------------------------------------------------------------- */

#define STR_KV(Field,Name) apr_psprintf(pool, Name" %u\n", \
		apr_atomic_read32(&stats->body.Field))

/*
RAWX{{
GET /info
~~~~~~~~~~~

Returns some static information about the targeted RAWX service.
No particular header is expected, neither in the request nor in the reply.

.. code-block:: http

   GET /info HTTP/1.1
   Host: 127.0.0.1
   Content-Length: 0


.. code-block:: http

   HTTP/1.1 200 OK
   Content-Length: 60

   namespace OPENIO
   path /home/jfs/.oio/sds/data/OPENIO-rawx-4

}}RAWX
*/
static const char *
__gen_info(const dav_resource *resource, apr_pool_t *pool)
{
	dav_rawx_server_conf *conf = resource->info->conf;
	return apr_pstrcat(pool, "namespace ", conf->ns_name, "\npath ", conf->docroot, "\n", NULL);
}

/*
RAWX{{
GET /stat
~~~~~~~~~~~

Returns some volatile counters and gauges about what's happening in the targeted RAWX service.

Sample exchange:

.. code-block:: http

   GET /stat HTTP/1.1
   Host: 127.0.0.1
   Content-Length: 0


.. code-block:: http

   HTTP/1.1 200 OK
   Content-Length: 625

   counter req.time 436106
   counter req.time.put 0
   counter req.time.get 0
   counter req.time.del 0
   counter req.time.stat 3612
   counter req.time.info 3613
   counter req.time.raw 0
   counter req.time.other 0
   counter req.hits 7225
   counter req.hits.put 0
   counter req.hits.get 0
   counter req.hits.del 0
   counter req.hits.stat 3612
   counter req.hits.info 3613
   counter req.hits.raw 0
   counter req.hits.other 0
   counter rep.hits.2xx 7225
   counter rep.hits.4xx 2
   counter rep.hits.5xx 0
   counter rep.hits.other 0
   counter rep.hits.403 0
   counter rep.hits.404 0
   counter rep.bread 0
   counter rep.bwritten 0
}}RAWX
*/
static const char *
__gen_stats(const dav_resource *resource, apr_pool_t *pool)
{
	dav_rawx_server_conf *c = resource_get_server_config(resource);

	struct shm_stats_s *stats = apr_shm_baseaddr_get(c->shm.handle);

	return apr_pstrcat(pool,
			STR_KV(time_all,       "counter req.time"),
			STR_KV(time_put,       "counter req.time.put"),
			STR_KV(time_get,       "counter req.time.get"),
			STR_KV(time_del,       "counter req.time.del"),
			STR_KV(time_stat,      "counter req.time.stat"),
			STR_KV(time_info,      "counter req.time.info"),
			STR_KV(time_raw,       "counter req.time.raw"),
			STR_KV(time_other,     "counter req.time.other"),

			STR_KV(req_all,       "counter req.hits"),
			STR_KV(req_chunk_put, "counter req.hits.put"),
			STR_KV(req_chunk_get, "counter req.hits.get"),
			STR_KV(req_chunk_del, "counter req.hits.del"),
			STR_KV(req_stat,      "counter req.hits.stat"),
			STR_KV(req_info,      "counter req.hits.info"),
			STR_KV(req_raw,       "counter req.hits.raw"),
			STR_KV(req_other,     "counter req.hits.other"),

			STR_KV(rep_2XX,       "counter rep.hits.2xx"),
			STR_KV(rep_4XX,       "counter rep.hits.4xx"),
			STR_KV(rep_5XX,       "counter rep.hits.5xx"),
			STR_KV(rep_other,     "counter rep.hits.other"),
			STR_KV(rep_403,       "counter rep.hits.403"),
			STR_KV(rep_404,       "counter rep.hits.404"),
			STR_KV(rep_bread,     "counter rep.bread"),
			STR_KV(rep_bwritten,  "counter rep.bwritten"),

			apr_psprintf(pool, "config volume %s", c->docroot),
			NULL);
}

static dav_resource*
__build_req_resource(const request_rec *r, const dav_hooks_repository *hooks, generator_f gen)
{
	dav_resource *resource = apr_pcalloc(r->pool, sizeof(*resource));
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
dav_rawx_stat_get_resource(request_rec *r, const char *root_dir, const char *label,
	int use_checked_in, dav_resource **result_resource)
{
	(void) root_dir;
	(void) label;
	(void) use_checked_in;

	*result_resource = NULL;

	if (r->method_number != M_GET)
		return server_create_and_stat_error(request_get_server_config(r), r->pool,
				HTTP_BAD_REQUEST, 0, apr_pstrdup(r->pool, "Invalid request method, only GET"));

	*result_resource = __build_req_resource(r, &dav_hooks_repository_rawxstat, __gen_stats);
	(*result_resource)->info->type = STAT;
	return NULL;
}

dav_error *
dav_rawx_info_get_resource(request_rec *r, const char *root_dir, const char *label,
	int use_checked_in, dav_resource **result_resource)
{
	(void) root_dir;
	(void) label;
	(void) use_checked_in;

	*result_resource = NULL;

	if (r->method_number != M_GET)
		return server_create_and_stat_error(request_get_server_config(r), r->pool,
				HTTP_BAD_REQUEST, 0, apr_pstrdup(r->pool, "Invalid request method, only GET"));

	*result_resource = __build_req_resource(r, &dav_hooks_repository_rawxinfo, __gen_info);
	(*result_resource)->info->type = INFO;
	return NULL;
}

static dav_error *
dav_rawx_get_parent_resource_SPECIAL(const dav_resource *resource, dav_resource **result_parent)
{
	*result_parent = __build_req_resource(resource->info->request,
		resource->hooks, resource->info->generator);
	return NULL;
}

static int
dav_rawx_is_same_resource_SPECIAL(const dav_resource *res1, const dav_resource *res2)
{
	(void) res1;
	(void) res2;
	return (res1->type == res2->type) && (res1->hooks == res2->hooks);
}

static int
dav_rawx_is_parent_resource_SPECIAL(const dav_resource *res1, const dav_resource *res2)
{
	return dav_rawx_is_same_resource_SPECIAL(res1, res2);
}

static dav_error *
dav_rawx_deliver_SPECIAL(const dav_resource *resource, ap_filter_t *output)
{
	const char *result;
	int result_len;
	apr_status_t status;
	apr_pool_t *pool;
	apr_bucket_brigade *bb;
	apr_bucket *bkt;

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
dav_rawx_set_headers_SPECIAL(request_rec *r, const dav_resource *resource)
{
	(void) r;
	(void) resource;
	return NULL;
}

static const char *
dav_rawx_stat_getetag(const dav_resource *resource)
{
	(void) resource;
	return apr_pstrdup(resource->info->request->pool, "rawx-stat");
}

static const char *
dav_rawx_info_getetag(const dav_resource *resource)
{
	(void) resource;
	return apr_pstrdup(resource->info->request->pool, "rawx-info");
}

const dav_hooks_repository dav_hooks_repository_rawxinfo =
{
	1,
	dav_rawx_info_get_resource,
	dav_rawx_get_parent_resource_SPECIAL,
	dav_rawx_is_same_resource_SPECIAL,
	dav_rawx_is_parent_resource_SPECIAL,
	NULL /*dav_rawx_info_open_stream*/,
	NULL /*dav_rawx_info_close_stream*/,
	NULL /*dav_rawx_info_write_stream*/,
	NULL /*dav_rawx_info_seek_stream*/,
	dav_rawx_set_headers_SPECIAL,
	dav_rawx_deliver_SPECIAL,
	NULL /* no collection creation */,
	NULL /* no copy of resources allowed */,
	NULL /* cannot move resources */,
	NULL /*dav_rawx_info_remove_resource*/,
	NULL /* no walk across the chunks */,
	dav_rawx_info_getetag,
	NULL, /* no module context */
#if MODULE_MAGIC_COOKIE == 0x41503234UL /* "AP24" */
	NULL,
	NULL,
#endif
};

const dav_hooks_repository dav_hooks_repository_rawxstat =
{
	1,
	dav_rawx_stat_get_resource,
	dav_rawx_get_parent_resource_SPECIAL,
	dav_rawx_is_same_resource_SPECIAL,
	dav_rawx_is_parent_resource_SPECIAL,
	NULL /*dav_rawx_stat_open_stream*/,
	NULL /*dav_rawx_stat_close_stream*/,
	NULL /*dav_rawx_stat_write_stream*/,
	NULL /*dav_rawx_stat_seek_stream*/,
	dav_rawx_set_headers_SPECIAL,
	dav_rawx_deliver_SPECIAL,
	NULL /* no collection creation */,
	NULL /* no copy of resources allowed */,
	NULL /* cannot move resources */,
	NULL /*dav_rawx_stat_remove_resource*/,
	NULL /* no walk across the chunks */,
	dav_rawx_stat_getetag,
	NULL, /* no module context */
#if MODULE_MAGIC_COOKIE == 0x41503234UL /* "AP24" */
	NULL,
	NULL,
#endif
};
