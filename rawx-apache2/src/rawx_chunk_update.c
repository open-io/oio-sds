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

#include <httpd.h>
#include <http_log.h>
#include <http_config.h>
#include <http_protocol.h>      /* for ap_set_* (in dav_rawx_set_headers) */
#include <http_request.h>       /* for ap_update_mtime() */
#include <mod_dav.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <rawx-lib/src/rawx.h>
#include <rawx-lib/src/compression.h>

#include <glib.h>

#include "mod_dav_rawx.h"
#include "rawx_internals.h"
#include "rawx_config.h"

/* ------------------------------------------------------------------------- */

struct dav_resource_private {
	apr_pool_t *pool;
	const request_rec *request;
	dav_rawx_server_conf *conf;
};

/* ------------------------------------------------------------------------- */

static apr_status_t
apr_hash_table_clean(void *p)
{
	GHashTable *ht = (GHashTable *) p;
	g_hash_table_destroy(ht);
	return APR_SUCCESS;
}

#define STR_KV(Field,Name) apr_psprintf(pool, "rawx."Name" %"G_GUINT64_FORMAT"\n", stats.Field)

static dav_resource*
__get_chunkupdate_resource(const request_rec *r, const dav_hooks_repository *hooks)
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
	resource->info->pool = r->pool;
	resource->info->conf = request_get_server_config(r);
	resource->info->request = r;

	return resource;
}

/*
RAWX{{
GET /update/{CHUNKID}
~~~~~~~~~~~~~~~~~~~~~

Despite the GET verb, this route alters the metadata of the chunk.

.. list-table:: URL tokens
   :header-rows: 1
   :widths: 10 20

   * - Token
     - Description
   * - CHUNKID
     - a string of 64 hexadecimal characters


.. list-table:: Headers
   :header-rows: 1
   :widths: 10 20

   * - Header
     - Description
   * - X-oio-chunk-meta-container-id
     - String of 64 hexadecimal characters
   * - X-oio-chunk-meta-content-path
     - A string
   * - X-oio-chunk-meta-content-id
     - String of hexadecimal characters, usually of 32 characters. The only constraint
       is that the number must be even, to be convertible to a binary form.
   * - X-oio-chunk-meta-content-version
     - A strictly positive integer, less than (2^63). That integer SHOULD match the
       number of bytes of the targeted chunk.
   * - X-oio-chunk-meta-content-storage-policy
     - A string, no check will be performed, at the RAWX level the string might even
       represent a non-existing storage policy
   * - X-oio-chunk-meta-content-chunk-method
     - A string. At the RAWX level no check will be performed and that string
       might even be an invalid chunk-method description.
   * - X-oio-chunk-meta-metachunk-size
     - A null or positive number
   * - X-oio-chunk-meta-metachunk-hash
     - A string of 32 hexadecimal characters
   * - X-oio-chunk-meta-chunk-id
     - A string of 64 hexadecimal characters that must math the CHUNKID present in
       the URL
   * - X-oio-chunk-meta-chunk-size
     - A null or positive integer
   * - X-oio-chunk-meta-chunk-hash
     - A string of 32 hexadecimal characters
   * - X-oio-chunk-meta-chunk-pos
     - Either a positive integer (including 0) or a compound of 2 positive integers
       gathered with a dot.
   * - X-oio-chunk-meta-oio-version
     - A string describing the versin of the headers.
   * - X-oio-chunk-meta-full-path
     - A string representing a complete OpenIO URL


Example
-------

.. code-block:: http

   GET /update/0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF HTTP/1.1
   Content-Length: 0
   X-oio-chunk-meta-container-id: 9006CE70B59E5777D6BB410C57944812EB05FCDB5BA85D520A14B3051D1D094F
   X-oio-chunk-meta-content-path: magic
   X-oio-chunk-meta-content-id: 5835AF8D805E0500AAB7F6808F50900A
   X-oio-chunk-meta-content-version: 1511281109448048
   X-oio-chunk-meta-content-storage-policy: EC
   X-oio-chunk-meta-content-chunk-method: ec/algo=liberasurecode_rs_vand,k=6,m=3
   X-oio-chunk-meta-metachunk-size: 111
   X-oio-chunk-meta-metachunk-hash: 272913026300E7AE9B5E2D51F138E674
   X-oio-chunk-meta-chunk-id: CE456217C7DBAC618A7F0EBFBCDB6C8F184ED8ADCBC6F0B6F493A51EE095D86A
   X-oio-chunk-meta-chunk-size: 100
   X-oio-chunk-meta-chunk-hash: 527EC56D67EF8DA68E3FB93158552272
   X-oio-chunk-meta-chunk-pos: 0.3
   X-oio-chunk-meta-oio-version: 4.0
   X-oio-chunk-meta-full-path: ACCT/JFS/magic/1511281109448048



.. code-block:: http

   HTTP/1.1 200 OK
   Content-Length: 0

}}RAWX
 */
dav_error *
dav_rawx_chunk_update_get_resource(request_rec *r, const char *root_dir, const char *label,
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

	*result_resource = __get_chunkupdate_resource(r, &dav_hooks_repository_chunkupdate);

	return NULL;
}

static dav_error *
dav_rawx_get_parent_resource_SPECIAL(const dav_resource *resource, dav_resource **result_parent)
{
	DAV_XDEBUG_POOL(resource->info->pool, 0, "%s(...)", __FUNCTION__);
	*result_parent = __get_chunkupdate_resource(resource->info->request,
		resource->hooks);
	return NULL;
}

static int
dav_rawx_is_same_resource_SPECIAL(const dav_resource *res1, const dav_resource *res2)
{
	(void) res1;
	(void) res2;

	DAV_XDEBUG_RES(res1, 0, "%s(...)", __FUNCTION__);
	return (res1->type == res2->type) && (res1->hooks == res2->hooks);
}

static int
dav_rawx_is_parent_resource_SPECIAL(const dav_resource *res1, const dav_resource *res2)
{
	DAV_XDEBUG_RES(res1, 0, "%s(...)", __FUNCTION__);
	return dav_rawx_is_same_resource_SPECIAL(res1, res2);
}

static dav_error *
__build_chunk_full_path(const dav_resource *resource, char **full_path)
{

	const request_rec *r = resource->info->request;
	dav_rawx_server_conf *conf = request_get_server_config(r);

	if(strlen(r->uri) < 65)
		return server_create_and_stat_error(request_get_server_config(r), r->pool,
				HTTP_BAD_REQUEST, 0, apr_pstrcat(r->pool, "Cannot parse request uri ", r->uri, NULL));
	char *p = NULL;

	uint i_p = 1;
	uint i_uri = 1;

	p = apr_palloc(r->pool, (65 + 1 + (conf->hash_depth * conf->hash_width) + conf->hash_depth));

	p[0] = '/';

	for (unsigned int i = 0; i < conf->hash_depth ; i++) {
		for (unsigned int j = 0; j < conf->hash_width ; j++)
			p[i_p++] = r->uri[i_uri++];
		p[i_p++] = '/';
	}

	memcpy(p + i_p, r->uri + 1, 64);
	i_p += 64;
	p[i_p] = '\0';

	*full_path = apr_pstrcat(r->pool, conf->docroot, p, NULL);

	return NULL;
}

static dav_error *
_load_request_info(const dav_resource *resource, char **full_path)
{
	dav_error *e = NULL;
	const request_rec *r = resource->info->request;

	/* configure full path */
	e = __build_chunk_full_path(resource, full_path);
	if (NULL != e)
		return e;

	DAV_DEBUG_REQ(r, 0, "Chunk path build from request: %s", *full_path);

	return NULL;
}

static dav_error *
_load_in_place_chunk_info(const dav_resource *r, const char *path, struct chunk_textinfo_s *chunk, GHashTable *comp_opt)
{
	dav_error *e = NULL;
	GError *ge = NULL;
	apr_pool_t *p = r->pool;
	dav_rawx_server_conf *conf = resource_get_server_config(r);

	/* No need to check for the chunk's presence, getting its attributes will
	 * fail if the chunk doesn't exists */
	if (!get_rawx_info_from_file(path, &ge, chunk)) {
		if (NULL != ge) {
			e = server_create_and_stat_error(conf, p, HTTP_CONFLICT, 0,
					apr_pstrcat(p, "Failed to get chunk attributes: ", ge->message, NULL));
			g_clear_error(&ge);
		} else {
			e = server_create_and_stat_error(conf, p, HTTP_CONFLICT, 0,
					"Failed to get chunk chunk attributes: No error specified");
		}
		return e;
	}

	str_replace_by_pooled_str(p, &(chunk->container_id));

	str_replace_by_pooled_str(p, &(chunk->content_id));
	str_replace_by_pooled_str(p, &(chunk->content_path));
	str_replace_by_pooled_str(p, &(chunk->content_version));
	str_replace_by_pooled_str(p, &(chunk->content_size));
	str_replace_by_pooled_str(p, &(chunk->content_chunk_nb));

	str_replace_by_pooled_str(p, &(chunk->content_storage_policy));
	str_replace_by_pooled_str(p, &(chunk->content_chunk_method));
	str_replace_by_pooled_str(p, &(chunk->content_mime_type));

	str_replace_by_pooled_str(p, &(chunk->chunk_id));
	str_replace_by_pooled_str(p, &(chunk->chunk_size));
	str_replace_by_pooled_str(p, &(chunk->chunk_position));
	str_replace_by_pooled_str(p, &(chunk->chunk_hash));

	str_replace_by_pooled_str(p, &(chunk->oio_version));
	str_replace_by_pooled_str(p, &(chunk->oio_full_path));


	if (!get_compression_info_in_attr(path, &ge, comp_opt)){
		if(NULL != ge) {
			e = server_create_and_stat_error(conf, p, HTTP_CONFLICT,
				0, apr_pstrcat(p, "Failed to get chunk compression attributes: ", ge->message, NULL));
			g_clear_error(&ge);
		} else {
			e = server_create_and_stat_error(conf, p, HTTP_CONFLICT,
					0, "Failed to get chunk compression attributes: No error specified");
		}
		return e;
	}

	return NULL;
}


static dav_error *
dav_rawx_deliver_SPECIAL(const dav_resource *resource, ap_filter_t *output)
{
	(void) output;
	dav_error *e = NULL;
	const request_rec *r = resource->info->request;
	GHashTable *comp_opt = NULL;
	struct chunk_textinfo_s *chunk = NULL;
	char *path = NULL;
	apr_pool_t *p = resource->pool;

	/* Load request informations */
	e = _load_request_info(resource, &path);
	if (NULL != e) {
		DAV_ERROR_REQ(r, 0, "Failed to load request informations: %s", e->desc);
		goto end_deliver;
	}

	comp_opt = g_hash_table_new_full( g_str_hash, g_str_equal, g_free, g_free);
	apr_pool_cleanup_register(p, comp_opt, apr_hash_table_clean, apr_pool_cleanup_null);
	chunk = apr_palloc(p, sizeof(struct chunk_textinfo_s));

	/* Load in place informations (sys-metadata & metadatacompress) */
	e = _load_in_place_chunk_info(resource, path, chunk, comp_opt);
	if (NULL != e) {
		DAV_ERROR_REQ(r, 0, "Failed to load in place chunk information: %s", e->desc);
		goto end_deliver;
	}

	DAV_ERROR_REQ(r, 0, "Failed to update chunk storage: PAYMENT REQUIRED"
			" to compress data (we accept bitcoins)");
	dav_rawx_server_conf *conf = resource_get_server_config(resource);
	e = server_create_and_stat_error(conf, p, HTTP_PAYMENT_REQUIRED,
			0, "Pay more to manage compression");

end_deliver:
	/* stats inc */
	return e;
}

static dav_error *
dav_rawx_set_headers_SPECIAL(request_rec *r, const dav_resource *resource)
{
	(void) r;
	(void) resource;
	return NULL;
}

static const char *
dav_rawx_getetag(const dav_resource *resource)
{
	(void) resource;
	return apr_pstrdup(resource->info->request->pool, "chunk-update");
}

const dav_hooks_repository dav_hooks_repository_chunkupdate =
{
	1,
	dav_rawx_chunk_update_get_resource,
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
	dav_rawx_getetag,
	NULL, /* no module context */
#if MODULE_MAGIC_COOKIE == 0x41503234UL /* "AP24" */
	NULL,
	NULL,
#endif
};
