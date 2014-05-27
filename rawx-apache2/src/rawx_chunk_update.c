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
apr_storage_policy_clean(void *p)
{
	struct storage_policy_s *sp = (struct storage_policy_s *) p;
	storage_policy_clean(sp);
	return APR_SUCCESS;
}

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

	for (int i = 0; i < conf->hash_depth ; i++) {
		for (int j = 0; j < conf->hash_width ; j++)
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
_load_request_info(const dav_resource *resource, char **full_path, struct storage_policy_s **sp)
{
	dav_error *e = NULL;
	const request_rec *r = resource->info->request;

	/* configure full path */
	e = __build_chunk_full_path(resource, full_path);
	if (NULL != e)
		return e;

	DAV_DEBUG_REQ(r, 0, "Chunk path build from request: %s", *full_path);
	
	/* init loaded storage policy */
	const char *pol_name = apr_table_get(r->headers_in, "storage-policy");
	if (!pol_name) {
		return server_create_and_stat_error(request_get_server_config(r), r->pool,
				HTTP_BAD_REQUEST, 0, "No storage-policy specified");
	}
	DAV_DEBUG_REQ(r, 0, "Policy found in request: %s", pol_name);

	dav_rawx_server_conf *conf = resource_get_server_config(resource);

	*sp = storage_policy_init(conf->rawx_conf->ni, pol_name);
	apr_pool_cleanup_register(r->pool, *sp, apr_storage_policy_clean, apr_pool_cleanup_null);

	return NULL;
}

static dav_error *
_load_in_place_chunk_info(const dav_resource *r, const char *path, struct content_textinfo_s *content,
		struct chunk_textinfo_s *chunk, GHashTable **comp_opt)
{
	dav_error *e = NULL;
	GError *ge = NULL;
	apr_pool_t *p = r->pool;
	dav_rawx_server_conf *conf = resource_get_server_config(r);
	
	
	apr_finfo_t finfo;

	/* check chunk presence */

	if(APR_SUCCESS != apr_stat(&finfo, path, APR_FINFO_NORM, p)) {
		return server_create_and_stat_error(conf, r->pool, HTTP_NOT_FOUND,
				0, "Chunk file not found");
	}

	if(!get_rawx_info_in_attr(path, &ge,
				content, chunk)) {
		if(NULL != ge) {	
			e = server_create_and_stat_error(conf, p, HTTP_CONFLICT,
				0, apr_pstrcat(p, "Failed to get chunk attributes: ", ge->message, NULL));
			g_clear_error(&ge);
		} else {
			e = server_create_and_stat_error(conf, p, HTTP_CONFLICT,
			                                0, "Failed to get chunk chunk attributes: No error specified");
		}
		return e;
	}

	str_replace_by_pooled_str(p, &(content->path));
	str_replace_by_pooled_str(p, &(content->size));
	str_replace_by_pooled_str(p, &(content->chunk_nb));
	str_replace_by_pooled_str(p, &(content->metadata));
	str_replace_by_pooled_str(p, &(content->system_metadata));
	str_replace_by_pooled_str(p, &(content->container_id));
	str_replace_by_pooled_str(p, &(chunk->id));
	str_replace_by_pooled_str(p, &(chunk->path));
	str_replace_by_pooled_str(p, &(chunk->size));
	str_replace_by_pooled_str(p, &(chunk->hash));
	str_replace_by_pooled_str(p, &(chunk->position));
	str_replace_by_pooled_str(p, &(chunk->metadata));
	str_replace_by_pooled_str(p, &(chunk->container_id));

	if(!get_compression_info_in_attr(path, &ge, comp_opt)){
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

static int
_is_storage_policy_already_applied(const struct data_treatments_s *dt, GHashTable *comp_opt)
{
	const char *c = NULL;

	switch (data_treatments_get_type(dt)) {
		case COMPRESSION:
			c = g_hash_table_lookup(comp_opt, NS_COMPRESSION_OPTION);
			if(NULL != c && g_ascii_strcasecmp(c, NS_COMPRESSION_ON)) {
				/* check algo & bsize */
				const char *pol_algo = NULL;
				const char *pol_bs = NULL;
				const char *current_algo = NULL;
				const char *current_bs = NULL;
				pol_algo = data_treatments_get_param(dt, DT_KEY_ALGO);
				pol_bs = data_treatments_get_param(dt, DT_KEY_BLOCKSIZE);
				current_algo = g_hash_table_lookup(comp_opt, NS_COMPRESS_ALGO_OPTION);
				current_bs = g_hash_table_lookup(comp_opt, NS_COMPRESS_BLOCKSIZE_OPTION);
				if(NULL != pol_algo && NULL != current_algo && 0 == g_ascii_strcasecmp(pol_algo, current_algo)) {
					if(NULL != pol_bs && NULL != current_bs && 0 == g_ascii_strcasecmp(pol_bs, current_bs)) {
						return APR_SUCCESS;
					}
				}
			}
			return 1;
		case DT_NONE:
			c = g_hash_table_lookup(comp_opt, NS_COMPRESSION_OPTION);
			if(!c || 0 == g_ascii_strcasecmp(c, NS_COMPRESSION_OFF)) {
				return APR_SUCCESS;
			}
			return 1;
		default:
			return APR_SUCCESS;	
	}
}

static dav_error *
_update_chunk_storage(const dav_resource *resource, const char *path, const struct data_treatments_s *dt, GHashTable *comp_opt)
{
	GError *e = NULL;
	dav_error *de = NULL;
	const char *c = NULL;
	const request_rec *r = resource->info->request;
	c = g_hash_table_lookup(comp_opt, NS_COMPRESSION_OPTION);
	if(NULL != c && 0 == g_ascii_strcasecmp(c, NS_COMPRESSION_ON)) {
		DAV_DEBUG_REQ(r, 0, "In place chunk is compressed, uncompress it");
		if(1 != uncompress_chunk(path, TRUE, &e)) {
			de = server_create_and_stat_error(request_get_server_config(r),
					r->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
					apr_pstrcat(r->pool, "Failed to uncompress chunk : ",
					((NULL != e)? e->message : "No error specified"), NULL));
			if(NULL != e)
				g_clear_error(&e);
			return de;
		}
		DAV_DEBUG_REQ(r, 0, "Chunk uncompressed");
	}

	if(COMPRESSION == data_treatments_get_type(dt)) {
		DAV_DEBUG_REQ(r, 0, "Re compressing chunk");
		const char *algo = data_treatments_get_param(dt, DT_KEY_ALGO);
		const char *bs = data_treatments_get_param(dt, DT_KEY_BLOCKSIZE);
		if(!algo || !bs) {
			return server_create_and_stat_error(request_get_server_config(r),
					r->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
					apr_pstrcat(r->pool, "Cannot compress chunk, missing info: ",
						algo, "|", bs, NULL));
		}

		if(1 != compress_chunk(path, algo, g_ascii_strtoll(bs, NULL, 10), TRUE, &e)) {
			de = server_create_and_stat_error(request_get_server_config(r),
					r->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
					apr_pstrcat(r->pool, "Failed to compress chunk : ",
						((NULL != e)? e->message : "No error specified"), NULL));
			if(NULL != e)
				g_clear_error(&e);
			return de;
		}
	}

	return NULL;
}

static dav_error *
_ensure_sys_metadata(const dav_resource *resource, const char *path, const char *sp, struct content_textinfo_s *content)
{

	if(!sp) {
		return NULL;
	}

	GError *ge = NULL;
	dav_error *e = NULL;
	int change = 1;

	if(!content->system_metadata) {
		content->system_metadata = apr_pstrcat(resource->pool, "storage-policy=", sp, ";", NULL);
	} else {
		const char *p = NULL;
		if (content->system_metadata)
			p = g_strrstr(content->system_metadata, "storage-policy=");
		if(NULL != p) {
			const char *end = NULL;
			p = p + strlen("storage-policy=");
			end = strchr(p, ';');
			if((strlen(sp) != (size_t)(end - p))
					|| 0 != g_ascii_strncasecmp(sp, p , strlen(sp))) {
				content->system_metadata = apr_pstrndup(resource->pool, content->system_metadata, p - content->system_metadata);
				content->system_metadata = apr_pstrcat(resource->pool, content->system_metadata, sp, end, NULL); 
			} else {
				change = 0;
			}
		} else {
			if(g_str_has_suffix(content->system_metadata, ";")) {
				content->system_metadata = apr_pstrcat(resource->pool, content->system_metadata, "storage-policy=", sp, NULL);
			} else {
				content->system_metadata = apr_pstrcat(resource->pool, content->system_metadata, ";storage-policy=", sp, NULL);
			}
		}
	}
	
	if(change && !set_content_info_in_attr(path, &ge, content)) {
		e = server_create_and_stat_error(resource_get_server_config(resource), resource->pool,
			HTTP_INTERNAL_SERVER_ERROR, 0, apr_pstrcat( resource->pool, "Failed to set chunk xattr : ",
			(NULL != ge) ? ge->message : "No error specified", NULL));
		if(NULL != ge)
			g_clear_error(&ge);
		return e;
	}

	return NULL;
}
	

static dav_error *
dav_rawx_deliver_SPECIAL(const dav_resource *resource, ap_filter_t *output)
{
	(void) output;
	dav_error *e = NULL;
	struct storage_policy_s *sp = NULL;
	const struct data_treatments_s *dt = NULL;
	const request_rec *r = resource->info->request;
	GHashTable *comp_opt = NULL;
	struct content_textinfo_s *content = NULL;
	struct chunk_textinfo_s *chunk = NULL;
	char *path = NULL;
	apr_pool_t *p = resource->pool;
	
	/* Load request informations */
	e = _load_request_info(resource, &path, &sp);
	if (NULL != e) {
		DAV_ERROR_REQ(r, 0, "Failed to load request informations: %s", e->desc);
		goto end_deliver;
	}

	if(!sp) {
		DAV_DEBUG_REQ(r, 0, "Storage policy not initialized with value found in header, don't do anything");
		goto end_deliver;
	}

	dt = storage_policy_get_data_treatments(sp);
	if(!dt)
		DAV_DEBUG_REQ(r, 0, "Data treatments not defined for this policy");

	comp_opt = g_hash_table_new_full( g_str_hash, g_str_equal, g_free, g_free);
	apr_pool_cleanup_register(p, comp_opt, apr_hash_table_clean, apr_pool_cleanup_null);
	chunk = apr_palloc(p, sizeof(struct chunk_textinfo_s));
	content = apr_palloc(p, sizeof(struct content_textinfo_s));

	/* Load in place informations (sys-metadata & metadatacompress) */
	e = _load_in_place_chunk_info(resource, path, content, chunk, &comp_opt);
	if (NULL != e) {
		DAV_ERROR_REQ(r, 0, "Failed to load in place chunk information: %s", e->desc);
		goto end_deliver;
	}

	DAV_DEBUG_REQ(r, 0, "In place chunk info loaded, compression status : %s", (gchar*)g_hash_table_lookup(comp_opt, NS_COMPRESSION_OPTION));

	/* check chunk not in required state */
	if (APR_SUCCESS != _is_storage_policy_already_applied(dt, comp_opt)) {
		DAV_DEBUG_REQ(r, 0, "Storage policy not already applied, apply it!");
		/* operate the data treatments */
		e = _update_chunk_storage(resource, path, dt, comp_opt);
		if (NULL != e) {
			DAV_ERROR_REQ(r, 0, "Failed to update chunk storage: %s", e->desc);
			goto end_deliver;
		}
		DAV_DEBUG_REQ(r, 0, "Chunk storage updated");
	} else {
		DAV_DEBUG_REQ(r, 0, "Storage policy already applied, don't do anything!");
	}


	/* ensure sys-metadata header is valid */
	e = _ensure_sys_metadata(resource, path, storage_policy_get_name(sp), content);
	if (NULL != e) {
		DAV_ERROR_REQ(r, 0, "Failed to ensure sys-metadata, storage-policy possibly not correctly present in xattr: %s", e->desc);
		goto end_deliver;
	}

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
