#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#ifdef APR_HAVE_STDIO_H
#include <stdio.h>              /* for sprintf() */
#endif

#include <unistd.h>
#include <assert.h>
#include <sys/stat.h>

#include <apr.h>
#include <apr_file_io.h>
#include <apr_strings.h>
#include <apr_buckets.h>

#include <apr_general.h>
#include <apr_thread_proc.h>

#include <httpd.h>
#include <http_log.h>
#include <http_config.h>
#include <http_protocol.h>      /* for ap_set_* (in dav_rainx_set_headers) */
#include <http_request.h>       /* for ap_update_mtime() */

#include <mod_dav.h>

// TODO FIXME replace by the APR equivalent
#include <openssl/md5.h>

#include <librain.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <cluster/lib/gridcluster.h>
#include <rawx-lib/src/rawx.h>

#include <glib.h>

#include "mod_dav_rainx.h"
#include "rainx_internals.h"
#include "rainx_repository.h"
#include "rainx_http_tools.h"

/* pull this in from the other source file */
/*extern const dav_hooks_locks dav_hooks_locks_fs; */

/* HERE */

/* Thread */
static apr_status_t rv;
static apr_pool_t *mp;
static apr_thread_mutex_t *mutex;
struct req_params_store** data_put_params; /* List of thread references for data */
/* ------- */

#define POINTER_TO_REQPARAMSSTORE(p) ((struct req_params_store*)p)
#define REQPARAMSSTORE_TO_POINTER(rps) ((void*)rps)

/* forward-declare the hook structures */
static const dav_hooks_repository dav_hooks_repository_rainx;

static const dav_hooks_liveprop dav_hooks_liveprop_rainx;

/*
 ** The namespace URIs that we use. This list and the enumeration must
 ** stay in sync.
 */
static const char * const dav_rainx_namespace_uris[] =
{
	"DAV:",
	"http://apache.org/dav/props/",
	NULL        /* sentinel */
};

enum {
	DAV_FS_URI_DAV,            /* the DAV: namespace URI */
	DAV_FS_URI_MYPROPS         /* the namespace URI for our custom props */
};

static apr_status_t
apr_storage_policy_clean(void *p)
{
	struct storage_policy_s *sp = (struct storage_policy_s *) p;
	storage_policy_clean(sp);
	return APR_SUCCESS;
}

static const dav_liveprop_spec dav_rainx_props[] =
{
	/* standard DAV properties */
	{
		DAV_FS_URI_DAV,
		"creationdate",
		DAV_PROPID_creationdate,
		0
	},
	{
		DAV_FS_URI_DAV,
		"getcontentlength",
		DAV_PROPID_getcontentlength,
		0
	},
	{
		DAV_FS_URI_DAV,
		"getetag",
		DAV_PROPID_getetag,
		0
	},
	{
		DAV_FS_URI_DAV,
		"getlastmodified",
		DAV_PROPID_getlastmodified,
		0
	},

	/* our custom properties */
	{
		DAV_FS_URI_MYPROPS,
		"executable",
		DAV_PROPID_FS_executable,
		0       /* handled special in dav_rainx_is_writable */
	},

	{ 0, 0, 0, 0 }        /* sentinel */
};

static const dav_liveprop_group dav_rainx_liveprop_group =
{
	dav_rainx_props,
	dav_rainx_namespace_uris,
	&dav_hooks_liveprop_rainx
};

static void* APR_THREAD_FUNC
putrawx(apr_thread_t *thd, void* params)
{
	(void)thd;

	struct req_params_store* rps = POINTER_TO_REQPARAMSSTORE(params);

	apr_thread_mutex_lock(mutex);
	rps->req_status = rainx_http_req(rps);
	apr_thread_mutex_unlock(mutex);

	return NULL;
}

static dav_error *
rainx_repo_check_request(request_rec *req, const char *root_dir,
		const char *label, int use_checked_in, dav_resource_private *ctx,
		dav_resource **result_resource)
{

	(void) ctx;
	/* Ensure the chunkid in the URL has the approriated format and
	 * increment the request counters */
	const char *src;

	src = strrchr(req->uri, '/');
	src = src ? src + 1 : req->uri;

	if (0 == apr_strnatcasecmp(src, "info")) {
		return dav_rainx_info_get_resource(req, root_dir, label,
				use_checked_in, result_resource);
	}

	if (0 == apr_strnatcasecmp(src, "stat")) {
		return dav_rainx_stat_get_resource(req, root_dir, label,
				use_checked_in, result_resource);
	}

	return NULL;
}

/* --------------------------------------------------------------------
 **
 ** REPOSITORY HOOK FUNCTIONS
 */

static void
__load_one_header(request_rec *request, apr_uint32_t headers,
		const char *name, char **dst)
{
	const char *value;

	*dst = NULL;

	if (headers & HEADER_SCHEME_V2) {
		char new_name[strlen(name) + sizeof(HEADER_PREFIX_GRID)];
		g_snprintf(new_name, sizeof(new_name), HEADER_PREFIX_GRID"%s", name);
		if (NULL != (value = apr_table_get(request->headers_in, new_name))) {
			*dst = apr_pstrdup(request->pool, value);
			DAV_XDEBUG_REQ(request, 0, "Header found [%s]:[%s]", new_name, *dst);
		}
	}

	if (!(*dst) && (headers & HEADER_SCHEME_V1)) {
		if (NULL != (value = apr_table_get(request->headers_in, name))) {
			*dst = apr_pstrdup(request->pool, value);
			DAV_XDEBUG_REQ(request, 0, "Header found [%s]:[%s]", name, *dst);
		}
	}
}

static void
request_load_chunk_info(request_rec *request, dav_resource *resource)
{
	dav_rainx_server_conf *conf = ap_get_module_config(
			resource->info->request->server->module_config, &dav_rainx_module);

	/* These headers are used by the Integrity loop */
	LOAD_HEADER(content, path,            "content_path");
	LOAD_HEADER(content, size,            "content_size");
	LOAD_HEADER(content, chunk_nb,        "content_chunksnb");
	LOAD_HEADER(content, metadata,        "content_metadata");
	LOAD_HEADER(content, system_metadata, "content_metadata-sys");
	LOAD_HEADER(content, container_id,    "content_containerid");

	LOAD_HEADER(chunk, id,           "chunk_id");
	LOAD_HEADER(chunk, path,         "chunk_path");
	LOAD_HEADER(chunk, size,         "chunk_size");
	LOAD_HEADER(chunk, hash,         "chunk_hash");
	LOAD_HEADER(chunk, position,     "chunk_position");
	LOAD_HEADER(chunk, metadata,     "chunk_metadata");
	LOAD_HEADER(chunk, container_id, "chunk_containerid");

	if (conf->headers_scheme & HEADER_SCHEME_V1) {
		/* There are the headers used by the common client.
		 * This is an ugly clue of history and entropy */
		LOAD_HEADER(chunk, id,           "chunkid");
		LOAD_HEADER(chunk, path,         "contentpath");
		LOAD_HEADER(chunk, size,         "chunksize");
		LOAD_HEADER(chunk, hash,         "chunkhash");
		LOAD_HEADER(chunk, position,     "chunkpos");
		LOAD_HEADER(chunk, metadata,     "chunkmetadata");
		LOAD_HEADER(chunk, container_id, "containerid");

		LOAD_HEADER(content, path,            "contentpath");
		LOAD_HEADER(content, size,            "contentsize");
		LOAD_HEADER(content, chunk_nb,        "chunknb");
		LOAD_HEADER(content, metadata,        "contentmetadata");
		LOAD_HEADER(content, system_metadata, "contentmetadata-sys");
		LOAD_HEADER(content, container_id,    "containerid");
		LOAD_HEADER(content, storage_policy,    "storagepolicy");
		LOAD_HEADER(content, rawx_list, "rawxlist");
		LOAD_HEADER(content, spare_rawx_list, "sparerawxlist");
	}

	resource->info->namespace = apr_pstrdup(request->pool, conf->ns_name);
	__load_one_header(request, conf->headers_scheme,
			"namespace", &(resource->info->namespace));
}

static dav_error *
dav_rainx_get_resource(request_rec *r, const char *root_dir, const char *label,
		int use_checked_in, dav_resource **result_resource)
{
	dav_resource_private ctx;
	dav_resource *resource;
	dav_rainx_server_conf *conf;
	dav_error *e = NULL;

	*result_resource = NULL;

	(void) use_checked_in;/* No way, we do not support versioning */
	conf = request_get_server_config(r);

	/* ACL */
	/* Check if client allowed to work with us */
	if (conf->enabled_acl) {
#if MODULE_MAGIC_COOKIE == 0x41503234UL /* "AP24" */
		if (!authorized_personal_only(r->connection->client_ip,
				conf->rainx_conf->acl))
#else
		if (!authorized_personal_only(r->connection->remote_ip,
				conf->rainx_conf->acl))
#endif
		{
			return server_create_and_stat_error(conf, r->pool,
					HTTP_UNAUTHORIZED, 0, "Permission Denied (APO)");
		}
	}

	/* Create private resource context descriptor */
	memset(&ctx, 0x00, sizeof(ctx));
	ctx.pool = r->pool;
	ctx.request = r;
	ctx.on_the_fly = g_str_has_prefix(r->uri, "/on-the-fly");

	e = rainx_repo_check_request(r, root_dir, label, use_checked_in,
			&ctx, result_resource);
	/* Return in case we have an error or if result_resource != null
	 * because it was an info request */
	if (NULL != e || NULL != *result_resource) {
		return e;
	}

	/* All the checks on the URL have been passed, now build a resource */

	resource = apr_pcalloc(r->pool, sizeof(*resource));
	resource->exists = 1;
	resource->collection = 0;
	resource->type = DAV_RESOURCE_TYPE_REGULAR;
	resource->info = apr_pcalloc(r->pool, sizeof(ctx));;
	memcpy(resource->info, &ctx, sizeof(ctx));
	resource->hooks = &dav_hooks_repository_rainx;
	resource->pool = r->pool;

	request_load_chunk_info(r, resource);

	/* Check META-Chunk size not larger than namespace allowed chunk-size */
	gint64 ns_chunk_size = namespace_chunk_size(conf->rainx_conf->ni,
				resource->info->namespace);
	gint64 subchunk_size = apr_atoi64(resource->info->chunk.size);
	if (r->method_number == M_PUT && ns_chunk_size < subchunk_size) {
		return server_create_and_stat_error(conf, r->pool, HTTP_BAD_REQUEST, 0,
				"Metachunk size exceeds namespace chunk size");
	}


	*result_resource = resource;

	return NULL;
}

static dav_error *
dav_rainx_get_parent_resource(const dav_resource *resource,
		dav_resource **result_parent)
{
	apr_pool_t *pool;
	dav_resource *parent;

	(void) resource;
	(void) result_parent;
	pool = resource->pool;

	DAV_XDEBUG_RES(resource, 0, "%s", __FUNCTION__);

	/* Build a fake root */
	parent = apr_pcalloc(resource->pool, sizeof(*resource));
	parent->exists = 1;
	parent->collection = 1;
	parent->uri = "/";
	parent->type = DAV_RESOURCE_TYPE_WORKING;
	parent->info = NULL;
	parent->hooks = &dav_hooks_repository_rainx;
	parent->pool = pool;

	*result_parent = parent;
	return NULL;
}

static int
dav_rainx_is_same_resource(const dav_resource *res1, const dav_resource *res2)
{
	(void) res1;
	(void) res2;

	DAV_XDEBUG_RES(res1, 0, "%s", __FUNCTION__);

	/* TODO */
	return 0;
}

static int
dav_rainx_is_parent_resource(const dav_resource *res1, const dav_resource *res2)
{
	(void) res1;
	(void) res2;

	DAV_XDEBUG_RES(res1, 0, "%s", __FUNCTION__);

	return 0;
}

static dav_error *
compute_subchunk_size(const dav_resource *resource, int k, int m,
		const char *algo, int *metachunk_size, int *subchunk_size)
{
	int sc_size = -1;
	apr_int64_t mc_size = -1;
	errno = 0;
	if (resource->info->chunk.size == NULL ||
			(mc_size = apr_atoi64(resource->info->chunk.size)) <= 0 ||
			errno != 0) {
		DAV_DEBUG_REQ(resource->info->request, 0 , "Bad chunk size parameter");
		return server_create_and_stat_error(
				resource_get_server_config(resource),
				resource_get_pool(resource),
				HTTP_BAD_REQUEST, 0, "Bad chunk size parameter");
	}

	sc_size = get_chunk_size(mc_size, k, m, algo);
	if (sc_size <= 0) {
		DAV_DEBUG_REQ(resource->info->request, 0 ,
				"failed to calculate the size of subchunks");
		return server_create_and_stat_error(
				resource_get_server_config(resource),
				resource_get_pool(resource),
				HTTP_INTERNAL_SERVER_ERROR, 0,
				"Rain operation failed on subchunk size calculation");
	}
	*metachunk_size = mc_size;
	*subchunk_size = sc_size;

	return NULL;
}

static dav_error *
rainx_repo_stream_create(const dav_resource *resource, dav_stream **result)
{
	int metachunk_size;
	int subchunk_size;
	dav_error *e = NULL;

	DAV_DEBUG_REQ(resource->info->request, 0, "%s", __FUNCTION__);

	/* Build the stream */
	apr_pool_t *p = resource->info->pool;
	dav_stream *ds = apr_pcalloc(p, sizeof(*ds));

	ds->p = p;
	ds->r = resource;
	/* ------- */

	dav_rainx_server_conf *conf = ap_get_module_config(
			resource->info->request->server->module_config,
			&dav_rainx_module);

	/* Storage policy management */
	/* Getting policy parameters (k, m, algo) */
	char* str = resource->info->content.storage_policy;
	struct storage_policy_s *sp = NULL;
	if (!str || !(sp = storage_policy_init(conf->rainx_conf->ni, str))) {
		DAV_DEBUG_REQ(resource->info->request, 0 ,
				"\"%s\" policy init failed for namespace \"%s\"",
				str, conf->rainx_conf->ni->name);
		return server_create_and_stat_error(conf, p, HTTP_BAD_REQUEST, 0,
				"Bad policy parameter");
	}

	apr_pool_cleanup_register(p, sp,
			apr_storage_policy_clean, apr_pool_cleanup_null);

	DAV_DEBUG_REQ(resource->info->request, 0 ,
			"\"%s\" policy init succeeded for namespace \"%s\"",
			str, conf->rainx_conf->ni->name);

	const struct data_security_s *datasec = storage_policy_get_data_security(sp);
	if (RAIN != data_security_get_type(datasec)) {
		DAV_DEBUG_REQ(resource->info->request, 0 ,
				"the data security type for the policy '%s' is not rain", str);
		return server_create_and_stat_error(conf, p, HTTP_INTERNAL_SERVER_ERROR,
				0, "Bad data security type (not rain)");
	}

	const char* k = NULL;
	const char* m = NULL;

	if ((NULL == (k = data_security_get_param(datasec, "k")))
			|| (NULL == (m = data_security_get_param(datasec, "m")))
			|| (NULL == (resource->info->algo =
					data_security_get_param(datasec, "algo")))) {
		DAV_DEBUG_REQ(resource->info->request, 0 ,
				"Failed to get all the \"%s\" policy parameters", str);
		return server_create_and_stat_error(conf, p, HTTP_INTERNAL_SERVER_ERROR,
				0, "Rain operation failed on loading policy");
	}

	if (0 >= (resource->info->k = strtol(k, NULL, 10))) {
		DAV_DEBUG_REQ(resource->info->request, 0 ,
				"bad \"%s\" policy 'k' parameter value", str);
		return server_create_and_stat_error(conf, p,
				HTTP_INTERNAL_SERVER_ERROR, 0,
				"Rain operation failed on loading policy");
	}

	if (0 >= (resource->info->m = strtol(m, NULL, 10))) {
		DAV_DEBUG_REQ(resource->info->request, 0 ,
				"bad \"%s\" policy 'm' parameter value", str);
		return server_create_and_stat_error(conf, p,
				HTTP_INTERNAL_SERVER_ERROR, 0,
				"Rain operation failed on loading policy");
	}

	DAV_DEBUG_REQ(resource->info->request, 0 ,
			"\"%s\" policy parameters are : k = %d, m = %d, algo = %s",
			str, resource->info->k, resource->info->m, resource->info->algo);
	/* ------- */

	/* Calculating subchunk size */
	e = compute_subchunk_size(resource, resource->info->k, resource->info->m,
			resource->info->algo, &metachunk_size, &subchunk_size);
	if (e)
		return e;
	resource->info->subchunk_size = subchunk_size;
	DAV_DEBUG_REQ(resource->info->request, 0, "calculated chunk size is %d bytes",
			resource->info->subchunk_size);
	/* ------- */

	/* Creating data buffer and infos */
	ds->original_data_size = metachunk_size;
	ds->original_data = apr_pcalloc(p, metachunk_size * sizeof(char));
	ds->original_data_chunk_start_ptr = ds->original_data;
	ds->original_data_chunk_end_ptr = ds->original_data;
	ds->original_data_stored = 0;
	/* ------ */

	/* Setting metachunk info */
	resource->info->current_rawx = 0;
	resource->info->current_chunk_remaining = subchunk_size;
	/* ------- */

	/* Getting the rawx addresses */
	char* rawx_list = resource->info->content.rawx_list;
	if (NULL == rawx_list) {
		DAV_DEBUG_REQ(resource->info->request, 0 , "rawx list is null");
		return server_create_and_stat_error(conf, p, HTTP_BAD_REQUEST,
				0, "Bad rawx list parameter");
	}
	resource->info->rawx_list = (char**)apr_pcalloc(p,
			(resource->info->k + resource->info->m) * sizeof(char*));
	char* last;
	// FIXME: this should be separated by ';', not '|'
	char* temp_tok = apr_strtok(rawx_list, RAWXLIST_SEPARATOR, &last);
	int i;
	for (i = 0; temp_tok && i < resource->info->k + resource->info->m; i++) {
		resource->info->rawx_list[i] = temp_tok;
		temp_tok = apr_strtok(NULL, RAWXLIST_SEPARATOR, &last);
	}
	if (i != resource->info->k + resource->info->m) {
		DAV_DEBUG_REQ(resource->info->request, 0 ,
				"missing one or more rawx address(es)");
		return server_create_and_stat_error(conf, p, HTTP_BAD_REQUEST,
				0, "Missing one or more rawx address(es)");
	}
	/* ------- */

	resource->info->response_chunk_list = NULL;

	MD5_Init(&(ds->md5_ctx));
	*result = ds;

	return NULL;
}

static dav_error *
dav_rainx_open_stream(const dav_resource *resource, dav_stream_mode mode,
		dav_stream **stream)
{
	dav_stream *ds = NULL;
	dav_error *e = NULL;

	(void) mode;

	DAV_DEBUG_REQ(resource->info->request, 0, "%s", __FUNCTION__);

	e = rainx_repo_stream_create(resource, &ds);
	if (NULL != e) {
		DAV_DEBUG_REQ(resource->info->request, 0,
				"Dav stream initialization failure");

		return e;
	}

	*stream = ds;

	/* Thread */
	apr_initialize();
	apr_pool_create(&mp, NULL);

	apr_thread_mutex_create(&mutex, APR_THREAD_MUTEX_UNNESTED, mp);

	data_put_params = (struct req_params_store**)apr_pcalloc(
			resource->info->request->pool,
			resource->info->k * sizeof(struct req_params_store*));
	/* ------- */

	return NULL;
}

static gboolean
do_rollback_specific(dav_stream *stream, char* rawx_address)
{
	char* reply = apr_pcalloc(stream->r->info->request->pool,
			MAX_REPLY_HEADER_SIZE + REPLY_BUFFER_SIZE);
	struct req_params_store rps;
	memset(&rps, 0, sizeof(rps));
	rps.pool = stream->r->info->request->pool;
	rps.reply = reply;
	rps.req_type = "DELETE";
	rps.resource = stream->r;
	rps.service_address = rawx_address;
	rainx_http_req(&rps);
	if (strlen(reply) < 12 || !g_str_has_prefix(reply, "HTTP/1.1 20"))
		return TRUE;

	return FALSE;
}

static void
do_rollback(dav_stream *stream)
{
	for (int i = 0; i < stream->r->info->k + stream->r->info->m; i++)
		do_rollback_specific(stream, stream->r->info->rawx_list[i]);
}

static gboolean
extract_code_message_reply(const dav_resource* resource, char* reply,
		char** code, char** message)
{
	if (!resource || !reply || !code || !message || strlen(reply) < 12)
		return FALSE;

	char* temp_reply = apr_pstrdup(resource->info->request->pool, reply);

	/* Isolating the first line */
	char* last;
	char* reply_tok = NULL;
	reply_tok = apr_strtok(temp_reply, "\r\n", &last);
	if (!reply_tok)
		return FALSE;
	/* ------- */

	/* Isolating the HTTP version */
	char* last2;
	char* reply_tok2 = apr_strtok(reply_tok, " ", &last2);
	if (!reply_tok2 || apr_strnatcmp(reply_tok2, "HTTP/1.1"))
		return FALSE;
	/* ------- */

	/* Isolating the returned code */
	reply_tok2 = apr_strtok(NULL, " ", &last2);
	if (!reply_tok2)
		return FALSE;
	memcpy(*code, reply_tok2, (int)strlen(reply_tok2));
	/* ------- */

	/* Isolating the returned message */
	reply_tok2 = apr_strtok(NULL, " ", &last2);
	if (!reply_tok2)
		return FALSE;
	memcpy(*message, reply_tok2, (int)strlen(reply_tok2));
	/* ------- */

	return TRUE;
}

static void
update_response_list(dav_stream *stream, char* rawx_entry,
		int stored_size, char* md5_digest)
{
	// FIXME: this should be separated by ';', not '|'
	char* response_entry = apr_psprintf(stream->r->info->request->pool,
			"%s%s%d%s%s", rawx_entry, RAWXLIST_SEPARATOR, stored_size,
			RAWXLIST_SEPARATOR, md5_digest);
	if (NULL == stream->r->info->response_chunk_list)
		stream->r->info->response_chunk_list = response_entry;
	else
		stream->r->info->response_chunk_list = apr_psprintf(
				stream->r->info->request->pool, "%s%s%s",
				stream->r->info->response_chunk_list,
				RAWXLIST_SEPARATOR2, response_entry);
}

static dav_error *
dav_rainx_close_stream(dav_stream *stream, int commit)
{
	dav_error *e = NULL;
	int i;
	char* custom_chunkid = NULL;
	char* custom_chunkpos = NULL;
	char* custom_chunksize = NULL;
	char* custom_chunkhash = NULL;
	char** coding_metachunks = NULL;
	struct req_params_store** coding_put_params = NULL;
	apr_pool_t **coding_subpools = NULL;

	DAV_DEBUG_REQ(stream->r->info->request, 0, "Closing (%s) the stream",
			(commit ? "commit" : "rollback"));

	dav_rainx_server_conf *conf = ap_get_module_config(
			stream->r->info->request->server->module_config, &dav_rainx_module);

	if (!commit) {
		e = server_create_and_stat_error(conf, stream->p,
				HTTP_INTERNAL_SERVER_ERROR, 0, "Rain operation failed");
		goto close_stream_error_label;
	} else {
		int subchunk_size = stream->r->info->subchunk_size;

		/* Preparing custom header */
		struct content_textinfo_s temp_content = stream->r->info->content;
		struct chunk_textinfo_s temp_chunk = stream->r->info->chunk;
		char* custom_header = apr_psprintf(stream->r->info->request->pool,
				"containerid: %s\nchunknb: %s\ncontentpath: %s\ncontentsize: %s",
				temp_content.container_id, temp_content.chunk_nb,
				temp_content.path, temp_content.size);
		if (temp_content.metadata)
			custom_header = apr_psprintf(stream->r->info->request->pool,
					"%s\ncontentmetadata: %s", custom_header,
					temp_content.metadata);
		if (temp_content.system_metadata)
            custom_header = apr_psprintf(stream->r->info->request->pool,
					"%s\ncontentmetadata-sys: %s", custom_header,
					temp_content.system_metadata);
		/* ------- */

		/* Finalizing custom header */
		int startid = strlen(
				stream->r->info->rawx_list[stream->r->info->current_rawx]) - 64;
		custom_chunkid = apr_pstrdup(stream->r->info->request->pool,
				stream->r->info->rawx_list[stream->r->info->current_rawx]
				+ startid);
		custom_chunkpos = apr_psprintf(stream->r->info->request->pool,
				"%s.%d", temp_chunk.position, stream->r->info->current_rawx);
		custom_chunksize = apr_itoa(stream->r->info->request->pool,
				subchunk_size - stream->r->info->current_chunk_remaining);
		custom_chunkhash = g_compute_checksum_for_string(G_CHECKSUM_MD5,
				stream->original_data_chunk_start_ptr,
				subchunk_size - stream->r->info->current_chunk_remaining);
		/* ------- */

		apr_pool_t *subpool = NULL;
		apr_pool_create(&subpool, mp);
		/* Flushing the last data metachunk (without the padding) */
		if (stream->original_data_stored > stream->original_data_size) {
			// FIXME: what?
			DAV_DEBUG_REQ(stream->r->info->request,
					0, "request entity too large");
			e = server_create_and_stat_error(conf, stream->p,
					HTTP_BAD_REQUEST, 0, "Request entity too large");
			goto close_stream_error_label;
		}

		if (subchunk_size - stream->r->info->current_chunk_remaining > 0) {
			/* Initializing the PUT params structure */
			i = stream->r->info->current_rawx;
			data_put_params[i] = (struct req_params_store*)apr_pcalloc(
					subpool, sizeof(struct req_params_store));
			data_put_params[i]->service_address = \
					stream->r->info->rawx_list[stream->r->info->current_rawx];
			data_put_params[i]->data_to_send = \
					stream->original_data_chunk_start_ptr;
			data_put_params[i]->data_to_send_size = \
					subchunk_size - stream->r->info->current_chunk_remaining;
			data_put_params[i]->header = apr_psprintf(subpool,
					"%s\nchunkid: %s\nchunkpos: %s\nchunksize: %s\nchunkhash: %s",
					custom_header, custom_chunkid, custom_chunkpos,
					custom_chunksize, custom_chunkhash);
			data_put_params[i]->req_type = "PUT";
			data_put_params[i]->reply = apr_pcalloc(subpool,
					MAX_REPLY_HEADER_SIZE + REPLY_BUFFER_SIZE);
			data_put_params[i]->resource = stream->r;
			/* APR_SUCCESS will set it to 0 */
			data_put_params[i]->req_status = INIT_REQ_STATUS;
			data_put_params[i]->pool = subpool;
			/* ------- */

			/* Launching the PUT thread */
			apr_threadattr_create(&(data_put_params[i]->thd_attr), subpool);
			rv = apr_thread_create(&(data_put_params[i]->thd_arr),
					data_put_params[i]->thd_attr, putrawx,
					REQPARAMSSTORE_TO_POINTER(data_put_params[i]), subpool);
			assert(rv == APR_SUCCESS);
			/* ------- */

			update_response_list(stream,
					stream->r->info->rawx_list[stream->r->info->current_rawx],
					subchunk_size - stream->r->info->current_chunk_remaining,
					custom_chunkhash);
		}

		g_free(custom_chunkhash);
		custom_chunkhash = NULL;
		/* ------- */

		/* Managing the end of put data threads */
		for (i = 0; i < stream->r->info->k; i++) {
			if (data_put_params[i] && data_put_params[i]->thd_arr) {
				apr_thread_join(&rv, data_put_params[i]->thd_arr);
				assert(rv == APR_SUCCESS);
			}
		}

		apr_pool_destroy(subpool);
		subpool = NULL;
		/* ------- */

		/* Error management */
		char* reply_code = apr_pcalloc(stream->r->info->request->pool, 4);
		char* reply_message = apr_pcalloc(stream->r->info->request->pool,
				MAX_REPLY_MESSAGE_SIZE);
		char apr_error_message[256];
		for (i = 0; i < stream->r->info->k; i++) {
			if (data_put_params[i] == NULL) {
				DAV_DEBUG_REQ(stream->r->info->request, 0,
						"Nothing to put on rawx %d", i);
			} else if (data_put_params[i]->req_status != APR_SUCCESS) {
				apr_strerror(data_put_params[i]->req_status, apr_error_message, sizeof(apr_error_message));
				if (!extract_code_message_reply(stream->r,
						data_put_params[i]->reply,
						&reply_code, &reply_message)) {
					DAV_DEBUG_REQ(stream->r->info->request, 0,
							"error while putting the data to the rawx %d: (%d: %s) %s",
							i, data_put_params[i]->req_status,
							apr_error_message,
							data_put_params[i]->reply);
					e = server_create_and_stat_error(conf, stream->p,
							(data_put_params[i]->req_status == APR_TIMEUP ?
							 HTTP_GATEWAY_TIME_OUT : HTTP_INTERNAL_SERVER_ERROR), 0,
							"Rain operation failed on put "
							"(and was unable to extract error message)");
					goto close_stream_error_label;
				}
				if (!g_str_has_prefix(reply_code, "20")) {
					DAV_DEBUG_REQ(stream->r->info->request, 0,
							"error while putting the data to the rawx %d: (%d:%s) '%s'",
							i, data_put_params[i]->req_status,
							apr_error_message,
							data_put_params[i]->reply);
					e = server_create_and_stat_error(conf, stream->p,
							atoi(reply_code), 0, reply_message);
					goto close_stream_error_label;
				}
			} else {
				DAV_DEBUG_REQ(stream->r->info->request, 0, "rawx %d filled", i);
			}
		}
		/* ------- */

		/* Rain calculation */
		stream->r->info->current_rawx = stream->r->info->k; /* Set there to rollback correctly in case of error */
		if (!(coding_metachunks = rain_get_coding_chunks(stream->original_data,
					stream->original_data_size, stream->r->info->k,
					stream->r->info->m, stream->r->info->algo))) {
			DAV_DEBUG_REQ(stream->r->info->request, 0,
					"failed to calculate coding chunks");
			e = server_create_and_stat_error(conf, stream->p,
					HTTP_INTERNAL_SERVER_ERROR, 0,
					"Coding chunks calculation failed");
			goto close_stream_error_label;
		} else {
			DAV_DEBUG_REQ(stream->r->info->request, 0,
					"coding metachunks calculation succeeded");

			/* List of thread references */
			coding_put_params = (struct req_params_store**)apr_pcalloc(
					stream->r->info->request->pool,
					stream->r->info->m * sizeof(struct req_params_store*));
			coding_subpools = (apr_pool_t**) apr_pcalloc(
					stream->r->info->request->pool,
					stream->r->info->m * sizeof(apr_pool_t*));
			/* ------- */

			/* Filling the stream->r->info->m coding metachunks */
			for (i = 0; i < stream->r->info->m; i++) {
				/* Set there to rollback correctly in case of error */
				stream->r->info->current_rawx = stream->r->info->k + i;

				/* Finalizing custom header values */
				startid = strlen(stream->r->info->rawx_list[stream->r->info->current_rawx]) - 64;
				custom_chunkid = apr_pstrdup(stream->r->info->request->pool,
						stream->r->info->rawx_list[stream->r->info->current_rawx]
						+ startid);
				custom_chunkpos = apr_psprintf(stream->r->info->request->pool,
						"%s.p%d", temp_chunk.position,
						stream->r->info->current_rawx - stream->r->info->k);
				custom_chunksize = apr_itoa(stream->r->info->request->pool,
						subchunk_size);
				custom_chunkhash = g_compute_checksum_for_string(G_CHECKSUM_MD5,
						coding_metachunks[i], subchunk_size);
				apr_pool_create(&(coding_subpools[i]), mp);
				/* ------- */

				/* Initializing the PUT params structure */
				coding_put_params[i] = (struct req_params_store*)apr_pcalloc(
						coding_subpools[i], sizeof(struct req_params_store));
                coding_put_params[i]->service_address = \
						stream->r->info->rawx_list[stream->r->info->current_rawx];
                coding_put_params[i]->data_to_send = coding_metachunks[i];
                coding_put_params[i]->data_to_send_size = subchunk_size;
				coding_put_params[i]->header = apr_psprintf(coding_subpools[i],
						"%s\nchunkid: %s\nchunkpos: %s\nchunksize: %s\nchunkhash: %s",
						custom_header, custom_chunkid, custom_chunkpos,
						custom_chunksize, custom_chunkhash);
                coding_put_params[i]->req_type = "PUT";
                coding_put_params[i]->reply = apr_pcalloc(coding_subpools[i],
						MAX_REPLY_HEADER_SIZE + REPLY_BUFFER_SIZE);
				coding_put_params[i]->resource = stream->r;
				/* APR_SUCCESS will set it to 0 */
				coding_put_params[i]->req_status = INIT_REQ_STATUS;
				coding_put_params[i]->pool = coding_subpools[i];
				/* ------- */

				/* Launching the PUT thread */
				apr_threadattr_create(&(coding_put_params[i]->thd_attr),
						coding_subpools[i]);
				rv = apr_thread_create(&(coding_put_params[i]->thd_arr),
						coding_put_params[i]->thd_attr, putrawx,
						REQPARAMSSTORE_TO_POINTER(coding_put_params[i]),
						coding_subpools[i]);
				assert(rv == APR_SUCCESS);
				/* ------- */

				update_response_list(stream,
						stream->r->info->rawx_list[stream->r->info->current_rawx],
						subchunk_size, custom_chunkhash);

				g_free(custom_chunkhash);
				custom_chunkhash = NULL;
			}

			for (i = 0; i < stream->r->info->m; i++) {
				rv = apr_thread_join(&rv, coding_put_params[i]->thd_arr);
				assert(rv == APR_SUCCESS);
			}
			/* ------- */

			/* Error management */
			for (i = 0; i < stream->r->info->m; i++) {
				if (coding_put_params[i]->req_status != APR_SUCCESS) {
					if (!extract_code_message_reply(stream->r,
							coding_put_params[i]->reply,
							&reply_code, &reply_message)) {
						DAV_DEBUG_REQ(stream->r->info->request, 0,
								"error while putting the coding to the rawx %d: (%d) %s",
								i, coding_put_params[i]->req_status,
								coding_put_params[i]->reply);
						e = server_create_and_stat_error(conf, stream->p,
								HTTP_INTERNAL_SERVER_ERROR, 0,
								"Rain operation failed on put");
						goto close_stream_error_label;
					}
					if (!g_str_has_prefix(reply_code, "20")) {
						DAV_DEBUG_REQ(stream->r->info->request, 0,
								"error while putting the coding to the rawx %d: (%d) %s",
								i, coding_put_params[i]->req_status,
								coding_put_params[i]->reply);
						e = server_create_and_stat_error(conf, stream->p,
								atoi(reply_code), 0, reply_message);
						goto close_stream_error_label;
					}
				}
				else
					DAV_DEBUG_REQ(stream->r->info->request, 0,
							"coding rawx %d filled", i);
			}
			/* ------- */
		}
		/* ------- */
	}
	/* ------- */

	/* Adding the list of actually stored metachunks
	 * (ip:port/chunk_id|stored_size|md5_digest;...)
	 * in the response header to the client */
	apr_table_setn(stream->r->info->request->headers_out,
			apr_pstrdup(stream->r->info->request->pool, "chunklist"),
			stream->r->info->response_chunk_list);
	/* ------- */

	/* stats update */
	server_inc_request_stat(resource_get_server_config(stream->r),
			RAWX_STATNAME_REQ_CHUNKPUT,
			request_get_duration(stream->r->info->request));

close_stream_error_label:
	if (e)
		do_rollback(stream);
	g_free(custom_chunkhash);
	if (coding_metachunks) {
		for (i = 0; i < stream->r->info->m; i++)
			g_free(coding_metachunks[i]);
		g_free(coding_metachunks);
	}
	if (coding_subpools) {
		for (i = 0; i < stream->r->info->m; i++)
			apr_pool_destroy(coding_subpools[i]);
	}
	apr_terminate();
	apr_thread_mutex_destroy(mutex);
	apr_pool_destroy(mp);
	return e;
}

static dav_error *
dav_rainx_write_stream(dav_stream *stream, const void *buf, apr_size_t bufsize)
{
	(void) buf;

	dav_rainx_server_conf *conf = ap_get_module_config(
			stream->r->info->request->server->module_config, &dav_rainx_module);

	apr_pool_t **data_subpools = NULL;

	if (stream->original_data_stored + (int)bufsize > stream->original_data_size) {
		/* Rollback */
		DAV_DEBUG_REQ(stream->r->info->request, 0, "request entity too large");
		return server_create_and_stat_error(conf, stream->p,
				HTTP_BAD_REQUEST, 0, "Request entity too large");
	}

	int subchunk_size = stream->r->info->subchunk_size;

	/* Buf management */
	int to_read = bufsize;
	char* buf_ptr = (char*)buf;
	/* ------- */

	/* Preparing custom header */
	struct content_textinfo_s temp_content = stream->r->info->content;
	struct chunk_textinfo_s temp_chunk = stream->r->info->chunk;
	char* custom_header = apr_psprintf(stream->r->info->request->pool,
			"containerid: %s\nchunknb: %s\ncontentpath: %s\ncontentsize: %s",
			temp_content.container_id, temp_content.chunk_nb,
			temp_content.path, temp_content.size);
	if (temp_content.metadata)
		custom_header = apr_psprintf(stream->r->info->request->pool,
				"%s\ncontentmetadata: %s", custom_header, temp_content.metadata);
	if (temp_content.system_metadata)
		custom_header = apr_psprintf(stream->r->info->request->pool,
				"%s\ncontentmetadata-sys: %s", custom_header,
				temp_content.system_metadata);
	/* ------- */

	data_subpools = (apr_pool_t**) apr_pcalloc(stream->r->info->request->pool,
			stream->r->info->k * sizeof(apr_pool_t*));

	/* While buf is not completely read */
	while (to_read > 0) {
		if (stream->r->info->current_chunk_remaining < to_read) {
			memcpy(stream->original_data_chunk_end_ptr, buf_ptr,
					stream->r->info->current_chunk_remaining);

			/* Updating buf state */
			buf_ptr += stream->r->info->current_chunk_remaining;
			to_read -= stream->r->info->current_chunk_remaining;

			stream->original_data_chunk_end_ptr += \
					stream->r->info->current_chunk_remaining;
			stream->original_data_stored += \
					stream->r->info->current_chunk_remaining;
			/* ------- */

			/* Finalizing custom header */
			int startid = strlen(
					stream->r->info->rawx_list[stream->r->info->current_rawx]) - 64;
			char* custom_chunkid = apr_pstrdup(stream->r->info->request->pool,
					stream->r->info->rawx_list[stream->r->info->current_rawx]
					+ startid);
			char* custom_chunkpos = apr_psprintf(stream->r->info->request->pool,
					"%s.%d", temp_chunk.position, stream->r->info->current_rawx);
			char* custom_chunksize = apr_itoa(stream->r->info->request->pool,
					subchunk_size);
			char* custom_chunkhash = g_compute_checksum_for_string(
					G_CHECKSUM_MD5, stream->original_data_chunk_start_ptr,
					subchunk_size);
			/* ------- */

			/* Initializing the PUT params structure */
			int i = stream->r->info->current_rawx;
			apr_pool_create(&(data_subpools[i]), mp);
			data_put_params[i] = (struct req_params_store*)apr_pcalloc(
					data_subpools[i], sizeof(struct req_params_store));
			data_put_params[i]->service_address = \
					stream->r->info->rawx_list[stream->r->info->current_rawx];
			data_put_params[i]->data_to_send = \
					stream->original_data_chunk_start_ptr;
			data_put_params[i]->data_to_send_size = subchunk_size;
			data_put_params[i]->header = apr_psprintf(data_subpools[i],
					"%s\nchunkid: %s\nchunkpos: %s\nchunksize: %s\nchunkhash: %s",
					custom_header, custom_chunkid, custom_chunkpos,
					custom_chunksize, custom_chunkhash);
			data_put_params[i]->req_type = "PUT";
			data_put_params[i]->reply = apr_pcalloc(data_subpools[i],
					MAX_REPLY_HEADER_SIZE + REPLY_BUFFER_SIZE);
			data_put_params[i]->resource = stream->r;
			/* APR_SUCCESS will set it to 0 */
			data_put_params[i]->req_status = INIT_REQ_STATUS;
			data_put_params[i]->pool = data_subpools[i];
			/* ------- */

			/* Launching the PUT thread */
			apr_threadattr_create(&(data_put_params[i]->thd_attr),
					data_subpools[i]);
			rv = apr_thread_create(&(data_put_params[i]->thd_arr),
					data_put_params[i]->thd_attr, putrawx,
					REQPARAMSSTORE_TO_POINTER(data_put_params[i]),
					data_subpools[i]);
			assert(rv == APR_SUCCESS);
			/* ------- */

			update_response_list(stream,
					stream->r->info->rawx_list[stream->r->info->current_rawx],
					subchunk_size, custom_chunkhash);

			if (custom_chunkhash) {
				g_free(custom_chunkhash);
				custom_chunkhash = NULL;
			}

			/* Updating current metachunk buffer state */
			stream->r->info->current_chunk_remaining = subchunk_size;
			stream->original_data_chunk_start_ptr = \
					stream->original_data_chunk_end_ptr;
			/* ------- */

			/* Updating general context */
			stream->r->info->current_rawx++;
			/* ------- */
		}
		else {
			memcpy(stream->original_data_chunk_end_ptr, buf_ptr, to_read);

			/* Updating buf state */
			stream->original_data_chunk_end_ptr += to_read;
			stream->original_data_stored += to_read;

			stream->r->info->current_chunk_remaining -= to_read;

			buf_ptr += to_read;
			to_read = 0;
			/* ------- */
		}
	}

	int i;
	for (i = 0; i < stream->r->info->k; i++) {
		if (data_put_params[i] && data_put_params[i]->thd_arr) {
			apr_thread_join(&rv, data_put_params[i]->thd_arr);
			assert(rv == APR_SUCCESS);
		}
		if (data_subpools[i])
			apr_pool_destroy(data_subpools[i]);
	}

	/* ------- */

	MD5_Update(&(stream->md5_ctx), buf, bufsize);
	server_add_stat(resource_get_server_config(stream->r),
			RAWX_STATNAME_REP_BWRITTEN, bufsize, 0);
	return NULL;
}

static dav_error *
dav_rainx_seek_stream(dav_stream *stream, apr_off_t abs_pos)
{
	(void) abs_pos, (void) stream;

	/* Do we really need this ? */
	DAV_XDEBUG_POOL(stream->p, 0, "%s", __FUNCTION__);
	return NULL;
}

static dav_error *
dav_rainx_set_headers(request_rec *r, const dav_resource *resource)
{
	if (!resource->exists)
		return NULL;

	DAV_DEBUG_REQ(r, 0, "%s", __FUNCTION__);

	return NULL;
}

static int
extract_content_from_reply(char** chunk, char* reply,
		const dav_resource *resource)
{
	if (!reply || !chunk)
		return -1;

	char* ptr_start = strstr(reply, "Content-Length");
	ptr_start += 16;
	char* ptr_end = strchr(ptr_start, '\r');
	char* content_length_str = apr_pstrndup(resource->info->request->pool,
			ptr_start, ptr_end - ptr_start);
	size_t content_length = strtoll(content_length_str, NULL, 10);

	ptr_start = strstr(reply, "\r\n\r\n");
	ptr_start += 4;
	memcpy(*chunk, ptr_start, content_length);

	return content_length;
}

static dav_error *
parse_spare_rawx_list(const dav_resource *resource, int max,
		gboolean* failure_array, char **spare_rawx_list, char** spare_md5_list)
{
	dav_error *e = NULL;
	apr_pool_t *pool = resource_get_pool(resource);
	dav_rainx_server_conf *conf = resource_get_server_config(resource);
	char *last1 = NULL;
	char *tok1 = apr_strtok(resource->info->content.spare_rawx_list,
			RAWXLIST_SEPARATOR2, &last1);
	int spare_rawx_list_pos = 0;

	while (tok1 && spare_rawx_list_pos < max) {
		char* last2;
		char* tok2 = apr_strtok(tok1, RAWXLIST_SEPARATOR, &last2);
		if (!tok2) {
			e = server_create_and_stat_error(conf, pool, HTTP_BAD_REQUEST,
					0, "Bad spare rawx address(es) format");
			DAV_DEBUG_REQ(resource->info->request,
					0, e->desc);
			goto end;
		}
		spare_rawx_list[spare_rawx_list_pos] = tok2;

		tok2 = apr_strtok(NULL, RAWXLIST_SEPARATOR, &last2);
		if (!tok2) {
			e = server_create_and_stat_error(conf, pool, HTTP_BAD_REQUEST,
					0, "Bad spare rawx address(es) format");
			DAV_DEBUG_REQ(resource->info->request, 0, e->desc);
			goto end;
		}

		errno = 0;
		apr_int64_t position = apr_atoi64(tok2);
		if (position < 0 || position >= max || errno != 0) {
			char *msg = apr_psprintf(resource->pool,
					"Invalid chunk position: %s", tok2);
			e = server_create_and_stat_error(conf, pool, HTTP_BAD_REQUEST,
					0, msg);
			DAV_DEBUG_REQ(resource->info->request, 0, msg);
			goto end;
		}
		failure_array[position] = TRUE;

		tok2 = apr_strtok(NULL, RAWXLIST_SEPARATOR, &last2);
		if (!tok2) {
			char *msg = apr_psprintf(resource->pool,
					"Bad spare rawx hash: %s", tok2);
			e = server_create_and_stat_error(
					conf, pool, HTTP_BAD_REQUEST, 0, msg);
			DAV_DEBUG_REQ(resource->info->request, 0, msg);
			goto end;
		}
		spare_md5_list[spare_rawx_list_pos] = tok2;

		spare_rawx_list_pos++;

		tok1 = apr_strtok(NULL, RAWXLIST_SEPARATOR2, &last1);
	}

	if (spare_rawx_list_pos >= max && !e) {
		e = server_create_and_stat_error(conf, pool, HTTP_BAD_REQUEST, 0,
				"Too many elements in spare rawx list");
	}

end:
	return e;
}

static dav_error *
check_reconstructed_data(const dav_resource *resource, gboolean* failure_array,
		char **datachunks, char **codingchunks, char** spare_md5_list)
{
	dav_error *e = NULL;
	int k, m, subchunk_size, metachunk_size;

	/* Testing the reconstructed data with the header md5 */
	int cur_spare_rawx = 0;
	int cumulated_data = 0;

	k = resource->info->k;
	m = resource->info->m;
	subchunk_size = resource->info->subchunk_size;
	metachunk_size = resource->info->metachunk_size;

	/* Data strips */
	for (int i = 0; i < k; i++) {
		if (failure_array[i]) {
			int data_to_hash_size = subchunk_size;
			if (cumulated_data + subchunk_size > metachunk_size)
				data_to_hash_size = metachunk_size - cumulated_data;
			if (data_to_hash_size < 0)
				data_to_hash_size = 0;

			char* custom_chunkhash = g_compute_checksum_for_string(
					G_CHECKSUM_MD5, datachunks[i], data_to_hash_size);

			if (custom_chunkhash) {
				g_free(custom_chunkhash);
				custom_chunkhash = NULL;
			}

			cur_spare_rawx++;
			cumulated_data += data_to_hash_size;
		}
		else
			cumulated_data += subchunk_size;
	}

	/* Coding strips */
	for (int i = 0; i < m; i++) {
		if (failure_array[k + i]) {
			char* custom_chunkhash = g_compute_checksum_for_string(
					G_CHECKSUM_MD5, codingchunks[i], subchunk_size);

			// FIXME: if md5 has special value "?", don't do this check, but
			// add the computed checksum as a response header (client lost it).
			if (g_ascii_strncasecmp(custom_chunkhash,
					spare_md5_list[cur_spare_rawx], strlen(custom_chunkhash))) {
				e = server_create_and_stat_error(
						resource_get_server_config(resource),
						resource_get_pool(resource),
						HTTP_INTERNAL_SERVER_ERROR, 0,
						"Failed to reconstruct a coding chunk (MD5 differs)");
				DAV_DEBUG_REQ(resource->info->request, 0, e->desc);
				if (custom_chunkhash) {
					g_free(custom_chunkhash);
					custom_chunkhash = NULL;
				}
				goto end;
			}

			if (custom_chunkhash) {
				g_free(custom_chunkhash);
				custom_chunkhash = NULL;
			}

			cur_spare_rawx++;
		}
	}
	/* ------- */

end:
	return e;
}

static dav_error *
upload_to_rawx(const dav_resource *resource, gboolean* failure_array,
		char **datachunks, char **codingchunks, char **spare_rawx_list,
		int data_rawx_list_size)
{
	dav_error *e = NULL;
	apr_status_t req_status;
	int cur_spare_rawx = 0;
	int cumulated_data = 0;
	int k = resource->info->k;
	int m = resource->info->m;
	int subchunk_size = resource->info->subchunk_size;
	int metachunk_size = resource->info->metachunk_size;
	char *reply, *reply_code, *reply_message;
	char* custom_header;
	struct req_params_store rps;
	struct content_textinfo_s temp_content = resource->info->content;
	struct chunk_textinfo_s temp_chunk = resource->info->chunk;

	reply = apr_palloc(resource->info->request->pool,
			MAX_REPLY_HEADER_SIZE + subchunk_size);
	reply_code = apr_pcalloc(resource->info->request->pool, 4);
	reply_message = apr_pcalloc(resource->info->request->pool,
			MAX_REPLY_MESSAGE_SIZE);

	memset(&rps, 0, sizeof(rps));
	rps.pool = resource_get_pool(resource);
	rps.reply = reply;
	rps.req_type = "PUT";
	rps.resource = resource;

	/* Preparing custom header */
	custom_header = apr_psprintf(resource->info->request->pool,
			"containerid: %s\nchunknb: %s\ncontentpath: %s\ncontentsize: %s",
			temp_content.container_id, temp_content.chunk_nb,
			temp_content.path, temp_content.size);
	if (temp_content.metadata)
		custom_header = apr_psprintf(resource->info->request->pool,
				"%s\ncontentmetadata: %s", custom_header, temp_content.metadata);
	if (temp_content.system_metadata)
		custom_header = apr_psprintf(resource->info->request->pool,
				"%s\ncontentmetadata-sys: %s", custom_header,
				temp_content.system_metadata);

	/* Data strips */
	for (int i = 0; i < data_rawx_list_size; i++) {
		int byte_count_to_send = subchunk_size;
		if (cumulated_data + subchunk_size > metachunk_size)
			byte_count_to_send = metachunk_size - cumulated_data;
		if (byte_count_to_send < 0)
			byte_count_to_send = 0;

		cumulated_data += byte_count_to_send;

		if (failure_array[i]) {
			memset(reply, 0, MAX_REPLY_HEADER_SIZE + subchunk_size);

			/* Finalizing custom header */
			int startid = strlen(spare_rawx_list[cur_spare_rawx]) - 64;
			char* custom_chunkid = apr_pstrdup(resource->info->request->pool,
					spare_rawx_list[cur_spare_rawx] + startid);
			char* custom_chunkpos = apr_psprintf(resource->info->request->pool,
					"%s.%d", temp_chunk.position, i);
			char* custom_chunksize = apr_itoa(resource->info->request->pool,
					byte_count_to_send);
			char* custom_chunkhash = g_compute_checksum_for_string(
					G_CHECKSUM_MD5, datachunks[i], byte_count_to_send);
			char* custom_header2 = apr_psprintf(resource->info->request->pool,
					"%s\nchunkid: %s\nchunkpos: %s\nchunksize: %s\nchunkhash: %s",
					custom_header, custom_chunkid, custom_chunkpos,
					custom_chunksize, custom_chunkhash);
			/* ------- */
			rps.service_address = spare_rawx_list[cur_spare_rawx];
			rps.header = custom_header2;
			rps.data_to_send = datachunks[i];
			rps.data_to_send_size = byte_count_to_send;
			req_status = rainx_http_req(&rps);

			memset(reply_code, 0, 4);
			memset(reply_message, 0, MAX_REPLY_MESSAGE_SIZE);
			if (!extract_code_message_reply(resource, reply,
					&reply_code, &reply_message)) {
				DAV_DEBUG_REQ(resource->info->request, 0,
						"error while putting the reconstructed "
						"data to the rawx %d: %s", i, reply);
				e = server_create_and_stat_error(
						resource_get_server_config(resource),
						resource_get_pool(resource),
						HTTP_INTERNAL_SERVER_ERROR, 0,
						"Rain operation failed on put");
				if (custom_chunkhash) {
					g_free(custom_chunkhash);
					custom_chunkhash = NULL;
				}
				goto end;
			}
			if (!g_str_has_prefix(reply_code, "20")) {
				DAV_DEBUG_REQ(resource->info->request, 0,
						"error while putting the reconstructed "
						"data to the rawx %d: %s", i, reply);
				e = server_create_and_stat_error(
						resource_get_server_config(resource),
						resource_get_pool(resource),
						apr_atoi64(reply_code), 0, reply_message);
				if (custom_chunkhash) {
					g_free(custom_chunkhash);
					custom_chunkhash = NULL;
				}
				goto end;
			}
			DAV_DEBUG_REQ(resource->info->request, 0,
					"rawx %d filled (reconstructed data)", i);

			if (custom_chunkhash) {
				g_free(custom_chunkhash);
				custom_chunkhash = NULL;
			}

			cur_spare_rawx++;
		}
	}
	/* Coding strips */
	for (int i = 0; i < m; i++) {
		if (failure_array[k + i]) {
			memset(reply, 0, MAX_REPLY_HEADER_SIZE + subchunk_size);

			/* Finalizing custom header */
			int startid = strlen(spare_rawx_list[cur_spare_rawx]) - 64;
			char* custom_chunkid = apr_pstrdup(resource->info->request->pool,
					spare_rawx_list[cur_spare_rawx] + startid);
			char* custom_chunkpos = apr_psprintf(resource->info->request->pool,
					"%s.p%d", temp_chunk.position, i);
			char* custom_chunksize = apr_itoa(
					resource->info->request->pool, subchunk_size);
			char* custom_chunkhash = g_compute_checksum_for_string(
					G_CHECKSUM_MD5, codingchunks[i], subchunk_size);
			char* custom_header2 = apr_psprintf(resource->info->request->pool,
					"%s\nchunkid: %s\nchunkpos: %s\nchunksize: %s\nchunkhash: %s",
					custom_header, custom_chunkid, custom_chunkpos,
					custom_chunksize, custom_chunkhash);
			/* ------- */
			rps.service_address = spare_rawx_list[cur_spare_rawx];
			rps.header = custom_header2;
			rps.data_to_send = codingchunks[i];
			rps.data_to_send_size = subchunk_size;
			req_status = rainx_http_req(&rps);

			memset(reply_code, 0, 4);
			memset(reply_message, 0, MAX_REPLY_MESSAGE_SIZE);
			if (!extract_code_message_reply(resource, reply,
						&reply_code, &reply_message)) {
				// FIXME: use apr_strerror() to get a clear message
				DAV_DEBUG_REQ(resource->info->request, 0,
						"error while putting the reconstructed coding "
						"to the rawx %d: (%d) %s", i, req_status, reply);
				e = server_create_and_stat_error(
						resource_get_server_config(resource),
						resource_get_pool(resource),
						HTTP_INTERNAL_SERVER_ERROR,
						0, "Rain operation failed on put");
				if (custom_chunkhash) {
					g_free(custom_chunkhash);
					custom_chunkhash = NULL;
				}
				goto end;
			}
			if (!g_str_has_prefix(reply_code, "20")) {
				DAV_DEBUG_REQ(resource->info->request, 0,
						"error while putting the reconstructed coding "
						"to the rawx %d: %s", i, reply);
				e = server_create_and_stat_error(
						resource_get_server_config(resource),
						resource_get_pool(resource),
						apr_atoi64(reply_code), 0, reply_message);
				if (custom_chunkhash) {
					g_free(custom_chunkhash);
					custom_chunkhash = NULL;
				}
				goto end;
			}
			DAV_DEBUG_REQ(resource->info->request, 0,
					"rawx %d filled (reconstructed coding)", i);

			if (custom_chunkhash) {
				g_free(custom_chunkhash);
				custom_chunkhash = NULL;
			}

			cur_spare_rawx++;
		}
	}
end:
	return e;
}

static dav_error *
dav_rainx_deliver(const dav_resource *resource, ap_filter_t *output)
{
	/* GET MAIN METHOD */

	dav_rainx_server_conf *conf;
	apr_pool_t *pool;
	dav_error *e = NULL;
	apr_status_t req_status;
	int i;
	char* reply = NULL;
	char *reconstructed_data = NULL;
	/* The array showing if a rawx is a failure */
	gboolean* failure_array = NULL;
	/* The array containing the spared rawx addresses */
	char** spare_rawx_list = NULL;
	/* The array containing the hash to check after reconstruction of a chunk */
	char** spare_md5_list = NULL;
	int metachunk_size = -1;
	int subchunk_size = -1;

	pool = resource->pool;
	conf = resource_get_server_config(resource);

	/* Check resource type */
	if (DAV_RESOURCE_TYPE_REGULAR != resource->type) {
		e = server_create_and_stat_error(conf, pool, HTTP_CONFLICT, 0,
			"Cannot GET this type of resource.");
		goto end_deliver;
	}

	if (resource->collection) {
		e = server_create_and_stat_error(conf, pool, HTTP_CONFLICT, 0,
			"No GET on collections");
		goto end_deliver;
	}
	/* ------- */

	/* Storage policy management (storage policy name got from the header) */
	/* Getting policy parameters (k, m, algo) */
	char* str = resource->info->content.storage_policy;
	struct storage_policy_s *sp;

	int k = -1;
	int m = -1;
	const char* algo = NULL;

	if (!str || !(sp = storage_policy_init(conf->rainx_conf->ni, str))) {
		DAV_DEBUG_REQ(resource->info->request, 0 ,
				"\"%s\" policy init failed for namespace \"%s\"",
				str, conf->rainx_conf->ni->name);
		e = server_create_and_stat_error(conf, pool, HTTP_BAD_REQUEST, 0,
				"Bad policy parameter");
		goto end_deliver;
	}

	apr_pool_cleanup_register(pool, sp,
			apr_storage_policy_clean, apr_pool_cleanup_null);

	DAV_DEBUG_REQ(resource->info->request, 0 ,
			"\"%s\" policy init succeeded for namespace \"%s\"",
			str, conf->rainx_conf->ni->name);

	const struct data_security_s *datasec = storage_policy_get_data_security(sp);
	if (RAIN != data_security_get_type(datasec)) {
		DAV_DEBUG_REQ(resource->info->request, 0 ,
				"the data security type for the policy \"%s\" is not rain", str);
		goto end_deliver;
	}

	const char* orig_k = NULL;
	const char* orig_m = NULL;

	if ((NULL == (orig_k = data_security_get_param(datasec, "k")))
			|| (NULL == (orig_m = data_security_get_param(datasec, "m")))
			|| (NULL == (algo = data_security_get_param(datasec, "algo")))) {
		DAV_DEBUG_REQ(resource->info->request, 0 ,
				"failed to get all the \"%s\" policy parameters", str);
		e = server_create_and_stat_error(conf, pool, HTTP_INTERNAL_SERVER_ERROR, 0,
				"Rain operation failed on loading policy");
		goto end_deliver;
	}

	k = strtol(orig_k, NULL, 10);
	m = strtol(orig_m, NULL, 10);
	resource->info->k = k;
	resource->info->m = m;
	resource->info->algo = apr_pstrdup(pool, algo);

	if (k <= 0 || m <= 0) {
		DAV_DEBUG_REQ(resource->info->request, 0 ,
				"bad \"%s\" policy 'k'  or 'm' parameter value", str);
		e = server_create_and_stat_error(conf, pool, HTTP_INTERNAL_SERVER_ERROR, 0,
				"Rain operation failed on loading policy");
		goto end_deliver;
	}

	DAV_DEBUG_REQ(resource->info->request, 0 , "\"%s\" policy parameters are : "
			"k = %d, m = %d, algo = %s", str, k, m, algo);
	/* ------- */

	/* Getting the rawx addresses from the header */
	if (NULL == resource->info->content.rawx_list) {
		DAV_DEBUG_REQ(resource->info->request, 0 , "rawx list is null");
		e = server_create_and_stat_error(conf, pool, HTTP_BAD_REQUEST, 0,
				"Bad rawx list parameter");
		goto end_deliver;
	}
	char** rawx_list =(char**)apr_pcalloc(resource->info->request->pool,
			(k + m) * sizeof(char*)); /* The given rawx addresses list */
	char* last;
	// FIXME: this should be separated by ';', not '|'
	char* temp_tok = apr_strtok(resource->info->content.rawx_list,
			RAWXLIST_SEPARATOR, &last);
	for (i = 0; temp_tok != NULL && i < k + m; i++) {
		rawx_list[i] = temp_tok;
		temp_tok = apr_strtok(NULL, RAWXLIST_SEPARATOR, &last);
	}
	int data_rawx_list_size = i - m; /* The number of given data rawx addresses */
	/* ------- */

	/* Getting the spare rawx addresses, the failures array,
	 * and the original MD5 array from the header */
	if (NULL == resource->info->content.spare_rawx_list) {
		DAV_DEBUG_REQ(resource->info->request, 0 , "spare rawx list is null");
		e = server_create_and_stat_error(conf, pool, HTTP_BAD_REQUEST,
				0, "Bad spare rawx list parameter");
		goto end_deliver;
	}

	failure_array = (gboolean*)apr_pcalloc(
			resource->info->request->pool, (k + m) * sizeof(gboolean));
	spare_rawx_list = (char**)apr_pcalloc(resource->info->request->pool,
			(k + m) * sizeof(char*));
	spare_md5_list = (char**)apr_pcalloc(resource->info->request->pool,
			(k + m) * sizeof(char*));
	e = parse_spare_rawx_list(resource, k + m,
			failure_array, spare_rawx_list, spare_md5_list);
	if (e)
		goto end_deliver;
	/* ------- */

	/* Calculating subchunk size through the librain library */
	e = compute_subchunk_size(resource, k, m, algo,
			&metachunk_size, &subchunk_size);
	DAV_DEBUG_REQ(resource->info->request,
			0, "calculated subchunk size is %d bytes", subchunk_size);
	if (e)
		goto end_deliver;
	resource->info->subchunk_size = subchunk_size;
	resource->info->metachunk_size = metachunk_size;
	/* ------- */

	/* Creating data strips */
	char** datachunks = (char**)apr_pcalloc(
			resource->info->request->pool, k * sizeof(char*));
	char* reply_code = apr_pcalloc(resource->info->request->pool, 4);
	char* reply_message = apr_pcalloc(resource->info->request->pool,
			MAX_REPLY_MESSAGE_SIZE);
	reply = apr_palloc(resource->info->request->pool,
			MAX_REPLY_HEADER_SIZE + subchunk_size);
	struct req_params_store rps;
	memset(&rps, 0, sizeof(rps));
	rps.data_to_send_size = subchunk_size;
	rps.pool = resource->info->request->pool;
	rps.reply = reply;
	rps.req_type = "GET";
	rps.resource = resource;
	for (i = 0; i < data_rawx_list_size; i++) {
		if (!failure_array[i]) {
			datachunks[i] = (char*)apr_pcalloc(resource->info->request->pool,
					subchunk_size * sizeof(char));
			memset(reply, 0, MAX_REPLY_HEADER_SIZE + subchunk_size);
			rps.service_address = rawx_list[i];
			req_status = rainx_http_req(&rps);

			/* Error management */
			memset(reply_code, 0, 4);
			memset(reply_message, 0, MAX_REPLY_MESSAGE_SIZE);
			if (!extract_code_message_reply(resource, reply,
					&reply_code, &reply_message) ||
					!g_str_has_prefix(reply_code, "20")) {
				DAV_DEBUG_REQ(resource->info->request,
						0, "unexpected failure on data rawx %d: %s", i, reply);
				e = server_create_and_stat_error(conf, pool, HTTP_BAD_REQUEST,
						0, "Unexpected failure on data rawx");
				goto end_deliver;
			}
			DAV_DEBUG_REQ(resource->info->request,
					0, "got the data chunk from the rawx %d", i);
			/* ------- */

			int lcont = extract_content_from_reply(datachunks + i, reply, resource);
			if (-1 == lcont) {
				DAV_DEBUG_REQ(resource->info->request,
						0, "problem occured while extracting the content "
						"got from the data rawx %d", i);
				e = server_create_and_stat_error(conf, pool,
						HTTP_INTERNAL_SERVER_ERROR, 0,
						"Problem occured while extracting the content got from a data rawx");
				goto end_deliver;
			}
		}
		else
			datachunks[i] = NULL;
	}
	/* If it remains entire padded chunks at the end */
	for (i = data_rawx_list_size; i < k; i++)
		datachunks[i] = (char*)apr_pcalloc(resource->info->request->pool,
				subchunk_size * sizeof(char));
	/* ------- */

	/* Creating coding strips */
	char** codingchunks = (char**)apr_pcalloc(resource->info->request->pool,
			m * sizeof(char*));
	memset(&rps, 0, sizeof(rps));
	rps.data_to_send_size = subchunk_size;
	rps.pool = resource->info->request->pool;
	rps.reply = reply;
	rps.req_type = "GET";
	rps.resource = resource;
	for (i = 0; i < m; i++) {
		if (!failure_array[k + i]) {
			codingchunks[i] = (char*)apr_pcalloc(resource->info->request->pool,
					subchunk_size * sizeof(char));

			memset(reply, 0, MAX_REPLY_HEADER_SIZE + subchunk_size);
			rps.service_address = rawx_list[data_rawx_list_size + i];
			req_status = rainx_http_req(&rps);

			/* Error management */
			memset(reply_code, 0, 4);
			memset(reply_message, 0, MAX_REPLY_MESSAGE_SIZE);
			if (!extract_code_message_reply(resource, reply,
						&reply_code, &reply_message) ||
						!g_str_has_prefix(reply_code, "20")) {
				DAV_DEBUG_REQ(resource->info->request,
						0, "unexpected failure on data rawx %d: %s", i, reply);
				e = server_create_and_stat_error(conf, pool, HTTP_BAD_REQUEST,
						0, "Unexpected failure on data rawx");
				goto end_deliver;
			}
			DAV_DEBUG_REQ(resource->info->request,
					0, "got the coding chunk from the rawx %d", i);
			/* ------- */

			int lcont = extract_content_from_reply(codingchunks + i,
					reply, resource);
			if (-1 == lcont) {
				DAV_DEBUG_REQ(resource->info->request, 0,
						"problem occured while extracting the content "
						"got from the coding rawx %d", i);
				e = server_create_and_stat_error(conf, pool,
						HTTP_INTERNAL_SERVER_ERROR, 0,
						"Problem occured while extracting the content "
						"got from a coding rawx");
				goto end_deliver;
			}
		}
		else
			codingchunks[i] = NULL;
	}
	/* ------- */

	/* Repairing lost data or coding subchunks */
	reconstructed_data = rain_repair_and_get_raw_data(datachunks, codingchunks,
			metachunk_size, k, m, algo);
	if (NULL == reconstructed_data) {
		DAV_DEBUG_REQ(resource->info->request,
				0, "failed to reconstruct the original data");
		e = server_create_and_stat_error(conf, pool,
				HTTP_INTERNAL_SERVER_ERROR, 0,
				"Failed to reconstruct the original data");
		goto end_deliver;
	}
	/* ------- */

	/* Testing the reconstructed data with the header md5 */
	e = check_reconstructed_data(resource, failure_array, datachunks,
			codingchunks, spare_md5_list);
	if (e)
		goto end_deliver;
	/* ------- */

	/* Putting reconstructed subchunks into new rawx */
	if (!resource->info->on_the_fly) {
		e = upload_to_rawx(resource, failure_array, datachunks, codingchunks,
				spare_rawx_list, data_rawx_list_size);
		if (e)
			goto end_deliver;
	}
	/* ------- */

	/* Returning the whole reconstructed data */
	apr_bucket_brigade *bb = apr_brigade_create(
			resource->info->request->pool, output->c->bucket_alloc);
	apr_brigade_write(bb, NULL, resource->info, reconstructed_data, metachunk_size);
	if (ap_pass_brigade(output, bb) != APR_SUCCESS) {
		DAV_DEBUG_REQ(resource->info->request, 0,
				"could not write content to filter");
		e = server_create_and_stat_error(conf, pool, HTTP_FORBIDDEN, 0,
				"Could not write content to filter");
		goto end_deliver;
	} else {
		DAV_DEBUG_REQ(resource->info->request, 0,
				"Reconstructed metachunk sent to client");
	}
	/* ------- */

	server_inc_stat(conf, RAWX_STATNAME_REP_2XX, 0);

end_deliver:

	/* Now we pass here even if an error occured, for process request duration */
	server_inc_request_stat(resource_get_server_config(resource),
			RAWX_STATNAME_REQ_CHUNKGET,
			request_get_duration(resource->info->request));

	g_free(reconstructed_data);

	return e;
}

static dav_error *
dav_rainx_remove_resource(dav_resource *resource, dav_response **response)
{

	/* DELETE MAIN FUNC */

	apr_pool_t *pool;
	dav_error *e = NULL;

	DAV_XDEBUG_RES(resource, 0, "%s", __FUNCTION__);
	pool = resource->pool;
	*response = NULL;

	if (DAV_RESOURCE_TYPE_REGULAR != resource->type)  {
		e = server_create_and_stat_error(resource_get_server_config(resource),
				pool, HTTP_CONFLICT, 0, "Cannot DELETE this type of resource.");
		goto end_remove;
	}
	if (resource->collection) {
		e = server_create_and_stat_error(resource_get_server_config(resource),
				pool, HTTP_CONFLICT, 0, "No DELETE on collections");
		goto end_remove;
	}

	resource->exists = 0;
	resource->collection = 0;

	server_inc_stat(resource_get_server_config(resource),
			RAWX_STATNAME_REP_2XX, 0);

end_remove:

	/* Now we pass here even if an error occured, for process request duration */
	server_inc_request_stat(resource_get_server_config(resource),
			RAWX_STATNAME_REQ_CHUNKDEL,
			request_get_duration(resource->info->request));

	return e;
}

/* XXX JFS: etags are strings that uniquely identify a content.
 * A chunk is unique in a namespace, thus the e-tag must contain
 * both fields. */
static const char *
dav_rainx_getetag(const dav_resource *resource)
{
	/* return etag */
	const char *etag;

	if (!resource->exists) {
		DAV_DEBUG_RES(resource, 0, "%s : resource not found",
				__FUNCTION__);

		return NULL;
	}

	etag = apr_psprintf(resource->pool, "Dummy ETag, not yet computed");
	DAV_DEBUG_RES(resource, 0, "%s : ETag=[%s]", __FUNCTION__, etag);

	return etag;
}

/* XXX JFS : rainx walks are dummy*/
static dav_error *
dav_rainx_walk(const dav_walk_params *params, int depth, dav_response **response)
{
	dav_walk_resource wres;
	dav_error *err;

	(void) depth;
	err = NULL;
	memset(&wres, 0x00, sizeof(wres));
	wres.walk_ctx = params->walk_ctx;
	wres.pool = params->pool;
	wres.resource = params->root;

	DAV_XDEBUG_RES(params->root, 0, "sanity checks on resource");

	if (wres.resource->type != DAV_RESOURCE_TYPE_REGULAR)
		return server_create_and_stat_error(
				resource_get_server_config(params->root),
				params->root->pool, HTTP_CONFLICT, 0,
				"Only regular resources can be deleted with RAWX");
	if (wres.resource->collection)
		return server_create_and_stat_error(
				resource_get_server_config(params->root),
				params->root->pool, HTTP_CONFLICT, 0,
				"Collection resources canot be deleted with RAWX");
	if (!wres.resource->exists)
		return server_create_and_stat_error(
				resource_get_server_config(params->root),
				params->root->pool, HTTP_NOT_FOUND, 0,
				"Resource not found (no chunk)");

	err = (*params->func)(&wres, DAV_CALLTYPE_MEMBER);
	*response = wres.response;
	return err;
}

static const dav_hooks_repository dav_hooks_repository_rainx =
{
	1,
	dav_rainx_get_resource,
	dav_rainx_get_parent_resource,
	dav_rainx_is_same_resource,
	dav_rainx_is_parent_resource,
	dav_rainx_open_stream,
	dav_rainx_close_stream,
	dav_rainx_write_stream,
	dav_rainx_seek_stream,
	dav_rainx_set_headers,
	dav_rainx_deliver,
	NULL /* no collection creation */,
	NULL /* no copy of resources allowed */,
	NULL /* cannot move resources */,
	dav_rainx_remove_resource /*only for regular resources*/,
	dav_rainx_walk /* no walk across the chunks */,
	dav_rainx_getetag,
	NULL, /* no module context */
#if MODULE_MAGIC_COOKIE == 0x41503234UL /* "AP24" */
	NULL,
	NULL,
#endif
};

static const dav_provider dav_rainx_provider =
{
	&dav_hooks_repository_rainx,
	&dav_hooks_db_dbm,
	NULL,               /* no lock management */
	NULL,               /* vsn */
	NULL,               /* binding */
	NULL,               /* search */
	NULL                /* ctx */
};


void
dav_rainx_register(apr_pool_t *p)
{
	dav_register_provider(p, "rainx", &dav_rainx_provider);
}
