#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "integrity.lib.check"
#endif

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>
#include <meta2/remote/meta2_remote.h>
#include <meta2v2/meta2v2_remote.h>
#include <meta2v2/generic.h>
#include <meta2v2/meta2_utils.h>

#include "check.h"

/**
 * List of meta2 for which a m2v1 request was successfully executed.
 * This enables to skip sending m2v2 requests to this meta2.
 */
static GSList *m2v1_list = NULL;

static GError*
_init_meta2_connection(struct meta2_ctx_s *ctx)
{
	GError *result = NULL;

	/* Create connection to meta2 */
        if(!(ctx->m2_cnx = metacnx_create(&result)))
		return result;

        ctx->m2_cnx->flags = METACNX_FLAGMASK_KEEPALIVE;
        ctx->m2_cnx->timeout.cnx = 30000;
        ctx->m2_cnx->timeout.req = 30000;

        if (!metacnx_init_with_url(ctx->m2_cnx, ctx->loc->m2_url[0], &result))
                goto clean_up;

        if (!metacnx_open(ctx->m2_cnx, &result))
                goto clean_up;

clean_up:
	if(result) {
		if(ctx->m2_cnx) {
	        metacnx_close(ctx->m2_cnx);
	        metacnx_destroy(ctx->m2_cnx);
	        ctx->m2_cnx = NULL;
	    }
	}	

	return result;
}


struct meta2_ctx_s *
get_meta2_ctx(const gchar *ns_name, const gchar *container_hexid,
		const gchar *content_name, gboolean check_only, GError **error)
{
	gchar *storage_policy = NULL;
	namespace_info_t *ns_info = NULL;
	GError *local_error = NULL;
	gs_error_t *gs_error = NULL;
	struct meta2_ctx_s *ctx = NULL;
	container_id_t cid;

	/* load namespace info for storage policies definitions */
	if(!(ns_info = get_namespace_info(ns_name, &local_error))) {
		GSETERROR(error, "Failed to load namespace info, cannot check content policy : %s",local_error->message);
		goto clean_up;
	}

	ctx = g_malloc0(sizeof(struct meta2_ctx_s));

	ctx->ns = g_strdup(ns_info->name);
	ctx->check_only = check_only;
	ctx->modified = FALSE;
	ctx->fail = FALSE;

	GRID_DEBUG("Namespace info ok");

	if(!(ctx->hc = gs_grid_storage_init(ns_name, &gs_error))) {
		GSETERROR(error, "Failed to init grid storage client : %s", gs_error_get_message(gs_error));
		goto clean_up;
	}

	GRID_DEBUG("context initialization ok");

	/* Locate container */
	if (!container_hexid) {
		GSETERROR(error, "Container is null");
		goto clean_up;
	}

	char* ct_ns_name = NULL;
	ctx->loc = gs_locate_container_by_hexid_v2(ctx->hc, container_hexid, &ct_ns_name, &gs_error);
	if (ctx->loc == NULL || ctx->loc->m2_url == NULL) {
		if(gs_error) {
			GSETERROR(error, "Failed to locate container [%s] in namespace: %s", container_hexid, gs_error_get_message(gs_error));
		} else {
			GSETERROR(error, "Failed to locate container [%s] in namespace: No error", container_hexid);
		}		
	}


	// if nsname --> replace by realy VNS name
	if (ct_ns_name) {
        if (g_strcmp0(ct_ns_name, ctx->ns) != 0) {
            g_free(ctx->ns);
            ctx->ns = ct_ns_name;

            // close old hc
			gs_grid_storage_free(ctx->hc);

			// reinit hc with VNS name
			if(!(ctx->hc = gs_grid_storage_init(ctx->ns, &gs_error))) {
	        	GSETERROR(error, "Failed to init grid storage client : %s", gs_error_get_message(gs_error));
				goto clean_up;
			}
		} else {
			g_free(ct_ns_name);
		}
	}

	// exit if container not loaded
	if (ctx->loc == NULL || ctx->loc->m2_url == NULL)
		goto clean_up;

	GRID_DEBUG("container located [%s/%s]", ctx->ns, ctx->loc->container_name);


	if((local_error = _init_meta2_connection(ctx)) != NULL) {
		GSETERROR(error, "Failed to init meta2 connection :%s", local_error->message);
		goto clean_up;
	}

	/* Try to find content */
	if (!container_id_hex2bin(container_hexid, strlen(container_hexid), &cid, &local_error))
		goto clean_up;
	ctx->content = meta2_remote_stat_content(ctx->m2_cnx, cid, content_name, strlen(content_name),
			&local_error);

	if (!ctx->content) {
		GRID_DEBUG("Content %s/%s/%s doesn't exist", ctx->ns,
				container_hexid, content_name);
		if (local_error) {
			GSETERROR(error, "Cannot check content state, "
					"content not found %s/%s/%s: %s",
					ctx->ns, container_hexid, content_name,
					local_error->message);
		}
		goto clean_up;
	}

	GRID_DEBUG("Content information:");
	GRID_DEBUG("Nb chunks: %"G_GUINT32_FORMAT, ctx->content->nb_chunks);
	GRID_DEBUG("Size: %"G_GINT64_FORMAT, ctx->content->size);
	if(ctx->content->metadata)
		GRID_DEBUG("Metadata : %s", (gchar*)ctx->content->metadata->data);
	else
		GRID_DEBUG("No metadata returned");

	local_error = storage_policy_from_metadata(ctx->content->system_metadata,
			&storage_policy);
	if (local_error != NULL || !storage_policy) {
		storage_policy = namespace_storage_policy(ns_info, ctx->ns);
		if (!storage_policy) {
			GSETERROR(error, "Failed to get content storage policy, "
					"cannot check it");

			goto clean_up;
		} else {
			GRID_INFO("No storage policy defined for content, "
					"will use default from namespace: %s", storage_policy);
		}
	}

	ctx->sp = storage_policy_init(ns_info, storage_policy);

clean_up:

	if(storage_policy)
		g_free(storage_policy);

	if(local_error) {
		g_clear_error(&local_error);
		local_error = NULL;
	}
	if(gs_error) {
		gs_error_free(gs_error);
		gs_error = NULL;
	}

	if(ns_info) {
		namespace_info_free(ns_info);
	}
	return ctx;
}

static void
_update_content_info(struct meta2_raw_content_s *p_raw_content,
		struct content_textinfo_s *content_info)
{
	GHashTable *sysmd_ht = NULL;

	content_info->storage_policy = g_strdup(p_raw_content->storage_policy);
	if (!content_info->storage_policy) {
		GRID_TRACE("Stgpol not found in meta2_raw_content, look into sysmd");
		if (p_raw_content->system_metadata) {
			sysmd_ht = metadata_unpack_gba(p_raw_content->system_metadata, NULL);
			content_info->storage_policy = g_strdup(g_hash_table_lookup(sysmd_ht, "storage-policy"));
			g_hash_table_destroy(sysmd_ht);
		}
	}
	if (!content_info->storage_policy) {
		GRID_DEBUG("Stgpol not found, neither in content nor in sysmd");
	}
	if (NULL == content_info->path)
		content_info->path = g_strdup(p_raw_content->path);
	content_info->version = g_strdup_printf("%"G_GINT64_FORMAT, p_raw_content->version);
}

static void
_update_chunk_info(struct meta2_raw_content_s *p_raw_content,
		struct chunk_textinfo_s *chunk_info, GSList **chunk_ids)
{
	gint given_chunk_pos;
	gint _useless_sub;
	gboolean _useless_par;

	if (!m2v2_parse_chunk_position(chunk_info->position,
			&given_chunk_pos, &_useless_par, &_useless_sub))
		return;

	void _find_chunks_at_given_pos(gpointer _raw_chunk, gpointer _unused)
	{
		struct meta2_raw_chunk_s *raw_chunk = _raw_chunk;
		// position is cast from guint32 to gint
		gint current_chunk_pos = raw_chunk->position;
		(void) _unused;
		if (current_chunk_pos == given_chunk_pos) {
			gchar strid[1024], straddr[64];
			chunk_id_to_string(&(raw_chunk->id), strid, sizeof(strid));
			addr_info_to_string(&(raw_chunk->id.addr), straddr, sizeof(straddr));
			*chunk_ids = g_slist_prepend(*chunk_ids, assemble_chunk_id(straddr, raw_chunk->id.vol, strid));
		}
	}
	g_slist_foreach(p_raw_content->raw_chunks, _find_chunks_at_given_pos, NULL);
}

GError *
generate_raw_chunk(check_info_t *info,
		struct meta2_raw_chunk_s *p_raw_chunk)
{
	GError *err = NULL;
	gchar *id_first_char;

	if (!convert_chunk_text_to_raw(info->ck_info, p_raw_chunk, &err)) {
		GRID_INFO("Could not convert text chunk_info to raw [%s]",
				err ? err->message : "no details");
		// Failed conversion may occur upon corrupted chunk id found in attr.
		// Try again with a chunk id generated from file path.
		if (!(id_first_char = strrchr(info->source_path,'/')))
			return err;
		id_first_char++;
		GRID_INFO("Try again conversion with chunk id regenerated from chunk path: [%s].",
				id_first_char);
		g_free(info->ck_info->id);
		// only copy the first 64 chars as there may be an extension
		info->ck_info->id = g_strndup(id_first_char, STRLEN_CHUNKID - 1);
		g_clear_error(&err);
		if (!convert_chunk_text_to_raw(info->ck_info, p_raw_chunk, &err)) {
			g_prefix_error(&err, "Could not convert text chunk_info to raw: [%s]",
					info->ck_info->id);
			return err;
		}
		GRID_INFO("Conversion succeeded.");
	}

	return NULL;
}

void check_result_append_msg(check_result_t *res, const gchar *format, ...)
{
	va_list args;

	if (res) {
		res->check_ok = FALSE;
		if (!res->msg)
			res->msg = g_string_new("");
		else
			g_string_append(res->msg, " ");
		va_start(args, format);
		g_string_append_vprintf(res->msg, format, args);
		va_end(args);
	}
}

void check_result_clear(check_result_t **p_res, void (*free_udata(gpointer)))
{
	if (p_res && *p_res) {
		if ((*p_res)->msg)
			g_string_free((*p_res)->msg, TRUE);
		if ((*p_res)->udata && free_udata)
			free_udata((*p_res)->udata);
		g_free(*p_res);
		*p_res = NULL;
	}
}

check_result_t *check_result_new()
{
	return g_malloc0(sizeof(check_result_t));
}

static GError*
_find_sp_fc_m2v1(const gchar* meta2, check_info_t *check_info,
		GSList **chunk_ids, struct meta2_raw_content_s **p_raw_content)
{
	GError *err = NULL;
	struct meta2_raw_content_s *raw_content = NULL;
	struct metacnx_ctx_s ctx;
	struct meta2_raw_chunk_s raw_chunk;
	struct chunk_textinfo_s *chunk_info = check_info->ck_info;
	struct content_textinfo_s *content_info = check_info->ct_info;
	const gchar *strcid = content_info->container_id;
	container_id_t cid;

	if (NULL != (err = generate_raw_chunk(check_info, &raw_chunk))) {
		return err;
	}

	g_strlcpy(raw_chunk.id.vol, check_info->rawx_vol, sizeof(raw_chunk.id.vol)-1);
	grid_string_to_addrinfo(check_info->rawx_str_addr, NULL, &(raw_chunk.id.addr));

	metacnx_clear(&ctx);
	if (!metacnx_init_with_url(&ctx, meta2, &err)) {
		return NEWERROR(ERRCODE_PARAM,
				"Could not init metacnx from url [%s]", meta2);
	}

	if (!container_id_hex2bin(strcid, strlen(strcid), &cid, &err)) {
		return NEWERROR(ERRCODE_PARAM,
				"Could not convert container id to bin: [%s]", strcid);
	}

	raw_content = meta2raw_remote_get_content_from_chunkid(
			&ctx, &err, cid, &(raw_chunk.id));

	if (raw_content) {
		_update_content_info(raw_content, content_info);
		_update_chunk_info(raw_content, chunk_info, chunk_ids);
		if (p_raw_content)
			*p_raw_content = raw_content;
		else
			meta2_maintenance_destroy_content(raw_content);
	}

	return err;
}

static GError*
_find_sp_fc_m2v2(const gchar* meta2,
		struct hc_url_s *url, check_info_t *check_info, GSList **chunk_ids)
{
	GError *err = NULL;
	GString *policy = NULL;
	GSList *beans = NULL;
	struct chunk_textinfo_s *chunk_info = check_info->ck_info;
	struct content_textinfo_s *content_info = check_info->ct_info;
	gchar *chunk_id;

	chunk_id = assemble_chunk_id(check_info->rawx_str_addr,
			check_info->rawx_vol, chunk_info->id);

	GRID_DEBUG("Url to perform GET_BY_CHUNK: [%s]",
			hc_url_get(url, HCURL_WHOLE));
	GRID_DEBUG("Chunk id to look for: [%s]", chunk_id);

	err = m2v2_remote_execute_GET_BY_CHUNK(meta2, NULL, url,
			chunk_id, 1, &beans);
	if (err != NULL) {
		g_prefix_error(&err, "Could not get contents referencing chunk %s: ",
				chunk_id);
		goto clean_up;
	} else {
		for (GSList *cursor = beans; cursor; cursor = cursor->next) {
			if (DESCR(cursor->data) == &descr_struct_CONTENTS_HEADERS) {
				GString *policy2 = CONTENTS_HEADERS_get_policy(cursor->data);
				if (policy != NULL && policy->len > 0 &&
						policy2 != NULL && policy2->len > 0 &&
						!g_string_equal(policy, policy2)) {
					err = NEWERROR(0, "Found 2 different policies for the same"
							" chunk!!! '%s' and '%s'", policy->str, policy2->str);
					goto clean_up;
				} else {
					policy = policy2;
				}
			} else if (DESCR(cursor->data) == &descr_struct_CONTENTS) {
				gint pos1, pos2;
				gint _sub; // don't care
				gboolean _par; // don't care
				GString *position = CONTENTS_get_position(cursor->data);
				m2v2_parse_chunk_position(position->str, &pos1, &_par, &_sub);
				m2v2_parse_chunk_position(chunk_info->position,
						&pos2, &_par, &_sub);
				// consider chunk only if same position
				if (pos1 == pos2) {
					GString *chunkid = CONTENTS_get_chunk_id(cursor->data);
					*chunk_ids = g_slist_prepend(*chunk_ids,
							g_strdup(chunkid->str));
				}
			} else if (DESCR(cursor->data) == &descr_struct_ALIASES) {
				GString *alias = ALIASES_get_alias(cursor->data);
				gint64 version = ALIASES_get_version(cursor->data);
				GRID_DEBUG("Chunk belongs to '%s' version %ld",
						alias->str, version);
				if (content_info->version == NULL) {
					if (NULL == content_info->path)
						content_info->path = g_strdup(alias->str);
					content_info->version = g_strdup_printf("%"G_GUINT64_FORMAT, version);
				}
			}
		}
		if (policy && policy->len == 0) {
			policy = NULL;
		}
		if (policy) {
			policy = g_string_new(policy->str); // make a copy before cleaning
		}
	}
	if (policy) {
		content_info->storage_policy = g_string_free(policy, FALSE);
		GRID_DEBUG("Storage policy found in content header: '%s'",
				content_info->storage_policy);
	}

clean_up:
	if (err != NULL) {
		g_slist_free_full(*chunk_ids, g_free);
		*chunk_ids = NULL;
	}
	g_free(chunk_id);
	_bean_cleanl2(beans);
	return err;
}

gboolean
is_m2v1(const gchar *meta2)
{
	return NULL != g_slist_find_custom(m2v1_list, meta2, (GCompareFunc) g_strcmp0);
}

void
free_m2v1_list()
{
	if (m2v1_list)
		g_slist_free_full(m2v1_list, g_free);
}

void
add_to_m2v1_list(const gchar *new_m2v1)
{
	m2v1_list = g_slist_prepend(m2v1_list, g_strdup(new_m2v1));
}

GError*
find_storage_policy_and_friend_chunks_full(const gchar* meta2,
		struct hc_url_s *url, check_info_t *check_info,
		GSList **chunk_ids, struct meta2_raw_content_s **p_raw_content)
{
	GError *err = NULL, *err2 = NULL;
	const gboolean is_v1 = is_m2v1(meta2);

	if (!is_v1) {
		GRID_DEBUG("Trying with M2V2 request on m2 [%s] for chunk [%s]",
				meta2, check_info->ck_info->id);
		err = _find_sp_fc_m2v2(meta2, url, check_info, chunk_ids);
		if (!err) {
			if (p_raw_content)
				convert_content_text_to_raw(check_info->ct_info, *p_raw_content, &err);
			return err;
		}
	}
	if (is_v1 || (err != NULL && err->code == 404)) {
		// If error code is 404, try with M2V1 request
		GRID_DEBUG("Trying with M2V1 request on m2 [%s] for chunk [%s]",
				meta2, check_info->ck_info->id);
		err2 = _find_sp_fc_m2v1(meta2, check_info, chunk_ids, p_raw_content);
		if (err2) {
			g_prefix_error(&err, "M2V1 request also failed: [%s] ", err2->message);
			g_clear_error(&err2);
		} else {
			g_clear_error(&err);
			if (!is_v1)
				add_to_m2v1_list(meta2);
		}
	}

	return err;
}

GError*
find_storage_policy_and_friend_chunks(const gchar* meta2,
		struct hc_url_s *url, check_info_t *check_info, GSList **chunk_ids)
{
	return find_storage_policy_and_friend_chunks_full(
			meta2, url, check_info, chunk_ids, NULL);
}

GHashTable *
check_option_new()
{
	return g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
}

void
check_option_destroy(GHashTable *options)
{
	if (options)
		g_hash_table_destroy(options);
}

static gpointer
_get_option(GHashTable *options, const gchar *option_name)
{
	if (!options || !option_name)
		return NULL;
	return g_hash_table_lookup(options, option_name);
}

static void
_set_option(GHashTable *options,
		const gchar *oname, gpointer ovalue)
{
	if (options && oname)
		g_hash_table_insert(options, g_strdup(oname), ovalue);
}

gint
check_option_get_int(GHashTable *options, const gchar *option_name)
{
	gint *optval = _get_option(options, option_name);
	if (optval)
		return *optval;
	return G_MAXINT;
}

gboolean
check_option_get_bool(GHashTable *options, const gchar *option_name)
{
	gboolean *optval = _get_option(options, option_name);
	if (optval)
		return *optval;
	return FALSE;
}

gchar*
check_option_get_str(GHashTable *options, const gchar *option_name)
{
	gchar *optval = _get_option(options, option_name);
	return optval;
}

void
check_option_set_int(GHashTable *options,
		const gchar *oname, gint ovalue)
{
	_set_option(options, oname, g_memdup(&ovalue, sizeof(ovalue)));
}

void
check_option_set_bool(GHashTable *options,
		const gchar *oname, gboolean ovalue)
{
	check_option_set_int(options, oname, ovalue);
}

void
check_option_set_str(GHashTable *options,
		const gchar *oname, const gchar *ovalue)
{
	_set_option(options, oname, g_strdup(ovalue));
}
