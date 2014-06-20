#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "rainx.remote"
#endif

#include "./gs_internals.h"
#include <curl/curl.h>

static GError *_fill_sorted_chunk_array(GArray *in, GArray *sorted_chunks,
		gint64 k)
{
	gboolean ok = FALSE;
	GError *err = NULL;
	for (guint i = 0; i < in->len; i++) {
		m2v2_chunk_pair_t *pair = &g_array_index(in, m2v2_chunk_pair_t, i);
		gint pos, par, sub = 0;
		ok = m2v2_parse_chunk_position(CONTENTS_get_position(pair->content)->str,
				&pos, &par, &sub);
		if (!ok) {
			err = NEWERROR(CODE_INTERNAL_ERROR,
					"Failed to parse chunk position '%s': %s",
					CONTENTS_get_position(pair->content)->str,
					(errno != 0)? g_strerror(errno) : "unknown reason");
			break;
		}
		if (par)
			sub += k;
		GRID_TRACE("Filling chunk array pos %d with chunk %s", sub,
				CONTENTS_get_position(pair->content)->str);
		/* We must make copies because we are not capable of making
		 * difference between externally an internally created beans at
		 * the time of cleaning. */
		m2v2_chunk_pair_t new_pair = {NULL, NULL};
		if (pair->chunk != NULL)
			new_pair.chunk = _bean_dup(pair->chunk);
		new_pair.content = _bean_dup(pair->content);
		g_array_index(sorted_chunks, m2v2_chunk_pair_t, sub) = new_pair;
	}
	return err;
}

static GError *_find_gaps_and_dispatch_chunks(struct rainx_params_s *params,
		gint k, gint m, GArray *sorted_chunks, gint64 *metachunk_size,
		GSList **gap_positions, GSList **valid_chunks, GSList **broken_chunks)
{
	GError *err = NULL;
	gint64 max_chunk_size = 0;
	gint really_missing_count = 0;

	for (gint64 i = 0; i < k + m; i++) {
		m2v2_chunk_pair_t *pair = &g_array_index(sorted_chunks,
				 m2v2_chunk_pair_t, i);
		if (pair->chunk == NULL) {
			// Save the gap position (in numeric format)
			*gap_positions = g_slist_prepend(*gap_positions, (gpointer)i);
			// Look for an unavailable chunk matching the gap
			gchar *s_pos = g_strdup_printf("%lu.%s%lu", params->metachunk_pos,
					(i >= k)? "p" : "", (i >= k)? i-k : i);
			GRID_DEBUG("Missing chunk at position %ld, looking for unavailable chunk '%s'",
					i, s_pos);
			for (guint j = 0; j < params->unavail_chunk_pairs->len; j++) {
				m2v2_chunk_pair_t *pair2 = &g_array_index(
						params->unavail_chunk_pairs, m2v2_chunk_pair_t, j);
				// Compare position and content id (in that order)
				if (!strcmp(s_pos, CONTENTS_get_position(pair2->content)->str) &&
						!metautils_gba_cmp(ALIASES_get_content_id(params->alias),
						CONTENTS_get_content_id(pair2->content))) {
					pair->content = _bean_dup(pair2->content);
					pair->chunk = _bean_dup(pair2->chunk);
					*broken_chunks = g_slist_prepend(*broken_chunks, pair2->chunk);
					*broken_chunks = g_slist_prepend(*broken_chunks, pair2->content);
					GRID_DEBUG("-> found matching broken chunk/content, will reuse hash");
					break;
				}
			}
			// Not found, create dummy content
			if (pair->chunk == NULL) {
				GRID_DEBUG("-> not found, create dummy content");
				// just make a content, chunk bean will be created later
				pair->content = _bean_create(&descr_struct_CONTENTS);
				CONTENTS_set_content_id(pair->content,
						ALIASES_get_content_id(params->alias));
				CONTENTS_set2_position(pair->content, s_pos);
				// Count only data chunks
				if (i < k)
					really_missing_count++;
			}
			g_free(s_pos);
		} else {
			*valid_chunks = g_slist_prepend(*valid_chunks, pair->chunk);
			*valid_chunks = g_slist_prepend(*valid_chunks, pair->content);
		}

		// Update metachunk_size and max_chunk_size
		if (pair->chunk != NULL) {
			if (CHUNKS_get_size(pair->chunk) > max_chunk_size)
				max_chunk_size = CHUNKS_get_size(pair->chunk);
			if (i < k)
				*metachunk_size += CHUNKS_get_size(pair->chunk);
		}
	}

	// Suppose that missing chunks are of maximum size
	*metachunk_size += really_missing_count * max_chunk_size;
	// Keep in order
	*gap_positions = g_slist_reverse(*gap_positions);

	return err;
}

static GError *_fill_gaps_with_spares(GArray *sorted_chunks,
		GSList *gap_positions, GSList **spare_chunks)
{
	GError *err = NULL;
	if (g_slist_length(*spare_chunks) < g_slist_length(gap_positions)) {
		err = NEWERROR(CODE_INTERNAL_ERROR, "not enough spare chunks (%d/%d)",
				g_slist_length(*spare_chunks), g_slist_length(gap_positions));
	}
	for (GSList *l = gap_positions; l != NULL && err == NULL; l = l->next) {
		gint64 gap_pos = (gint64) l->data;
		struct bean_CHUNKS_s *spare = (struct bean_CHUNKS_s *)(*spare_chunks)->data;
		m2v2_chunk_pair_t *pair = &g_array_index(sorted_chunks,
				 m2v2_chunk_pair_t, gap_pos);
		GRID_DEBUG("Using spare chunk at position %"G_GINT64_FORMAT, gap_pos);
		if (pair->chunk == NULL) {
			// Chunk was lost, hash is still empty
			pair->chunk = spare;
		} else {
			// Chunk was referenced but unavailable, hash is known
			CHUNKS_set_id(pair->chunk, CHUNKS_get_id(spare));
			_bean_clean(spare);
		}
		CONTENTS_set_chunk_id(pair->content, CHUNKS_get_id(pair->chunk));
		*spare_chunks = g_slist_remove(*spare_chunks, spare);
	}
	return err;
}

static gchar *_chunk_url_to_short_form(const gchar *url)
{
	const gchar *end = NULL;
	const gchar *start = strstr(url, "//");
	const gchar *hex_id = strrchr(url, '/');

	if (start != NULL)
		start += 2; // skip "//"
	else
		start = url;

	end = strchr(start, '/');

	return g_strdup_printf("%.*s%s", (int)(end - start), start, hex_id);
}

static gchar *_build_piped_rawx_list(GArray *chunks)
{
	gchar *res = NULL;
	gchar **addrs = g_malloc0_n(chunks->len + 1, sizeof(gchar*));
	for (guint i = 0; i < chunks->len; i++) {
		struct bean_CHUNKS_s *chunk = (&g_array_index(chunks,
				m2v2_chunk_pair_t, i))->chunk;
		addrs[i] = _chunk_url_to_short_form(CHUNKS_get_id(chunk)->str);
	}
	res = g_strjoinv("|", addrs);
	g_strfreev(addrs);
	return res;
}

static gchar *_build_semicol_spare_rawx_list(GArray *chunks,
		GSList *gap_positions)
{
	gchar *hash_str = NULL;
	GString *res = g_string_sized_new(64);
	for (GSList *l = gap_positions; l != NULL; l = l->next) {
		gint64 pos = (gint64)l->data;
		m2v2_chunk_pair_t *pair = &g_array_index(chunks, m2v2_chunk_pair_t, pos);
		gchar *cid = _chunk_url_to_short_form(CHUNKS_get_id(pair->chunk)->str);
		GByteArray *hash_gba = CHUNKS_get_hash(pair->chunk);
		if (hash_gba == NULL || hash_gba->len == 0) {
			hash_str = g_strdup("");
		} else {
			GString *hash = metautils_gba_to_hexgstr(NULL,
					CHUNKS_get_hash(pair->chunk));
			hash_str = g_string_free(hash, FALSE);
		}
		g_string_append_printf(res, "%s|%ld|%s;", cid, pos, hash_str);
		g_free(hash_str);
		g_free(cid);
		hash_str = NULL;
	}
	res = g_string_truncate(res, res->len-1);
	return g_string_free(res, FALSE);
}

static size_t _drop_curl_data(void *buffer, size_t size, size_t nmemb,
		void *userp)
{
	(void) buffer;
	(void) userp;
	return size * nmemb;
}

static GError *_ask_reconstruct(struct rainx_params_s *params,
		struct hc_url_s *url, GArray *sorted_chunks, gint64 metachunk_size,
		GSList *gap_positions)
{
	GError *err = NULL;
	gchar rainx_url[128];
	gchar error_buf[CURL_ERROR_SIZE];
	gchar *rawx_list = NULL, *spare_rawx_list = NULL;
	CURL *handle = NULL;
	struct curl_slist *header_list = NULL;
	long error_code = 0;

	// Build string rawx lists
	rawx_list = _build_piped_rawx_list(sorted_chunks);
	spare_rawx_list = _build_semicol_spare_rawx_list(sorted_chunks, gap_positions);

#define ADD_HEADER(header,valueformat,value) do {\
	gchar buf[1024];\
	g_snprintf(buf, 1024, "%s: "valueformat, (header), (value));\
	header_list = curl_slist_append(header_list, buf);\
} while (0)

	ADD_HEADER("storagepolicy", "%s",
			CONTENTS_HEADERS_get_policy(params->content_header)->str);
	ADD_HEADER("rawxlist", "%s", rawx_list);
	ADD_HEADER("sparerawxlist", "%s", spare_rawx_list);
	ADD_HEADER("containerid", "%s", hc_url_get(url, HCURL_HEXID));
	ADD_HEADER("chunknb", "%d", 1);
	ADD_HEADER("contentpath", "%s", ALIASES_get_alias(params->alias)->str);
	ADD_HEADER("contentsize", "%ld",
			CONTENTS_HEADERS_get_size(params->content_header));
	ADD_HEADER("chunksize", "%ld", metachunk_size); // Size of the metachunk
	ADD_HEADER("chunkpos", "%ld", params->metachunk_pos); // Position of the metachunk
	ADD_HEADER("contentmetadata-sys", "%s", ALIASES_get_mdsys(params->alias)->str);
	ADD_HEADER("namespace", "%s", hc_url_get(url, HCURL_NS));

#undef ADD_HEADER

	struct service_info_s *si = get_one_namespace_service(
			hc_url_get(url, HCURL_NS), "rainx", &err);
	if (!si) {
		if (err != NULL)
			GSETCODE(&err, 500, "Unknown error");
		goto reconstruct_cleanup;
	} else {
		addr_info_to_string(&(si->addr), rainx_url+7, sizeof(rainx_url)-7);
		service_info_clean(si);
		si = NULL;
	}

	strncpy(rainx_url, "http://", 7);
	handle = curl_easy_init();
	curl_easy_setopt(handle, CURLOPT_HTTPHEADER, header_list);
	curl_easy_setopt(handle, CURLOPT_URL, rainx_url);
	curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, _drop_curl_data);
	curl_easy_setopt(handle, CURLOPT_ERRORBUFFER, error_buf);

	GRID_DEBUG("Calling rainx at %s for reconstruction...", rainx_url);
	CURLcode rc = curl_easy_perform(handle);
	curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &error_code);
	if (rc != 0) {
		err = NEWERROR(CODE_INTERNAL_ERROR, "request failed (%d): %s",
				rc, error_buf);
	} else if (error_code != 200) {
		err = NEWERROR(CODE_INTERNAL_ERROR, "reconstruction failed (code %ld)",
				error_code);
	} else {
		GRID_DEBUG("Reconstruction succeeded (%ld)", error_code);
	}

reconstruct_cleanup:
	if (handle != NULL)
		curl_easy_cleanup(handle);
	if (header_list != NULL)
		curl_slist_free_all(header_list);

	g_free(spare_rawx_list);
	g_free(rawx_list);

	return err;
}

static void _free_sorted_chunks(GArray *sorted_chunks)
{
	for (guint i = 0; i < sorted_chunks->len; i++) {
		m2v2_chunk_pair_t *pair = &g_array_index(sorted_chunks, m2v2_chunk_pair_t, i);
		_bean_clean(pair->chunk);
		pair->chunk = NULL;
		_bean_clean(pair->content);
		pair->content = NULL;
	}
	g_array_free(sorted_chunks, TRUE);
}

GError *rainx_reconstruct(struct hc_url_s *url, namespace_info_t *nsinfo,
		struct rainx_params_s *params, gboolean reuse_broken)
{
	GError *err = NULL;
	struct meta1_service_url_s *m1u = NULL;
	gchar **meta2_addrs = NULL;
	struct hc_resolver_s* resolver = NULL;
	gint64 k = 1, m = 0;
	gint64 metachunk_size = 0;
	// List of integer positions of the missing/broken chunks
	GSList *gap_positions = NULL;
	// List of valid chunks and contents beans (do not free data)
	GSList *valid_chunks = NULL;
	// List of broken chunks and contents beans (do not free data)
	GSList *broken_chunks = NULL;
	// List of spare chunks beans (please free data)
	GSList *spare_chunks = NULL;
	// Complete list of final beans (do not free data)
	GSList *final_beans = NULL;
	// Array of chunk pairs, sorted by position (please free data)
	GArray *sorted_chunks = NULL;

	GRID_TRACE("%s(alias: '%s', data: %d, parity: %d, unavail: %d)",
			__FUNCTION__, ALIASES_get_alias(params->alias)->str,
			params->data_chunk_pairs->len, params->parity_chunk_pairs->len,
			params->unavail_chunk_pairs->len);

	stg_pol_rainx_get_param(nsinfo,
			CONTENTS_HEADERS_get_policy(params->content_header)->str,
			DS_KEY_K, &k);
	stg_pol_rainx_get_param(nsinfo,
			CONTENTS_HEADERS_get_policy(params->content_header)->str,
			DS_KEY_M, &m);

	sorted_chunks = g_array_sized_new(TRUE, TRUE,
			sizeof(m2v2_chunk_pair_t), k + m);
	g_array_set_size(sorted_chunks, k + m);

	// Browse the chunk pair arrays, and build an ordered one with gaps
	err = _fill_sorted_chunk_array(params->data_chunk_pairs, sorted_chunks, k);
	if (err != NULL)
		goto global_cleanup;
	err = _fill_sorted_chunk_array(params->parity_chunk_pairs, sorted_chunks, k);
	if (err != NULL)
		goto global_cleanup;

	// Look for gaps in the ordered chunk pair array
	err = _find_gaps_and_dispatch_chunks(params, k, m, sorted_chunks,
			&metachunk_size, &gap_positions, &valid_chunks, &broken_chunks);
	if (err != NULL)
		goto global_cleanup;

	resolver = hc_resolver_create();
	err = hc_resolve_reference_service(resolver, url, "meta2", &meta2_addrs);
	if (err != NULL)
		goto global_cleanup;

	// Get spare chunks
	m1u = meta1_unpack_url(meta2_addrs[0]);
	err = m2v2_remote_execute_SPARE(m1u->host, NULL, url,
			CONTENTS_HEADERS_get_policy(params->content_header)->str,
			valid_chunks, reuse_broken? NULL : broken_chunks, &spare_chunks);
	if (err != NULL)
		goto global_cleanup;

	// Travel gap_positions list and fix chunks
	err = _fill_gaps_with_spares(sorted_chunks, gap_positions, &spare_chunks);
	if (err != NULL)
		goto global_cleanup;

	// Ask rainx for reconstruction
	err = _ask_reconstruct(params, url, sorted_chunks, metachunk_size,
			gap_positions);
	if (err != NULL) {
		goto global_cleanup;
	}

	// Send new chunks to meta2
	for (gint i = sorted_chunks->len -1; i >= 0; i--) {
		m2v2_chunk_pair_t *pair = NULL;
		pair = &g_array_index(sorted_chunks, m2v2_chunk_pair_t, i);
		final_beans = g_slist_prepend(final_beans, pair->chunk);
		final_beans = g_slist_prepend(final_beans, pair->content);
	}
	final_beans = g_slist_prepend(final_beans, params->content_header);
	final_beans = g_slist_prepend(final_beans, params->alias);
	GRID_DEBUG("Updating '%s' with new chunks",
			ALIASES_get_alias(params->alias)->str);
	err = m2v2_remote_execute_OVERWRITE(m1u->host, NULL, url, final_beans);
	if (err != NULL)
		goto global_cleanup;

	// Remove broken chunks from meta2
	GRID_DEBUG("Removing broken chunks from '%s'",
			ALIASES_get_alias(params->alias)->str);
	err = m2v2_remote_execute_RAW_DEL(m1u->host, NULL, url, broken_chunks);

global_cleanup:
	meta1_service_url_clean(m1u);
	hc_resolver_destroy(resolver);
	g_strfreev(meta2_addrs);
	g_slist_free(gap_positions);
	_free_sorted_chunks(sorted_chunks);
	_bean_cleanl2(spare_chunks); // is probably already NULL
	g_slist_free(broken_chunks);
	g_slist_free(valid_chunks);
	g_slist_free(final_beans);
	return err;
}

