#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "rainx.remote"
#endif

#include <glib.h>
#include <curl/curl.h>

#include <meta2v2/autogen.h>
#include "./gs_internals.h"

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

static GError *_find_gaps_and_dispatch_chunks(struct rainx_rec_params_s *params,
		gint k, gint m, GArray *sorted_chunks, gint64 *metachunk_size,
		GSList **gap_positions, GSList **valid_chunks, GSList **broken_chunks)
{
	GError *err = NULL;

	for (gint64 i = 0; i < k + m; i++) {
		m2v2_chunk_pair_t *pair = &g_array_index(sorted_chunks,
				 m2v2_chunk_pair_t, i);
		if (pair->chunk == NULL) {
			// Look for an unavailable chunk matching the gap
			gchar *s_pos = g_strdup_printf("%lu.%s%lu", params->metachunk_pos,
					(i >= k)? "p" : "", (i >= k)? i-k : i);
			GRID_DEBUG("No chunk at position %ld, looking for unavailable chunk '%s'",
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
					GRID_DEBUG("-> found matching broken chunk/content, will reuse hash");
					break;
				}
			}
			if (pair->chunk != NULL) {
				// Save the gap position (in numeric format)
				*gap_positions = g_slist_prepend(*gap_positions, (gpointer)i);
			} else {
				if (i > 0 && i < k) {
					GRID_DEBUG("-> not found, metachunk was probably smaller"
							" than (k-1)*rain_blocksize");
				} else {
					GRID_DEBUG("-> not found, create dummy content");
					// just make a content, chunk bean will be created later
					pair->content = _bean_create(&descr_struct_CONTENTS);
					CONTENTS_set_content_id(pair->content,
							ALIASES_get_content_id(params->alias));
					CONTENTS_set2_position(pair->content, s_pos);
					*gap_positions = g_slist_prepend(*gap_positions, (gpointer)i);
				}
			}
			g_free(s_pos);
		} else {
			*valid_chunks = g_slist_prepend(*valid_chunks, pair->chunk);
			*valid_chunks = g_slist_prepend(*valid_chunks, pair->content);
		}

		// Update metachunk_size
		if (pair->chunk != NULL) {
			if (i < k)
				*metachunk_size += CHUNKS_get_size(pair->chunk);
		}
	}

	// Keep in order
	*gap_positions = g_slist_reverse(*gap_positions);

	return err;
}

static GError *_fill_gaps_with_spares(GArray *sorted_chunks,
		GSList *gap_positions, GSList **spare_chunks,
		GSList **substitutions)
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
			// Chunk was referenced but unavailable, hash is known,
			// we just need the new chunk_id from the spare
			struct bean_CHUNKS_s **subst = g_malloc0_n(2, sizeof(void*));
			subst[0] = _bean_dup(pair->chunk);
			CHUNKS_set_id(pair->chunk, CHUNKS_get_id(spare));
			subst[1] = _bean_dup(pair->chunk);
			*substitutions = g_slist_prepend(*substitutions, subst);
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
	for (guint i = 0, j = 0; i < chunks->len; i++) {
		struct bean_CHUNKS_s *chunk = (&g_array_index(chunks,
				m2v2_chunk_pair_t, i))->chunk;
		if (chunk)
			addrs[j++] = _chunk_url_to_short_form(CHUNKS_get_id(chunk)->str);
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
			// We don't know the hash, but RAINX will fail on empty string.
			hash_str = g_strdup("?");
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

static GError *_ask_reconstruct(struct rainx_rec_params_s *params,
		struct rainx_writer_s *writer, struct hc_url_s *url,
		GArray *sorted_chunks, gint64 metachunk_size, GSList *gap_positions,
		gboolean on_the_fly)
{
	GError *err = NULL;
	gchar rainx_url[128];
	gchar error_buf[CURL_ERROR_SIZE];
	gchar *rawx_list = NULL, *spare_rawx_list = NULL;
	CURL *handle = NULL;
	struct curl_slist *header_list = NULL;
	long error_code = 0;

	memset(rainx_url, 0, sizeof(rainx_url));

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
	if (on_the_fly)
		g_strlcpy(rainx_url + strlen(rainx_url), "/on-the-fly",
				sizeof(rainx_url) - strlen(rainx_url));
	handle = curl_easy_init();
	curl_easy_setopt(handle, CURLOPT_HTTPHEADER, header_list);
	curl_easy_setopt(handle, CURLOPT_URL, rainx_url);
	if (writer && writer->callback) {
		curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, writer->callback);
		if (writer->param) {
			curl_easy_setopt(handle, CURLOPT_WRITEDATA, writer->param);
		}
	} else {
		curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, _drop_curl_data);
	}
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
		struct rainx_rec_params_s *params, struct rainx_writer_s *writer,
		gboolean reuse_broken, gboolean on_the_fly)
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
	// List of chunks that have been substituted (arrays with old and new)
	GSList *substitutions = NULL;

	void _clean_subst(gpointer ptr)
	{
		struct bean_CHUNKS_s **subst = ptr;
		_bean_clean(subst[0]);
		_bean_clean(subst[1]);
		subst[0] = NULL;
		subst[1] = NULL;
		g_free(ptr);
	}

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

	if (!on_the_fly) {
		// Get spare chunks
		m1u = meta1_unpack_url(meta2_addrs[0]);
		err = m2v2_remote_execute_SPARE(m1u->host, NULL, url,
				CONTENTS_HEADERS_get_policy(params->content_header)->str,
				valid_chunks, reuse_broken? NULL : broken_chunks, &spare_chunks);
		if (err != NULL)
			goto global_cleanup;

		// Travel gap_positions list and fix chunks
		err = _fill_gaps_with_spares(sorted_chunks, gap_positions, &spare_chunks,
				&substitutions);
		if (err != NULL)
			goto global_cleanup;
	}

	// Ask rainx for reconstruction
	err = _ask_reconstruct(params, writer, url, sorted_chunks, metachunk_size,
			gap_positions, on_the_fly);
	if (err != NULL) {
		goto global_cleanup;
	}

/*	// TODO: this is commented because useless at the moment, see next TODO.
	// Send new chunks to meta2
	for (gint i = sorted_chunks->len -1; i >= 0; i--) {
		m2v2_chunk_pair_t *pair = NULL;
		pair = &g_array_index(sorted_chunks, m2v2_chunk_pair_t, i);
		final_beans = g_slist_prepend(final_beans, pair->chunk);
		final_beans = g_slist_prepend(final_beans, pair->content);
	}
	final_beans = g_slist_prepend(final_beans, params->content_header);
	final_beans = g_slist_prepend(final_beans, params->alias);
*/

	if (!on_the_fly) {
		GRID_DEBUG("Updating '%s' with new chunks",
				ALIASES_get_alias(params->alias)->str);
		for (GSList *l = substitutions; l; l = l->next) {
			struct bean_CHUNKS_s **subst = l->data;
			err = m2v2_remote_execute_SUBST_CHUNKS_single(m1u->host, NULL, url,
					subst[1], subst[0], FALSE);
			if (err != NULL)
				goto global_cleanup;
		}


		if (broken_chunks) {
			// Remove broken chunks from meta2
			GRID_DEBUG("Removing broken chunks from '%s'",
					ALIASES_get_alias(params->alias)->str);
			err = m2v2_remote_execute_RAW_DEL(m1u->host, NULL, url, broken_chunks);
		} else {
			GRID_DEBUG("Some reconstructed chunks may still be unreferenced!");
			// TODO: Chunk we repaired were unreferenced, so they are not in
			// broken_chunks, and substitution won't work.
			// We will have to reference them again.
		}
	}

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
	g_slist_free_full(substitutions, _clean_subst);
	return err;
}

struct rainx_rec_params_s *rainx_rec_params_build(GSList *beans,
		GSList *broken_chunk_ids, gint64 position)
{
	struct rainx_rec_params_s *params = g_malloc0(
			sizeof(struct rainx_rec_params_s));
	params->metachunk_pos = position;
	params->data_chunk_pairs = g_array_new(FALSE, TRUE,
			sizeof(m2v2_chunk_pair_t));
	params->parity_chunk_pairs = g_array_new(FALSE, TRUE,
			sizeof(m2v2_chunk_pair_t));
	params->unavail_chunk_pairs = g_array_new(FALSE, TRUE,
			sizeof(m2v2_chunk_pair_t));

	// Calling func can pass all chunks beans (not just chunks of the broken
	// metachunk), so it's better to use a hash table to do the matching.
	GHashTable *chunks = g_hash_table_new(g_str_hash, g_str_equal);

	// Initialize chunk pairs for the broken metachunk and index chunk beans
	for (GSList *l = beans; l; l = l->next) {
		if (DESCR(l->data) == &descr_struct_CONTENTS) {
			gint pos = 0, par = 0, sub = 0;
			m2v2_parse_chunk_position(
					CONTENTS_get_position(l->data)->str,
					&pos, &par, &sub);
			if (pos == position) {
				m2v2_chunk_pair_t pair = {l->data, NULL};
				if (par) {
					g_array_append_val(params->parity_chunk_pairs, pair);
				} else {
					g_array_append_val(params->data_chunk_pairs, pair);
				}
			}
		} else if (DESCR(l->data) == &descr_struct_CHUNKS) {
			g_hash_table_insert(chunks, CHUNKS_get_id(l->data)->str, l->data);
		} else if (DESCR(l->data) == &descr_struct_ALIASES) {
			params->alias = l->data;
		} else if (DESCR(l->data) == &descr_struct_CONTENTS_HEADERS) {
			params->content_header = l->data;
		}
	}

	// Associate chunk beans to content data beans
	for (guint i = 0; i < params->data_chunk_pairs->len; i++) {
		m2v2_chunk_pair_t *pair = &g_array_index(params->data_chunk_pairs,
				m2v2_chunk_pair_t, i);
		gchar *id = CONTENTS_get_chunk_id(pair->content)->str;
		pair->chunk = g_hash_table_lookup(chunks, id);
		if (!pair->chunk)
			GRID_WARN("No chunk bean found for [%s]", id);
	}
	// Associate chunk beans to content parity beans
	for (guint i = 0; i < params->parity_chunk_pairs->len; i++) {
		m2v2_chunk_pair_t *pair = &g_array_index(params->parity_chunk_pairs,
				m2v2_chunk_pair_t, i);
		gchar *id = CONTENTS_get_chunk_id(pair->content)->str;
		pair->chunk = g_hash_table_lookup(chunks, id);
		if (!pair->chunk)
			GRID_WARN("No chunk bean found for [%s]", id);
	}

	// Move broken chunk pairs out of params->data_chunk_pairs
	for (GSList *l = broken_chunk_ids; l; l = l->next) {
		for (guint i = 0; i < params->data_chunk_pairs->len; i++) {
			m2v2_chunk_pair_t *pair = &g_array_index(params->data_chunk_pairs,
				m2v2_chunk_pair_t, i);
			if (!g_strcmp0(l->data, CHUNKS_get_id(pair->chunk)->str)) {
				g_array_append_val(params->unavail_chunk_pairs, *pair);
				g_array_remove_index_fast(params->data_chunk_pairs, i);
				break;
			}
		}
	}
	// Move broken chunk pairs out of params->parity_chunk_pairs
	for (GSList *l = broken_chunk_ids; l; l = l->next) {
		for (guint i = 0; i < params->parity_chunk_pairs->len; i++) {
			m2v2_chunk_pair_t *pair = &g_array_index(params->parity_chunk_pairs,
				m2v2_chunk_pair_t, i);
			if (!g_strcmp0(l->data, CHUNKS_get_id(pair->chunk)->str)) {
				g_array_append_val(params->unavail_chunk_pairs, *pair);
				g_array_remove_index_fast(params->parity_chunk_pairs, i);
				break;
			}
		}
	}

	g_hash_table_destroy(chunks);

	GRID_DEBUG("Chunks: %d data, %d parity, %d unavailable",
		params->data_chunk_pairs->len, params->parity_chunk_pairs->len,
		params->unavail_chunk_pairs->len);

	return params;
}

void rainx_rec_params_free(struct rainx_rec_params_s *params)
{
	if (!params)
		return;
	g_array_unref(params->data_chunk_pairs);
	g_array_unref(params->parity_chunk_pairs);
	g_array_unref(params->unavail_chunk_pairs);
	memset(params, 0, sizeof(struct rainx_rec_params_s));
}

