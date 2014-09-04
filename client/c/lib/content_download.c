#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.client.download"
#endif

#include <glib.h>

#include "./gs_internals.h"

static void
download_debug(struct dl_status_s *status, gs_content_t *content, const gchar *msg)
{
#if 1
	if (!DEBUG_ENABLED())
		return;

	DEBUG("GRID download : %s [%s/%s]"
		" content{offset=%"G_GINT64_FORMAT";size=%"G_GINT64_FORMAT";already=%"G_GINT64_FORMAT"}"
		" chunk{start=%"G_GINT64_FORMAT";dl_offset=%"G_GINT64_FORMAT";dl_size=%"G_GINT64_FORMAT";total=%"G_GINT64_FORMAT"}"
		" retry{pos=%d;attempts=%d}",
			msg, C1_NAME(content), C1_PATH(content),
			status->dl_info.offset, status->dl_info.size, status->content_dl, 
			status->chunk_start_offset, status->chunk_dl_offset, status->chunk_dl_size, status->chunk_dl,
			status->last_position, status->last_position_attempts);
#else
	syslog(LOG_DEBUG, "GRID download : %s [%s/%s]"
		" content{offset=%"G_GINT64_FORMAT";size=%"G_GINT64_FORMAT";already=%"G_GINT64_FORMAT"}"
		" chunk{start=%"G_GINT64_FORMAT";dl_offset=%"G_GINT64_FORMAT";dl_size=%"G_GINT64_FORMAT";total=%"G_GINT64_FORMAT"}"
		" retry{pos=%d;attempts=%d}",
			msg, C1_NAME(content), C1_PATH(content),
			status->dl_info.offset, status->dl_info.size, status->content_dl, 
			status->chunk_start_offset, status->chunk_dl_offset, status->chunk_dl_size, status->chunk_dl,
			status->last_position, status->last_position_attempts);
#endif
}

/**
 * Downloads one agregate of chunks.
 *
 * Runs the list of chunks in the agregate (replications of the same chunk)
 * until enough bytes have been download for this chunk. Note that when
 * exiting from the donload, there are only 3 cases possible:
 *  1) all the bytes have been read and managed by the caller (this includes the case of a caller that asked to stop)
 *  2) the RAWX could not be contacted (this only case allows retries)
 *  3) the caller made an error
 *
 * @param agregate the list of chunks replicates
 * @param dl_orig
 * @param dl the up-to-date information about what have been downloaded successfully downlaoded yet
 * @param offset_chunk
 * @param err
 * 
 * @return
 */
static chunk_info_t*
download_agregate(gs_content_t *content, GSList *agregate, struct dl_status_s *status,
		gboolean *may_reload, GSList **p_broken_rawx_list, GError **gerr)
{
	GSList *l;
	GError *local_gerr = NULL;
	GError *local_gerr2 = NULL;
	struct  dl_status_s statusTmp;

	*may_reload = FALSE;

	gboolean previousError = FALSE;

memcpy(&statusTmp, status, sizeof(struct dl_status_s));

	for (l=agregate; l ;l=l->next) {
		gs_chunk_t dummy_chunk;
		dummy_chunk.content = content;
		dummy_chunk.ci = l->data;

/* init val defaut if re-load */
		memcpy(status, &statusTmp, sizeof(struct dl_status_s));

		if (rawx_download(&dummy_chunk, &local_gerr, status, p_broken_rawx_list)) {
			download_debug(status, content, "chunk download succeeded");
			*may_reload = FALSE;
			if (local_gerr)
				g_clear_error(&local_gerr);

			return l->data;
		}


		if (status->caller_error) {
			download_debug(status, content, "chunk download error due to caller");
			*may_reload = FALSE;
			if (local_gerr)
				g_clear_error(&local_gerr);

			return NULL;
		}


		if (status->content_dl > statusTmp.content_dl) {
			ftruncate(*((int *) status->dl_info.user_data), statusTmp.content_dl);
			lseek(*((int *) status->dl_info.user_data), statusTmp.content_dl, SEEK_SET);
		}

		/* then an error with the rawx happened, retry is possible */
		switch (local_gerr->code) {
			case CODE_CONTENT_CORRUPTED:
				/* some bad bytes have been served to the client calback,
				 * we cannot continue and think it is OK! */
				rawx_set_corrupted(&dummy_chunk, &local_gerr2);
				if (local_gerr2) {
					g_propagate_prefixed_error(gerr, local_gerr2,
						"corruption detected: %s, and rename failed: ",
						local_gerr->message);
					(*gerr)->code = CODE_CONTENT_CORRUPTED;
				} else {
					GSETCODE(gerr, CODE_CONTENT_CORRUPTED,
							"corruption detected: %s", local_gerr->message);
				}

				break;
			case CODE_NETWORK_ERROR:
				if ( previousError && (*gerr)->code != local_gerr->code) {
					GSETCODE(gerr,CODE_PLATFORM_ERROR,"chunk download error, platform error");
				} else {
					GSETCODE(gerr,CODE_NETWORK_ERROR, "service unavailable");
				}

				break;
			case 1404:/* NOT FOUND */
			case 1410:/* GONE */
			case 1416:/* RANGE NOT SATISFIABLE */
				if ( previousError && (*gerr)->code != local_gerr->code) {
                                        GSETCODE(gerr,CODE_PLATFORM_ERROR,"chunk download error, platform error");
                                } else {
					GSETCODE(gerr,CODE_CONTENT_UNCOMPLETE, "Missing chunk");
				}
				*may_reload = TRUE;
				download_debug(status, content, "chunk download error, reload possible");
				break;
			default:
				download_debug(status, content, "chunk download error");
				break;
		}

		previousError = TRUE;
	}

	if (local_gerr)
                g_clear_error(&local_gerr);
	GSETERROR(gerr, "Chunk agregate not/partially downloaded");
	return NULL;
}

/**
 * Returns the next chunk aggregate corresponding to the wanted offset (status argument)
 * and updates the 
 * @return an element of the 'agregates' list
 */
static GSList *
download_jump_to_target(GSList *agregates, struct dl_status_s *status, chunk_info_t **p_failed_ci, gs_error_t **gserr)
{
	GSList *ag, *chunks;
	chunk_info_t *ci = NULL;
	int64_t wanted_offset, remaining_size;
	
	status->caller_error = FALSE;
	status->chunk_start_offset = 0LL;
	status->chunk_dl_offset = 0LL;
	status->chunk_dl_size = 0LL;
	wanted_offset = status->dl_info.offset + status->content_dl;
	remaining_size = status->dl_info.size - status->content_dl;

	chunks = agregates->data;
	ci = chunks->data;


	for (ag=agregates; ag ; ag=ag->next, status->chunk_start_offset += ci->size) {
		chunks = ag->data;
		ci = chunks->data;

		if (wanted_offset < status->chunk_start_offset + ci->size) {

			/* Manage the attempts counter to avoid looping infinitely
			 * on the same chunks agregate */
			if (ci->position != status->last_position) {
				status->chunk_dl = 0LL;
				status->last_position_attempts = 0U;
				status->last_position = ci->position;
			}

			status->last_position_attempts ++;

			if (status->last_position_attempts > NB_DOWNLOADS_GET) {
				GSERRORSET(gserr, "Too many DL attempts on agregate %d", ci->position);
				if (p_failed_ci)
					*p_failed_ci = ci;
				return NULL;
			}

			/* We found the right and it is not used to much, try it */
			status->chunk_dl_offset = wanted_offset - status->chunk_start_offset;
			status->chunk_dl_size = ci->size - status->chunk_dl_offset;
			status->chunk_dl_size = MIN(status->chunk_dl_size, remaining_size);

			return ag;
		}
	}


	GSERRORSET(gserr, "Offset/Size pair not satisfiable");
	return NULL;
}

static gboolean
download_terminated(struct dl_status_s *status)
{
	return /*status->caller_stopped ||*/ status->caller_error
		|| (status->content_dl >= status->dl_info.size);
}

static gboolean
agregate_chunks(GSList **result, gs_content_t *content, gs_error_t **err)
{
	GSList *list;

	list = g_slist_reverse(g_slist_agregate(content->chunk_list, chunkinfo_sort_position_DESC));

	DEBUG("%u chunks in %u agregates", g_slist_length(content->chunk_list), g_slist_length(list));

	if (GS_OK != gs_check_chunk_agregate(list, err)) {
		g_slist_free_agregated(list);
		return FALSE;
	}

	if (*result)
		g_slist_free_agregated(*result);

	*result = list;
	return TRUE;
}

static gboolean
reload_and_agregate_chunks(GSList **result, gs_content_t *content, gs_error_t **err)
{
	if (*result) {
		g_slist_free_agregated(*result);
		*result = NULL;
	}

	gs_decache_chunks_in_metacd(content);

	if (!gs_content_reload(content, TRUE, TRUE, err))
		return FALSE;
	if (!agregate_chunks(result, content, err))
		return FALSE;
	return TRUE;
}

gs_status_t
gs_download_content (gs_content_t *content, gs_download_info_t *dl_info, gs_error_t **err)
{
	return gs_download_content_full(content, dl_info, NULL, NULL, NULL, err);
}

/**
 * Get a list of chunk URLs (gchar*) from a list of (chunk_info_t*).
 * The list may contain duplicates. Free the values with g_free().
 */
static GSList*
_chunk_ids_from_chunk_info_list(GSList *ci_list)
{
	GSList *out = NULL;
	for (; ci_list; ci_list = ci_list->next) {
		chunk_info_t *ci = ci_list->data;
		gchar buf1[STRLEN_ADDRINFO], buf2[STRLEN_CHUNKID];
		grid_addrinfo_to_string(&(ci->id.addr), buf1, STRLEN_ADDRINFO);
		// Container id and chunk id are both hash_sha256_t
		container_id_to_string(ci->id.id, buf2, STRLEN_CHUNKID);
		gchar *str_cid = assemble_chunk_id(buf1, ci->id.vol, buf2);
		out = g_slist_prepend(out, str_cid);
	}
	return out;
}

gs_status_t
gs_download_content_full (gs_content_t *content, gs_download_info_t *dl_info,
		const char *stgpol, void *_filtered, void *_beans, gs_error_t **err)
{
	struct dl_status_s status, status_copy, status_at_first_error;
	GSList *agregated_chunks;
	int remaining_reloads = NB_RELOADS_GET;
	gboolean is_rainx = FALSE, is_last_subchunk = TRUE;
	GError *local_gerr = NULL;
	GSList *broken_rawx_list = NULL, *local_filtered = NULL, *local_beans = NULL;
	GHashTable *failed_chunks = NULL;
	chunk_info_t *cur_chunk = NULL, *failed_ci = NULL;
	gboolean may_reload = FALSE;
	GSList *next_agregate = NULL;
	gs_status_t ret = GS_ERROR;
	// I don't know what this parameter was used for
	(void) _filtered;
	GSList *beans = _beans;
	guint k = 0, m = 0;
	gint64 k_signed, m_signed;
	chunk_info_t *ci = NULL;
	const guint nb_data_chunks = g_slist_length(content->chunk_list);
	struct hc_url_s *url = NULL;

	/*check the parameters*/
	if (!content || !dl_info) {
		GSERRORSET(err, "Invalid parameter");
		return GS_ERROR;
	}
	if (dl_info->offset < 0LL) {
		GSERRORSET(err, "Negative download offset");
		return GS_ERROR;
	}
	if (dl_info->size < 0LL) {
		GSERRORSET(err, "Negative download size");
		return GS_ERROR;
	}

	/* If zero/negative size is specified, download the whole content */
	agregated_chunks = NULL;
	bzero(&status, sizeof(status));
	memcpy(&(status.dl_info), dl_info, sizeof(status.dl_info));

	/* (lazy) reload of the content's chunks */
	if (!content->chunk_list) {
		if (!gs_content_reload_with_filtered(content, TRUE, TRUE, &local_filtered, &local_beans, err)) {
			GSERRORSET(err,"Cannot get the chunks of '%s'", content->info.path);
			return GS_ERROR;
		}
	}

	/* Overwrite storage policy by the real one */
	stgpol = content->policy;
	is_rainx = stg_pol_is_rainx(&(content->info.container->info.gs->ni), stgpol);

	/* Sanity checks on the data boundaries. These checks must be performed
	 * after the (lazy) chunks reload because the content's size might be
	 * unknown */
	if (status.dl_info.size == 0LL) {
		if (status.dl_info.offset == 0LL) {/* download everything */
			status.dl_info.size = content->info.size;
			status.dl_info.offset = 0LL;
		} else { /* Download everything between the offset and the end */
			status.dl_info.size = content->info.size - status.dl_info.offset;
		}
	}
	else {
		if (status.dl_info.offset == 0LL)
			status.dl_info.offset = 0LL;
	}
	if ((status.dl_info.offset > content->info.size)
			|| (status.dl_info.offset + status.dl_info.size > content->info.size)) {
		GSERRORCODE(err, 400, "Byte range not satisfiable "
			"asked=[%"G_GINT64_FORMAT",%"G_GINT64_FORMAT"] allowed=[0,%"G_GINT64_FORMAT"]",
			status.dl_info.offset, status.dl_info.offset + status.dl_info.size,
			content->info.size);
		return GS_ERROR;
	}

	fill_hcurl_from_content(content, &url);

	/* Now we can start working. First agregate the known chunks, then iterate
	 * on them */
	if (!agregate_chunks(&agregated_chunks, content, err)) {
		GSERRORSET(err, "Invalid chunk sequence");
		goto error_label;
	}

	download_debug(&status, content, "downloading content");
	failed_chunks = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, NULL);

	if (is_rainx) {
		if (stg_pol_rainx_get_param(&(content->info.container->info.gs->ni), stgpol, DS_KEY_K, &k_signed))
			k = k_signed;
		if (stg_pol_rainx_get_param(&(content->info.container->info.gs->ni), stgpol, DS_KEY_M, &m_signed))
			m = m_signed;
	} else {
		struct storage_policy_s *sp = storage_policy_init(
				&(content->info.container->info.gs->ni), stgpol);
		const gchar *nb_copy = data_security_get_param(
				storage_policy_get_data_security(sp), "nb_copy");
		// In case of duplication, we have one base chunk
		k = 1;
		// and (nb_copy - 1) backups
		m = nb_copy != NULL? strtoll(nb_copy, NULL, 10) -1 : 0;
		storage_policy_clean(sp);
	}

	while (!download_terminated(&status)) {
		may_reload = FALSE;
		next_agregate = NULL;
		failed_ci = NULL;

		/* Find the first, chunks agregate that match our current offset.
		 * Be careful, this call will change the download status */
		next_agregate = download_jump_to_target(agregated_chunks, &status, &failed_ci, err);
		if (!next_agregate) {
			if ( local_gerr ) {
				GSERRORCODE(err,local_gerr->code,local_gerr->message);
				g_clear_error(&local_gerr);
			} else {
				GSERRORCODE(err, CODE_CONTENT_UNCOMPLETE, "No chunk matches");
			}
			if (is_rainx) {
				if (ci) {
					int64_t nbW64 = ci->size;
					status.content_dl = status.content_dl + nbW64;
					status.chunk_dl = status.content_dl + nbW64;
				}
				remaining_reloads = NB_RELOADS_GET;
				status.caller_stopped = TRUE;
				if (status.content_dl < status.dl_info.size)
					continue;
				// else go on with this iteration, to see if we need reconstruction
			} else {
				goto error_label;
			}
		} else {
			g_clear_error(&local_gerr);
		}

		download_debug(&status, content, "downloading chunk");
		if (next_agregate) {
			ci = g_slist_nth_data(next_agregate->data, 0);
			is_last_subchunk = nb_data_chunks < k ?
					(ci->position + 1) == nb_data_chunks :
					((ci->position + 1) % k) == 0;
			if (is_rainx && remaining_reloads == -1 && g_hash_table_size(failed_chunks) > 0)
				status.caller_stopped = TRUE;
			cur_chunk = download_agregate(content, next_agregate->data, &status,
					&may_reload, &broken_rawx_list, &local_gerr);
			if (NULL == cur_chunk) {

				if (status.caller_error) {/* no need to continue if the caller had problems */
					GSERRORCAUSE(err, local_gerr, "Caller error");
					g_clear_error(&local_gerr);
					goto error_label;
				}

				if (local_gerr && local_gerr->code == CODE_CONTENT_CORRUPTED) {
					// no retry
					GSERRORCAUSE(err, local_gerr, "Corruption detected.");
					g_clear_error(&local_gerr);
					goto error_label;
				}

				if (local_gerr && local_gerr->code == CODE_NETWORK_ERROR) {
					// waiting before retry
					usleep(100000);
				}

				if (may_reload) {
					if (remaining_reloads-- >= 0) {
						if (is_rainx) {
							if (g_hash_table_size(failed_chunks) > m) {
								GSERRORCAUSE(err, local_gerr, "Too many errors on same metachunk, reconstruction is impossible");
								g_clear_error(&local_gerr);
								goto error_label;
							}
							if (g_hash_table_size(failed_chunks) == 0) {
								memcpy(&status_at_first_error, &status, sizeof(struct dl_status_s));
							}
							g_hash_table_insert(failed_chunks, g_memdup(&(ci->position), sizeof(chunk_position_t)), ci);
							continue;
						} else {
							GSERRORCAUSE(err, local_gerr, "Download error");
							GSERRORSET(err, "Too many reload attempts");
							g_clear_error(&local_gerr);
							goto error_label;
						}
					} else {
						goto error_label;
					}
				}
			}
		}

		/* Function called by the reconstructor to provide the reconstructed
		 * metachunk. As we may already have some data at the beginning,
		 * we may have to skip up to (k-1)*chunk_size bytes. */
		size_t _rainx_cb(void *buffer, size_t elt_size, size_t elt_count, void *udata)
		{
			size_t *to_skip = (size_t*) udata;
			size_t written = 0;
			if (to_skip && *to_skip > 0) {
				if (*to_skip > elt_size * elt_count) {
					written = elt_size * elt_count;
					*to_skip -= written;
				} else {
					size_t to_write = elt_size * elt_count - *to_skip;
					written = status.dl_info.writer(status.dl_info.user_data,
						buffer + *to_skip, to_write);
					status.content_dl += written;
					status.chunk_dl_offset += written;
					status.chunk_dl_size -= written;
					// What was skipped must still be reported to the caller
					written += *to_skip;
					*to_skip = 0;
				}
			} else {
				written = status.dl_info.writer(status.dl_info.user_data,
						buffer, elt_size * elt_count);
				status.content_dl += written;
				status.chunk_dl_offset += written;
				status.chunk_dl_size -= written;
			}
			download_debug(&status, content, "Received data from rainx");
			return written;
		}

		remaining_reloads = NB_RELOADS_GET;
		if (is_rainx && g_hash_table_size(failed_chunks) > 0 && is_last_subchunk) {
			status.caller_stopped = FALSE;
			DEBUG("Corruption detected, Reconstruction started...");
			memcpy(&status_copy, &status, sizeof(struct dl_status_s));
			memcpy(&status, &status_at_first_error, sizeof(struct dl_status_s));

			// Get URLs of broken chunks
			GSList *broken_chunks = _chunk_ids_from_chunk_info_list(broken_rawx_list);

			size_t to_skip = 0;
			// If we are at the start of a metachunk, don't skip data
			if (status.last_position % k) {
				// Last chunk of metachunk may be smaller, take previous' size
				GSList *prev_aggregate = g_slist_nth_data(agregated_chunks,
						status.last_position - 1);
				chunk_info_t *first_ci = prev_aggregate->data;
				// Skip up to (k-1)*(chunk_size) bytes
				to_skip = first_ci->size * (status.last_position % k);
			}
			// Prepare rainx reconstruction parameters
			struct rainx_writer_s rainx_writer = {_rainx_cb, &to_skip};
			struct rainx_rec_params_s *rainx_params = NULL;
			rainx_params = rainx_rec_params_build(
					local_beans? local_beans : beans,
					broken_chunks, status.last_position / k);

			local_gerr = rainx_reconstruct(url,
					&(content->info.container->info.gs->ni),
					rainx_params, &rainx_writer, TRUE, TRUE);

			rainx_rec_params_free(rainx_params);
			g_slist_free_full(broken_chunks, g_free);

			if (local_gerr != NULL) {
				GSERRORCAUSE(err, local_gerr, "Corruption detected, and reconstruct failed.");
				GSERRORSET(err, "Too many reload attempts");
				g_clear_error(&local_gerr);

				if (!reload_and_agregate_chunks(&agregated_chunks, content, err)) {
					GSERRORCAUSE(err, local_gerr, "Download failed and reload error");
					g_clear_error(&local_gerr);
					goto error_label;
				}
				DEBUG("Reconstruction failed, reload and restarted...");
				memcpy(&status, &status_copy, sizeof(struct dl_status_s));
			} else {
				GRID_INFO("Reconstruction finished with success.");
				gs_error_clear(err);
			}
			g_hash_table_remove_all(failed_chunks);
		}
		download_debug(&status, content, "content reloaded");
	} // end while

	download_debug(&status, content, "content downloaded");
	ret = GS_OK;

error_label:
	g_clear_error(&local_gerr);
	if (agregated_chunks)
		g_slist_free_agregated(agregated_chunks);
	g_hash_table_destroy(failed_chunks);
	if (local_filtered)
		g_slist_free(local_filtered);
	if (local_beans)
		_bean_cleanl2(local_beans);
	hc_url_clean(url);
	return ret;
}

