/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LOG_DOMAIN
# define LOG_DOMAIN "grid.client.download"
#endif
#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.client.download"
#endif

#include "./gs_internals.h"
#include "./rawx.h"

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
static gboolean
download_agregate(gs_content_t *content, GSList *agregate, struct dl_status_s *status, gboolean *may_reload, GError **gerr)
{
	GSList *l;
	GError *local_gerr = NULL;

	*may_reload = FALSE;

	gboolean previousError = FALSE;

	for (l=agregate; l ;l=l->next) {
		gs_chunk_t dummy_chunk;
		dummy_chunk.content = content;
		dummy_chunk.ci = l->data;

		if (rawx_download(&dummy_chunk, &local_gerr, status)) {
			download_debug(status, content, "chunk download succeeded");
			*may_reload = FALSE;
			if (local_gerr)
                                g_clear_error(&local_gerr);
			return TRUE;
		}
		if (status->caller_error) {
			download_debug(status, content, "chunk download error due to caller");
			*may_reload = FALSE;
			if (local_gerr)
                                g_clear_error(&local_gerr);
			return FALSE;
		}
		/* then an error with the rawx happened, retry is possible */
		//switch ((*gerr)->code) {
		switch (local_gerr->code) {
	
			case CODE_CONTENT_CORRUPTED:
				/* some bad bytes have been served to the client calback,
				 * we cannot continue and think it is OK! */
				GSETCODE(gerr, CODE_CONTENT_CORRUPTED, "corruption detected");
				return FALSE;
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
	return FALSE;
}

/**
 * Returns the next chunk aggregate corresponding to the wanted offset (status argument)
 * and updates the 
 * @return an element of the 'agregates' list
 */
static GSList *
download_jump_to_target(GSList *agregates, struct dl_status_s *status, gs_error_t **gserr)
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
	return status->caller_stopped || status->caller_error
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
	struct dl_status_s status;
	GSList *agregated_chunks;
	int remaining_reloads = NB_RELOADS_GET;

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
		if (!gs_content_reload(content, TRUE, TRUE, err)) {
			GSERRORSET(err,"Cannot get the chunks of '%s'", content->info.path);
			return GS_ERROR;
		}
	}

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

	/* Now we can start working. First agregate the known chunks, then iterate
	 * on them */
	if (!agregate_chunks(&agregated_chunks, content, err)) {
		GSERRORSET(err, "Invalid chunk sequence");
		goto error_label;
	}

	download_debug(&status, content, "downloading content");

	
	GError *local_gerr = NULL;
	while (!download_terminated(&status)) {
		gboolean may_reload = FALSE;
		GSList *next_agregate = NULL;

		/* Find the first, chunks agregate that match our current offset.
		 * Be careful, this call will change the download status */
		next_agregate = download_jump_to_target(agregated_chunks, &status, err);
		if (!next_agregate) {
			if ( local_gerr ) {
				GSERRORCODE(err,local_gerr->code,local_gerr->message);
				g_clear_error(&local_gerr);
			} else {
				GSERRORCODE(err, CODE_CONTENT_UNCOMPLETE, "No chunk matches");
			}
			goto error_label;
		} else {
			g_clear_error(&local_gerr);
		}

		download_debug(&status, content, "downloading chunk");

		if (GS_OK != download_agregate(content, next_agregate->data, &status, &may_reload, &local_gerr)) {

			if (status.caller_error) {/* no need to continue if the caller had problems */
				GSERRORCAUSE(err, local_gerr, "Caller error");
				g_clear_error(&local_gerr);
				goto error_label;
			}
			
			if (local_gerr && local_gerr->code == CODE_CONTENT_CORRUPTED) {
				// no retry
				GSERRORCAUSE(err, local_gerr, "Corruption detected");
				g_clear_error(&local_gerr);
				goto error_label;
			}
			if (local_gerr && local_gerr->code == CODE_NETWORK_ERROR) {
				// waiting before retry
				usleep(100000);
			}

			if (may_reload) {
				if (remaining_reloads-- <= 0) {
					GSERRORCAUSE(err, local_gerr, "Download error");
					GSERRORSET(err, "Too many reload attempts");
					g_clear_error(&local_gerr);
					goto error_label;
				}
				else if (!reload_and_agregate_chunks(&agregated_chunks, content, err)) {
					GSERRORCAUSE(err, local_gerr, "Download failed and reload error");
					g_clear_error(&local_gerr);
					goto error_label;
				}
				download_debug(&status, content, "content reloaded");

				
				//if (local_gerr)
				//	g_clear_error(&local_gerr);
			}
			/* else {
			 *   // No need to reload, just retry on the same chunk agregate
			 * } */

			/* no need to print */
			WARN("Retrying after : %s", (local_gerr?local_gerr->message:"unknown error"));
		}
	}
	g_clear_error(&local_gerr);
	
	download_debug(&status, content, "content downloaded");
	if (agregated_chunks)
		g_slist_free_agregated(agregated_chunks);
	return GS_OK;

error_label:
	if (agregated_chunks)
		g_slist_free_agregated(agregated_chunks);
	return GS_ERROR;
}

