#ifndef RAINX_REMOTE_H
# define RAINX_REMOTE_H
# include "./gs_internals.h"

struct rainx_params_s
{
	/** Position of the metachunk in the content */
	gint64 metachunk_pos;
	/** Alias bean */
	struct bean_ALIASES_s *alias;
	/** Content header bean */
	struct bean_CONTENTS_HEADERS_s *content_header;
	/** Array of data chunks/contents (m2v2_chunk_pair_t) */
	GArray *data_chunk_pairs;
	/** Array of parity chunks/contents (m2v2_chunk_pair_t) */
	GArray *parity_chunk_pairs;
	/** Array of unavailable chunks/contents (m2v2_chunk_pair_t) */
	GArray *unavail_chunk_pairs;
};

/**
 * Trigger reconstruction of a broken metachunk.
 *
 * @param url The URL of the content
 * @param nsinfo Current namespace info
 * @param param Necessary parameters for the reconstruction
 *   (see struct rainx_params_s)
 * @param reuse_broken Allow the reuse of RAWX containing broken chunks
 * @return A GError in case of error, NULL otherwise
 */
GError *rainx_reconstruct(struct hc_url_s *url, namespace_info_t *nsinfo,
		struct rainx_params_s *params, gboolean reuse_broken);

#endif

