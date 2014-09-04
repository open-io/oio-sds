#ifndef RAINX_REMOTE_H
# define RAINX_REMOTE_H
# include <glib.h>
# include "./gs_internals.h"

struct rainx_rec_params_s
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

struct rainx_writer_s
{
	size_t (*callback)(void *buffer, size_t size, size_t nmemb, void *param);
	void *param;
};

/**
 * Utility function to build reconstruction parameter from the whole
 * list of beans of a content and a list chunk ids known to be broken.
 *
 * @param beans List of beans of a content (alias, content header, and at least
 *   chunk and contents for the broken position)
 * @param broken_chunk_ids List of broken chunk id urls (strings)
 * @param position The metachunk position in the content
 * @return The structure to use as third argument of rainx_reconstruct
 */
struct rainx_rec_params_s *rainx_rec_params_build(GSList *beans,
		GSList *broken_chunk_ids, gint64 position);

/**
 * Free rainx recontruction parameters.
 */
void rainx_rec_params_free(struct rainx_rec_params_s *params);

/**
 * Trigger reconstruction of a broken metachunk.
 *
 * @param url The URL of the content
 * @param nsinfo Current namespace info
 * @param params Necessary parameters for the reconstruction
 *   (see struct rainx_rec_params_s)
 * @param writer Callback to write recontructed data to
 * @param reuse_broken Allow the reuse of RAWX containing broken chunks
 * @param on_the_fly Do not upload reconstructed chunks to rawx
 * @return A GError in case of error, NULL otherwise
 */
GError *rainx_reconstruct(struct hc_url_s *url, namespace_info_t *nsinfo,
		struct rainx_rec_params_s *params, struct rainx_writer_s *writer,
		gboolean reuse_broken, gboolean on_the_fly);

#endif

