#ifndef __CHUNKINFO_NEON_SESSION_H__
# define __CHUNKINFO_NEON_SESSION_H__
# include "./gs_internals.h"

#define RAWX_ATTR_CHUNK_POSITION "chunkpos"
#define RAWX_ATTR_CONTENT_CHUNKNB "chunknb"
#define RAWX_ATTR_CONTENT_SIZE "contentsize"

typedef struct ne_request_param_s {
	ne_session *session;
	const char *method;
	char *cPath;
	const char *containerid;
	const char *contentpath;
	chunk_position_t chunkpos;
	guint32 chunknb;
	chunk_size_t chunksize;
	int64_t contentsize;
} ne_request_param_t;

/**
 * Chunk
 */
struct chunk_attr_s {
	const char *key;
	const char *val;
};

/* delete one remote chunk */
gs_status_t rawx_delete (gs_chunk_t *chunk, GError **err);

/**
 * Delete a chunk from a RawX
 *
 * @param chunk a pointer to a (struct bean_CHUNKS_s*) or (struct bean_CONTENTS_s*)
 * @param err a pointer to a GError (must not be NULL)
 * @return FALSE in case of error
 */
gboolean rawx_delete_v2(gpointer chunk, GError **err);

/**
 * Tell a RawX a chunk is corrupted (rename it with ".corrupted" extension),
 * so future GET will return 404 instead of corrupted data.
 *
 * @param chunk A pointer to a gs_chunk_t instance
 * @param[out] err A pointer to a GError (required)
 */
gs_status_t rawx_set_corrupted(gs_chunk_t *chunk, GError **err);

/**
 * Tell a RawX a chunk is corrupted (rename it with ".corrupted" extension),
 * so future GET will return 404 instead of corrupted data.
 *
 * @param chunk A pointer to a bean_CHUNKS_s or bean_CONTENTS_s instance
 * @param[out] err A pointer to a GError (required)
 */
gboolean rawx_set_corrupted_v2(gpointer chunk, GError **err);

/*  */
gboolean rawx_download (gs_chunk_t *chunk, GError **err,
		struct dl_status_s *status, GSList **p_broken_rawx_list);
int rawx_init (void);

gboolean rawx_update_chunk_attr(struct meta2_raw_chunk_s *c, const char *name,
		const char *val, GError **err);

/**
 * Update chunk extended attributes.
 *
 * @param url The URL of the chunk (a.k.a "chunk id")
 * @param attrs A list of (struct chunk_attr_s *)
 * @param err
 * @return TRUE on success, FALSE otherwise
 */
gboolean rawx_update_chunk_attrs(const gchar *chunk_url, GSList *attrs,
		GError **err);

ne_request_param_t* new_request_param(void);
void free_request_param(ne_request_param_t *param);

char* create_rawx_request_common(ne_request **req, ne_request_param_t *param,
		GError **err);
char* create_rawx_request_from_chunk(ne_request **req, ne_session *session,
		const char *method, gs_chunk_t *chunk, GByteArray *system_metadata,
		GError **err);

ne_session *opensession_common(const addr_info_t *addr_info,
		int connect_timeout, int read_timeout, GError **err);

/**
 * Generate an request id
 *
 * @param dst destination buffer (will be nul-terminated)
 * @param dst_size size of the destination buffer
 */
void gen_req_id_header(gchar *dst, gsize dst_size);

#endif /*__CHUNKINFO_NEON_SESSION_H__*/
