#ifndef HC_M2V2_REMOTE__H
# define HC_M2V2_REMOTE__H 1
# include <glib.h>
# include <meta2v2/autogen.h>

#define M2V2_FLAG_NODELETED        0x00000001
#define M2V2_FLAG_ALLVERSION       0x00000002
#define M2V2_FLAG_NOPROPS          0x00000004
#define M2V2_FLAG_NOFORMATCHECK    0x00000008
#define M2V2_FLAG_ALLPROPS         0x00000010
#define M2V2_FLAG_HEADERS          0x00000020
// FVE: M2V2_FLAG_HEADERS was 0x00000016, is there any reason?
#define M2V2_FLAG_SYNCDEL          0x00000040

#define M2V2_DESTROY_PURGE 0x01
/* Flush the container before deleting it
 * (slower than M2V2_DESTROY_FORCE but same effect) */
#define M2V2_DESTROY_FLUSH 0x02
/* Destroy container even if aliases or snapshots are still present */
#define M2V2_DESTROY_FORCE 0x04
/* Destroy only the local base */
#define M2V2_DESTROY_LOCAL 0x08

/* Request N spare chunks which should not be on provided blacklist */
#define M2V2_SPARE_BY_BLACKLIST "SPARE_BLACKLIST"
/* Request N spare chunks according to a storage policy */
#define M2V2_SPARE_BY_STGPOL "SPARE_STGPOL"

struct hc_url_s;

/**
 * @addtogroup meta2v2_remote
 * @{
 */

struct m2v2_create_params_s
{
	const gchar *storage_policy;
	const gchar *version_policy;
	gboolean local; /**< Do not try to replicate, do not call get_peers() */
};

/**
 * @addtogroup meta2v2_remote_packers
 * @ingroup meta2v2_remote
 * @{
 */

GByteArray* m2v2_remote_pack_PURGE(GByteArray *sid, struct hc_url_s *url,
		gboolean dry_run);

GByteArray* m2v2_remote_pack_DEDUP(GByteArray *sid, struct hc_url_s *url,
		gboolean dry_run);

GByteArray* m2v2_remote_pack_CREATE(GByteArray *sid, struct hc_url_s *url,
		struct m2v2_create_params_s *pols);

GByteArray* m2v2_remote_pack_DESTROY(GByteArray *sid, struct hc_url_s *url,
		guint32 flags);

GByteArray* m2v2_remote_pack_HAS(GByteArray *sid, struct hc_url_s *url);

GByteArray* m2v2_remote_pack_PUT(GByteArray *sid, struct hc_url_s *url,
		GSList *beans);

GByteArray* m2v2_remote_pack_OVERWRITE(GByteArray *sid, struct hc_url_s *url,
		GSList *beans);

GByteArray* m2v2_remote_pack_APPEND(GByteArray *sid, struct hc_url_s *url,
		GSList *beans);

GByteArray* m2v2_remote_pack_COPY(GByteArray *sid, struct hc_url_s *url,
		const char *src);

GByteArray* m2v2_remote_pack_BEANS(GByteArray *sid, struct hc_url_s *url,
		const gchar *pol, gint64 size, gboolean append);

GByteArray* m2v2_remote_pack_SPARE(GByteArray *sid, struct hc_url_s *url,
		const gchar *pol, GSList *notin_list, GSList *broken_list);

GByteArray* m2v2_remote_pack_DEL(GByteArray *sid, struct hc_url_s *url,
		gboolean sync_del);

GByteArray* m2v2_remote_pack_RAW_DEL(GByteArray *sid, struct hc_url_s *url,
		GSList *beans);

GByteArray* m2v2_remote_pack_SUBST_CHUNKS(GByteArray *sid, struct hc_url_s *url,
		GSList *new_chunks, GSList *old_chunks, gboolean restrict_to_alias);

GByteArray* m2v2_remote_pack_GET(GByteArray *sid, struct hc_url_s *url,
		guint32 flags);

GByteArray* m2v2_remote_pack_GET_BY_CHUNK(GByteArray *sid,
		struct hc_url_s *url, const gchar *chunk_id, gint64 limit);

GByteArray* m2v2_remote_pack_LIST(GByteArray *sid, struct hc_url_s *url,
		guint32 flags);

GByteArray* m2v2_remote_pack_PROP_GET(GByteArray *sid, struct hc_url_s *url,
		guint32 flags);

GByteArray* m2v2_remote_pack_PROP_SET(GByteArray *sid, struct hc_url_s *url,
		guint32 flags, GSList *beans);

GByteArray* m2v2_remote_pack_STGPOL(GByteArray *sid, struct hc_url_s *url,
		const char *pol);

GByteArray* m2v2_remote_pack_EXITELECTION(GByteArray *sid, struct hc_url_s *url);

GByteArray* m2v2_remote_pack_SNAP_TAKE(GByteArray *sid, struct hc_url_s *url);

GByteArray* m2v2_remote_pack_SNAP_LIST(GByteArray *sid, struct hc_url_s *url);

GByteArray* m2v2_remote_pack_SNAP_RESTORE(GByteArray *sid, struct hc_url_s *url,
		gboolean hard_restore);

GByteArray* m2v2_remote_pack_SNAP_DELETE(GByteArray *sid, struct hc_url_s *url);

GByteArray* m2v2_remote_pack_TOUCH_content(GByteArray *sid, struct hc_url_s *url);
GByteArray* m2v2_remote_pack_TOUCH_container(GByteArray *sid, struct hc_url_s *url, guint32 flags);
/**
 * @}
 */


#define M2V2_MODE_DRYRUN  0x10000000

GError* m2v2_remote_execute_PURGE(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, gboolean dry_run, 
		gdouble timeout_to_step, gdouble timeout_to_overall, GSList **out);

/**
 * @param out A status message
 */
GError* m2v2_remote_execute_DEDUP(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, gboolean dry_run, gchar **out);

GError* m2v2_remote_execute_CREATE(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, struct m2v2_create_params_s *pols);

GError* m2v2_remote_execute_DESTROY(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, guint32 flags);

/**
 * Locally destroy a container on several services.
 *
 * @param targets An array of services managing the database.
 * @param sid
 * @param url URL of the container to destroy
 * @param flags
 */
GError* m2v2_remote_execute_DESTROY_many(gchar **targets, GByteArray *sid,
		struct hc_url_s *url, guint32 flags);

GError* m2v2_remote_execute_HAS(const gchar *target, GByteArray *sid,
		struct hc_url_s *url);

GError* m2v2_remote_execute_BEANS(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, const gchar *pol, gint64 size,
		gboolean append, GSList **out);

/**
 * Get spare chunks. The number of spare chunks returned
 * will be the one defined by the policy minus the length of notin_list.
 *
 * @param target
 * @param sid
 * @param url
 * @param stgpol The storage policy that the spare chunks should match
 * @param notin_list The list of already known chunks that should be taken into
 *   account when computing distance between chunks.
 * @param broken_list The list of broken chunks, provided to prevent getting
 *   spare chunks from the same rawx (not taken into account when computing
 *   distance between chunks).
 * @param[out] out The output list of spare chunks
 * @return A GError in case of error
 *
 * @note notin_list and broken_list may contain beans other than
 *   (struct bean_CHUNKS_s *) with no harm (they will be ignored).
 */
GError* m2v2_remote_execute_SPARE(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, const gchar *stgpol,
		GSList *notin_list, GSList *broken_list,
		GSList **out);

GError* m2v2_remote_execute_PUT(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, GSList *in, GSList **out);

GError* m2v2_remote_execute_OVERWRITE(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, GSList *in);

GError* m2v2_remote_execute_APPEND(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, GSList *in, GSList **out);

GError* m2v2_remote_execute_COPY(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, const char *src);

GError* m2v2_remote_execute_GET(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, guint32 flags, GSList **out);

/**
 * Get aliases (and related beans) to which a chunk belongs.
 *
 * @param url The URL of the container to search into
 * @param chunk_id The id of the chunk to search (you are advised to send
 *   the whole chunk id, not just the hash part)
 * @param limit The maximum number of returned aliases (-1 means no limit)
 */
GError* m2v2_remote_execute_GET_BY_CHUNK(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, const gchar *chunk_id, gint64 limit, GSList **out);

GError* m2v2_remote_execute_DEL(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, gboolean sync_del, GSList **out);

GError* m2v2_remote_execute_RAW_DEL(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, GSList *beans);

/**
 * Substitute chunks by another one in meta2 database.
 * TODO: return number of substitutions
 */
GError* m2v2_remote_execute_SUBST_CHUNKS(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, GSList *new_chunks, GSList *old_chunks,
		gboolean restrict_to_alias);

GError* m2v2_remote_execute_SUBST_CHUNKS_single(const gchar *target,
		GByteArray *sid,
		struct hc_url_s *url, struct bean_CHUNKS_s *new_chunk,
		struct bean_CHUNKS_s *old_chunk, gboolean restrict_to_alias);

GError* m2v2_remote_execute_LIST(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, guint32 flags, GSList **out);

GError* m2v2_remote_execute_PROP_SET(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, guint32 flags, GSList *in);

GError* m2v2_remote_execute_PROP_GET(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, guint32 flags, GSList **out);

GError* m2v2_remote_execute_STGPOL(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, const char *pol, GSList **out);

GError* m2v2_remote_execute_EXITELECTION(const gchar *target, GByteArray *sid,
                struct hc_url_s *url);

GError* m2v2_remote_execute_SNAP_TAKE(const gchar *target, GByteArray *sid,
		struct hc_url_s *url);

GError* m2v2_remote_execute_SNAP_LIST(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, GSList **out);

GError* m2v2_remote_execute_SNAP_RESTORE(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, gboolean hard_restore);

GError* m2v2_remote_execute_SNAP_DELETE(const gchar *target, GByteArray *sid,
		struct hc_url_s *url);


GError* m2v2_remote_touch_content(const gchar *target, GByteArray *sid,
        struct hc_url_s *url);

GError* m2v2_remote_touch_container_ex(const gchar *target, GByteArray *sid,
        struct hc_url_s *url, guint32 flags);


/**
 * @}
 */

#endif /* HC_M2V2_REMOTE__H */
