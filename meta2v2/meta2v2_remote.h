/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#ifndef OIO_SDS__meta2v2__meta2v2_remote_h
# define OIO_SDS__meta2v2__meta2v2_remote_h 1

# include <glib.h>
# include <meta2v2/autogen.h>

#define M2V2_FLAG_NODELETED        0x00000001
#define M2V2_FLAG_ALLVERSION       0x00000002
#define M2V2_FLAG_NOPROPS          0x00000004
#define M2V2_FLAG_NOFORMATCHECK    0x00000008
#define M2V2_FLAG_ALLPROPS         0x00000010

/* when listing */
#define M2V2_FLAG_HEADERS          0x00000020

/* when getting an alias, do not follow the foreign keys toward
 * headers, contents and chunks. */
#define M2V2_FLAG_NORECURSION      0x00000080

/* when getting an alias, ignores the version in the URL and
 * return the latest alias only. */
#define M2V2_FLAG_LATEST           0x00000100

/* flush the properties */
#define M2V2_FLAG_FLUSH            0x00000200

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

struct list_params_s;
struct list_result_s;

/**
 * @addtogroup meta2v2_remote
 * @{
 */

void m2v2_list_result_clean (struct list_result_s *p);

struct m2v2_create_params_s
{
	const gchar *storage_policy; /**< Will override the (maybe present) stgpol property. */
	const gchar *version_policy; /**< idem for the verpol property. */
	gchar **properties; /**< A NULL-terminated sequence of strings where:
						  * properties[i*2] is the i-th key and
						  * properties[(i*2)+1] is the i-th value */
	gboolean local; /**< Do not try to replicate, do not call get_peers() */
};

/**
 * @addtogroup meta2v2_remote_packers
 * @ingroup meta2v2_remote
 * @{
 */

GByteArray* m2v2_remote_pack_PURGE(struct hc_url_s *url, gboolean dry_run);

GByteArray* m2v2_remote_pack_DEDUP(struct hc_url_s *url, gboolean dry_run);

/* The storage_policy, version_policy and all the properties are optional
 * and plain ASCII strings, so they will be sent as HEADER of the message
 * request instead of as a serialized body. */
GByteArray* m2v2_remote_pack_CREATE(struct hc_url_s *url,
		struct m2v2_create_params_s *pols);

GByteArray* m2v2_remote_pack_DESTROY(struct hc_url_s *url, guint32 flags);

GByteArray* m2v2_remote_pack_HAS(struct hc_url_s *url);

GByteArray* m2v2_remote_pack_PUT(struct hc_url_s *url, GSList *beans);

GByteArray* m2v2_remote_pack_OVERWRITE(struct hc_url_s *url, GSList *beans);

GByteArray* m2v2_remote_pack_APPEND(struct hc_url_s *url, GSList *beans);

GByteArray* m2v2_remote_pack_COPY(struct hc_url_s *url, const char *src);

GByteArray* m2v2_remote_pack_BEANS(struct hc_url_s *url,
		const gchar *pol, gint64 size, gboolean append);

GByteArray* m2v2_remote_pack_SPARE(struct hc_url_s *url,
		const gchar *pol, GSList *notin_list, GSList *broken_list);

GByteArray* m2v2_remote_pack_DEL(struct hc_url_s *url);

GByteArray* m2v2_remote_pack_RAW_ADD(struct hc_url_s *url, GSList *beans);

GByteArray* m2v2_remote_pack_RAW_DEL(struct hc_url_s *url, GSList *beans);

GByteArray* m2v2_remote_pack_RAW_SUBST(struct hc_url_s *url,
		GSList *new_chunks, GSList *old_chunks);

GByteArray* m2v2_remote_pack_GET(struct hc_url_s *url, guint32 flags);

GByteArray* m2v2_remote_pack_GET_BY_CHUNK(struct hc_url_s *url, const gchar *chunk_id, gint64 limit);

GByteArray* m2v2_remote_pack_LIST(struct hc_url_s *url, struct list_params_s *p);

GByteArray* m2v2_remote_pack_PROP_DEL(struct hc_url_s *url, GSList *names);

GByteArray* m2v2_remote_pack_PROP_SET(struct hc_url_s *url, guint32 flags, GSList *beans);

GByteArray* m2v2_remote_pack_PROP_GET(struct hc_url_s *url, guint32 flags);

GByteArray* m2v2_remote_pack_STGPOL(struct hc_url_s *url, const char *pol);

GByteArray* m2v2_remote_pack_EXITELECTION(struct hc_url_s *url);

GByteArray* m2v2_remote_pack_TOUCH_content(struct hc_url_s *url);

GByteArray* m2v2_remote_pack_TOUCH_container(struct hc_url_s *url, guint32 flags);

/**
 * @}
 */

#define M2V2_MODE_DRYRUN  0x10000000

GError* m2v2_remote_execute_PURGE(const gchar *target, struct hc_url_s *url,
		gboolean dry_run, gdouble timeout, GSList **out);

/** @param out A status message */
GError* m2v2_remote_execute_DEDUP(const gchar *target, struct hc_url_s *url,
		gboolean dry_run, gchar **out);

GError* m2v2_remote_execute_CREATE(const gchar *target, struct hc_url_s *url,
		struct m2v2_create_params_s *pols);

GError* m2v2_remote_execute_DESTROY(const gchar *target, struct hc_url_s *url,
		guint32 flags);

/**
 * Locally destroy a container on several services.
 *
 * @param targets An array of services managing the database.
 * @param sid
 * @param url URL of the container to destroy
 * @param flags
 */
GError* m2v2_remote_execute_DESTROY_many(gchar **targets, struct hc_url_s *url,
		guint32 flags);

GError* m2v2_remote_execute_HAS(const gchar *target, struct hc_url_s *url);

GError* m2v2_remote_execute_BEANS(const gchar *target, struct hc_url_s *url,
		const gchar *pol, gint64 size, gboolean append, GSList **out);

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
GError* m2v2_remote_execute_SPARE(const gchar *target, struct hc_url_s *url,
		const gchar *stgpol, GSList *notin_list, GSList *broken_list,
		GSList **out);

GError* m2v2_remote_execute_PUT(const gchar *target, struct hc_url_s *url,
		GSList *in, GSList **out);

GError* m2v2_remote_execute_OVERWRITE(const gchar *target, struct hc_url_s *url,
		GSList *in);

GError* m2v2_remote_execute_APPEND(const gchar *target, struct hc_url_s *url,
		GSList *in, GSList **out);

GError* m2v2_remote_execute_COPY(const gchar *target, struct hc_url_s *url,
		const char *src);

GError* m2v2_remote_execute_GET(const gchar *target, struct hc_url_s *url,
		guint32 flags, GSList **out);

/**
 * Get aliases (and related beans) to which a chunk belongs.
 *
 * @param url The URL of the container to search into
 * @param chunk_id The id of the chunk to search (you are advised to send
 *   the whole chunk id, not just the hash part)
 * @param limit The maximum number of returned aliases (-1 means no limit)
 */
GError* m2v2_remote_execute_GET_BY_CHUNK(const gchar *target, 
		struct hc_url_s *url, const gchar *chunk_id, gint64 limit, GSList **out);

GError* m2v2_remote_execute_DEL(const gchar *target, struct hc_url_s *url);

GError* m2v2_remote_execute_RAW_ADD(const gchar *target, struct hc_url_s *url,
		GSList *beans);

GError* m2v2_remote_execute_RAW_DEL(const gchar *target, struct hc_url_s *url,
		GSList *beans);

/** Substitute chunks by another one in meta2 database.
 * TODO: return number of substitutions */
GError* m2v2_remote_execute_RAW_SUBST(const gchar *target,
		struct hc_url_s *url, GSList *new_chunks, GSList *old_chunks);

GError* m2v2_remote_execute_RAW_SUBST_single(const gchar *target,
		struct hc_url_s *url,
		struct bean_CHUNKS_s *new_chunk, struct bean_CHUNKS_s *old_chunk);

GError* m2v2_remote_execute_LIST(const gchar *target,
		struct hc_url_s *url, struct list_params_s *p,
		struct list_result_s *out, gchar ***out_properties);

/* works for contents only. for container props, @see sqlx_pack_PROPDEL() */
GError* m2v2_remote_execute_PROP_DEL(const gchar *target,
		struct hc_url_s *url, GSList *names);

/* works for contents only. for container props, @see sqlx_pack_PROPSET() */
GError* m2v2_remote_execute_PROP_SET(const gchar *target,
		struct hc_url_s *url, guint32 flags, GSList *in);

/* works for contents only. for container props, @see sqlx_pack_PROPGET() */
GError* m2v2_remote_execute_PROP_GET(const gchar *target,
		struct hc_url_s *url, guint32 flags, GSList **out);

GError* m2v2_remote_execute_STGPOL(const gchar *target,
		struct hc_url_s *url, const char *pol, GSList **out);

GError* m2v2_remote_execute_EXITELECTION(const gchar *target,
		struct hc_url_s *url);

GError* m2v2_remote_touch_content(const gchar *target, struct hc_url_s *url);

GError* m2v2_remote_touch_container_ex(const gchar *target, struct hc_url_s *url, guint32 flags);

/** Allows to send a request with a custom timeouts. */
GError* m2v2_request(const gchar *url, GByteArray *req, gdouble timeout, GSList **out);

/**
 * @}
 */

#endif /*OIO_SDS__meta2v2__meta2v2_remote_h*/
