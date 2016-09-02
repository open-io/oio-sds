/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015-2016 OpenIO, as part of OpenIO Software Defined Storage

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

/* Request N spare chunks which should not be on provided blacklist */
#define M2V2_SPARE_BY_BLACKLIST "SPARE_BLACKLIST"
/* Request N spare chunks according to a storage policy */
#define M2V2_SPARE_BY_STGPOL "SPARE_STGPOL"

struct oio_url_s;

struct list_params_s;

struct list_result_s
{
	GSList *beans;
	GTree *props;
	gchar *next_marker;
	gboolean truncated;
};

void m2v2_list_result_init (struct list_result_s *p);
void m2v2_list_result_clean (struct list_result_s *p);
/* suitable as a request extractor */
gboolean m2v2_list_result_extract (gpointer ctx, MESSAGE reply);

struct m2v2_create_params_s
{
	const char *storage_policy; /**< Will override the (maybe present) stgpol property. */
	const char *version_policy; /**< idem for the verpol property. */
	gchar **properties; /**< A NULL-terminated sequence of strings where:
						  * properties[i*2] is the i-th key and
						  * properties[(i*2)+1] is the i-th value */
	gboolean local; /**< Do not try to replicate, do not call get_peers() */
};

#define M2V2_MODE_DRYRUN  0x10000000

enum m2v2_destroy_flag_e {
	/* send a destruction event */
	M2V2_DESTROY_EVENT = 0x01,
	M2V2_DESTROY_FLUSH = 0x02,
	M2V2_DESTROY_FORCE = 0x04,
};

GError* m2v2_remote_execute_DESTROY(const char *target, struct oio_url_s *url,
		guint32 flags);

/* Locally destroy a container on several services. */
GError* m2v2_remote_execute_DESTROY_many(gchar **targets, struct oio_url_s *url,
		guint32 flags);

GByteArray* m2v2_remote_pack_CREATE(struct oio_url_s *url, struct m2v2_create_params_s *pols);
GByteArray* m2v2_remote_pack_DESTROY(struct oio_url_s *url, guint32 flags);

GByteArray* m2v2_remote_pack_HAS(struct oio_url_s *url);
GByteArray* m2v2_remote_pack_ISEMPTY (struct oio_url_s *url);

GByteArray* m2v2_remote_pack_FLUSH(struct oio_url_s *url);
GByteArray* m2v2_remote_pack_PURGE(struct oio_url_s *url);
GByteArray* m2v2_remote_pack_DEDUP(struct oio_url_s *url);

GByteArray* m2v2_remote_pack_BEANS(struct oio_url_s *url, const char *pol,
		gint64 size, gboolean append);

GByteArray* m2v2_remote_pack_SPARE(struct oio_url_s *url, const char *pol,
		GSList *notin_list, GSList *broken_list);

GByteArray* m2v2_remote_pack_PUT(struct oio_url_s *url, GSList *beans);
GByteArray* m2v2_remote_pack_OVERWRITE(struct oio_url_s *url, GSList *beans);
GByteArray* m2v2_remote_pack_UPDATE(struct oio_url_s *url, GSList *beans);
GByteArray* m2v2_remote_pack_APPEND(struct oio_url_s *url, GSList *beans);

GByteArray* m2v2_remote_pack_LINK(struct oio_url_s *url);

GByteArray* m2v2_remote_pack_COPY(struct oio_url_s *url, const char *src);

GByteArray* m2v2_remote_pack_DEL(struct oio_url_s *url);

GByteArray* m2v2_remote_pack_TRUNC(struct oio_url_s *url, gint64 size);

GByteArray* m2v2_remote_pack_GET(struct oio_url_s *url, guint32 flags);
GByteArray* m2v2_remote_pack_LIST(struct oio_url_s *url, struct list_params_s *p);
GByteArray* m2v2_remote_pack_LIST_BY_CHUNKID(struct oio_url_s *url, struct list_params_s *p, const char *chunk);
GByteArray* m2v2_remote_pack_LIST_BY_HEADERHASH(struct oio_url_s *url, struct list_params_s *p, GBytes *h);
GByteArray* m2v2_remote_pack_LIST_BY_HEADERID(struct oio_url_s *url, struct list_params_s *p, GBytes *h);

GByteArray* m2v2_remote_pack_RAW_DEL(struct oio_url_s *url, GSList *beans);
GByteArray* m2v2_remote_pack_RAW_ADD(struct oio_url_s *url, GSList *beans);
GByteArray* m2v2_remote_pack_RAW_SUBST(struct oio_url_s *url, GSList *new_chunks, GSList *old_chunks);

GByteArray* m2v2_remote_pack_PROP_DEL(struct oio_url_s *url, gchar **names);
GByteArray* m2v2_remote_pack_PROP_SET(struct oio_url_s *url, guint32 flags, GSList *beans);
GByteArray* m2v2_remote_pack_PROP_GET(struct oio_url_s *url, guint32 flags);

GByteArray* m2v2_remote_pack_EXITELECTION(struct oio_url_s *url);
GByteArray* m2v2_remote_pack_TOUCHB(struct oio_url_s *url, guint32 flags);
GByteArray* m2v2_remote_pack_TOUCHC(struct oio_url_s *url);

#endif /*OIO_SDS__meta2v2__meta2v2_remote_h*/
