/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

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

struct m2v2_create_params_s;

GError* m2v2_remote_execute_DESTROY(const char *target, struct oio_url_s *url,
		guint32 flags);

/* Locally destroy a container on several services. */
GError* m2v2_remote_execute_DESTROY_many(gchar **targets, struct oio_url_s *url,
		guint32 flags);

GByteArray* m2v2_remote_pack_CREATE(struct oio_url_s *url,
		struct m2v2_create_params_s *pols);

GByteArray* m2v2_remote_pack_DESTROY(struct oio_url_s *url, guint32 flags);

/* accepts M2V2_FLAG_MASTER */
GByteArray* m2v2_remote_pack_HAS(struct oio_url_s *url, guint32 flags);

/* accepts M2V2_FLAG_MASTER */
GByteArray* m2v2_remote_pack_ISEMPTY (struct oio_url_s *url, guint32 flags);

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

GByteArray* m2v2_remote_pack_DRAIN(struct oio_url_s *url);

GByteArray* m2v2_remote_pack_DEL(struct oio_url_s *url);

GByteArray* m2v2_remote_pack_TRUNC(struct oio_url_s *url, gint64 size);

/* accepts M2V2_FLAG_MASTER */
GByteArray* m2v2_remote_pack_GET(
		struct oio_url_s *url, guint32 flags);

/* accepts M2V2_FLAG_MASTER */
GByteArray* m2v2_remote_pack_LIST(
		struct oio_url_s *url, guint32 flags,
		struct list_params_s *p);

/* accepts M2V2_FLAG_MASTER */
GByteArray* m2v2_remote_pack_LIST_BY_CHUNKID(
		struct oio_url_s *url, guint32 flags,
		struct list_params_s *p, const char *chunk);

/* accepts M2V2_FLAG_MASTER */
GByteArray* m2v2_remote_pack_LIST_BY_HEADERHASH(
		struct oio_url_s *url, guint32 flags,
		struct list_params_s *p, GBytes *h);

/* accepts M2V2_FLAG_MASTER */
GByteArray* m2v2_remote_pack_LIST_BY_HEADERID(
		struct oio_url_s *url, guint32 flags,
		struct list_params_s *p, GBytes *h);

GByteArray* m2v2_remote_pack_RAW_DEL(struct oio_url_s *url, GSList *beans);
GByteArray* m2v2_remote_pack_RAW_ADD(struct oio_url_s *url, GSList *beans, gboolean force);
GByteArray* m2v2_remote_pack_RAW_SUBST(struct oio_url_s *url, GSList *new_chunks, GSList *old_chunks);
GByteArray* m2v2_remote_pack_PROP_DEL(struct oio_url_s *url, gchar **names);

GByteArray* m2v2_remote_pack_PROP_SET(
		struct oio_url_s *url, guint32 flags,
		GSList *beans);

/* accepts M2V2_FLAG_MASTER */
GByteArray* m2v2_remote_pack_PROP_GET(struct oio_url_s *url, guint32 flags);

GByteArray* m2v2_remote_pack_EXITELECTION(struct oio_url_s *url);
GByteArray* m2v2_remote_pack_TOUCHB(struct oio_url_s *url, guint32 flags);
GByteArray* m2v2_remote_pack_TOUCHC(struct oio_url_s *url);

#endif /*OIO_SDS__meta2v2__meta2v2_remote_h*/
