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

#ifndef HC_M2V2_REMOTE__H
# define HC_M2V2_REMOTE__H 1
# include <glib.h>

#define M2V2_FLAG_NODELETED        0x00000001
#define M2V2_FLAG_ALLVERSION       0x00000002
#define M2V2_FLAG_NOPROPS          0x00000004
#define M2V2_FLAG_NOFORMATCHECK    0x00000008
#define M2V2_FLAG_ALLPROPS         0x00000010
#define M2V2_FLAG_HEADERS	   0x00000016

struct hc_url_s;

/**
 * @addtogroup meta2v2_remote
 * @{
 */

struct m2v2_create_params_s
{
	const gchar *storage_policy;
	const gchar *version_policy;
};

/**
 * @addtogroup meta2v2_remote_packers
 * @ingroup meta2v2_remote
 * @{
 */

GByteArray*
m2v2_remote_pack_PURGE(GByteArray *sid, struct hc_url_s *url);

GByteArray* m2v2_remote_pack_DEDUP(GByteArray *sid, struct hc_url_s *url);

GByteArray* m2v2_remote_pack_CREATE(GByteArray *sid, struct hc_url_s *url,
		struct m2v2_create_params_s *pols);

GByteArray* m2v2_remote_pack_DESTROY(GByteArray *sid, struct hc_url_s *url);

GByteArray* m2v2_remote_pack_OPEN(GByteArray *sid, struct hc_url_s *url);

GByteArray* m2v2_remote_pack_CLOSE(GByteArray *sid, struct hc_url_s *url);

GByteArray* m2v2_remote_pack_HAS(GByteArray *sid, struct hc_url_s *url);

GByteArray* m2v2_remote_pack_PUT(GByteArray *sid, struct hc_url_s *url,
		GSList *beans);

GByteArray* m2v2_remote_pack_APPEND(GByteArray *sid, struct hc_url_s *url,
		GSList *beans);

GByteArray* m2v2_remote_pack_BEANS(GByteArray *sid, struct hc_url_s *url,
		const gchar *pol, gint64 size, gboolean append);

GByteArray* m2v2_remote_pack_DEL(GByteArray *sid, struct hc_url_s *url);

GByteArray* m2v2_remote_pack_GET(GByteArray *sid, struct hc_url_s *url,
		guint32 flags);

GByteArray* m2v2_remote_pack_LIST(GByteArray *sid, struct hc_url_s *url,
		guint32 flags);

GByteArray* m2v2_remote_pack_PROP_GET(GByteArray *sid, struct hc_url_s *url, guint32 flags);

GByteArray* m2v2_remote_pack_PROP_SET(GByteArray *sid, struct hc_url_s *url,
		GSList *beans);

GByteArray* m2v2_remote_pack_STGPOL(GByteArray *sid, struct hc_url_s *url,
		const char *pol);

/**
 * @}
 */

GError* m2v2_remote_execute_PURGE(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, GSList **out);

/**
 * @param out A status message
 */
GError* m2v2_remote_execute_DEDUP(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, gchar **out);

GError* m2v2_remote_execute_CREATE(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, struct m2v2_create_params_s *pols);

GError* m2v2_remote_execute_DESTROY(const gchar *target, GByteArray *sid,
		struct hc_url_s *url);

GError* m2v2_remote_execute_OPEN(const gchar *target, GByteArray *sid,
		struct hc_url_s *url);

GError* m2v2_remote_execute_CLOSE(const gchar *target, GByteArray *sid,
		struct hc_url_s *url);

GError* m2v2_remote_execute_HAS(const gchar *target, GByteArray *sid,
		struct hc_url_s *url);

GError* m2v2_remote_execute_BEANS(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, const gchar *pol, gint64 size,
		gboolean append, GSList **out);

GError* m2v2_remote_execute_PUT(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, GSList *in, GSList **out);

GError* m2v2_remote_execute_APPEND(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, GSList *in, GSList **out);

GError* m2v2_remote_execute_GET(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, guint32 flags, GSList **out);

GError* m2v2_remote_execute_DEL(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, GSList **out);

GError* m2v2_remote_execute_LIST(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, guint32 flags, GSList **out);

GError* m2v2_remote_execute_PROP_SET(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, GSList *in);

GError* m2v2_remote_execute_PROP_GET(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, guint32 flags, GSList **out);

GError* m2v2_remote_execute_STGPOL(const gchar *target, GByteArray *sid,
		struct hc_url_s *url, const char *pol, GSList **out);

/**
 * @}
 */

#endif /* HC_M2V2_REMOTE__H */
