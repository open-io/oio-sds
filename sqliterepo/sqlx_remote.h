/*
OpenIO SDS sqliterepo
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS

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

#ifndef OIO_SDS__sqliterepo__sqlx_remote_h
# define OIO_SDS__sqliterepo__sqlx_remote_h 1

#define NAME_CHECK(C) do {\
	EXTRA_ASSERT((C) != NULL);\
	EXTRA_ASSERT(oio_str_is_set((C)->base)); \
	EXTRA_ASSERT(oio_str_is_set((C)->type)); \
	EXTRA_ASSERT(oio_str_is_set((C)->ns)); \
} while (0)

#define NAME2CONST(n, n0) struct sqlx_name_s n = { (n0).ns, (n0).base, (n0).type }

#define NAMEFILL(Name, Src) do { \
	g_strlcpy((Name).ns, (Src).ns, sizeof((Name).ns)); \
	g_strlcpy((Name).base, (Src).base, sizeof((Name).base)); \
	g_strlcpy((Name).type, (Src).type, sizeof((Name).type)); \
} while (0)

#define SQLXNAME_CHECK(p) do { EXTRA_ASSERT((p) != NULL); NAME_CHECK(p); } while (0)

# include <metautils/lib/metatypes.h>

struct Row;
struct Table;
struct TableSequence;

// Handy structures avoiding passing too many arguments ------------------------

struct sqlx_name_inline_s
{
	gchar ns[LIMIT_LENGTH_NSNAME];
	gchar base[LIMIT_LENGTH_BASENAME];
	gchar type[LIMIT_LENGTH_BASETYPE];
};

struct sqlx_name_s
{
	const char *ns;
	const char *base;
	const char *type;
};

#define sqlx_inline_name_fill sqlx_inline_name_fill_type_asis

void sqlx_inline_name_fill_type_asis  (struct sqlx_name_inline_s *n,
		struct oio_url_s *url, const char *srvtype, gint64 seq);


GError* sqlx_name_extract (const struct sqlx_name_s *n,
		struct oio_url_s *url, const char *srvtype, gint64 *pseq);

// sqliterepo-related requests coders ------------------------------------------

GByteArray* sqlx_pack_ENABLE (const struct sqlx_name_s *name, gint64 deadline);
GByteArray* sqlx_pack_FREEZE (const struct sqlx_name_s *name, gint64 deadline);
GByteArray* sqlx_pack_DISABLE (const struct sqlx_name_s *name, gint64 deadline);

GByteArray* sqlx_pack_PROPGET (const struct sqlx_name_s *name, gint64 deadline);
GByteArray* sqlx_pack_PROPDEL (struct oio_url_s *url,
		const struct sqlx_name_s *name, const gchar * const *k, gint64 deadline);

/* @param kv a NULL-terminated array of strings, containing N pairs
 * with for 0 <= i < N:
 *   kv[2i] is the key
 *   kv[2i+1] if the value.
 */
GByteArray* sqlx_pack_PROPSET_tab (struct oio_url_s *url,
		const struct sqlx_name_s *name, gboolean flush, gchar **kv,
		gint64 deadline);

GByteArray* sqlx_pack_EXITELECTION(const struct sqlx_name_s *name, gint64 deadline);
GByteArray* sqlx_pack_USE(const struct sqlx_name_s *name, const gchar *peers,
		const gboolean master, gint64 deadline);
GByteArray* sqlx_pack_HAS(const struct sqlx_name_s *name, gint64 deadline);
GByteArray* sqlx_pack_DESCR(const struct sqlx_name_s *name, gint64 deadline);
GByteArray* sqlx_pack_STATUS(const struct sqlx_name_s *name, gint64 deadline);
GByteArray* sqlx_pack_GETVERS(const struct sqlx_name_s *name, const gchar *peers,
		gint64 deadline);

GByteArray* sqlx_pack_SNAPSHOT(const struct sqlx_name_s *name, const gchar *source,
		const gchar *cid, const gchar *seq_num, const gchar **fields, gint64 deadline);
GByteArray* sqlx_pack_PIPEFROM(const struct sqlx_name_s *name, const gchar *source, gint check_type, gint64 deadline);
GByteArray* sqlx_pack_PIPETO(const struct sqlx_name_s *name, const gchar *target, gint64 deadline);
GByteArray* sqlx_pack_REMOVE(const struct sqlx_name_s *name, gint64 deadline);
GByteArray* sqlx_pack_RESYNC(const struct sqlx_name_s *name, const gint check_type, gint64 deadline);
GByteArray* sqlx_pack_VACUUM(const struct sqlx_name_s *name, gboolean local, gint64 deadline);
GByteArray* sqlx_pack_DUMP(const struct sqlx_name_s *name, gboolean chunked, gint check_type, gint64 deadline);
GByteArray* sqlx_pack_RESTORE(const struct sqlx_name_s *name, const guint8 *raw, gsize rawsize, gint64 deadline);

GByteArray* sqlx_pack_REPLICATE(const struct sqlx_name_s *name, struct TableSequence *tabseq, gint64 deadline);

// service-wide requests
GByteArray* sqlx_pack_LEANIFY(gint64 deadline);
GByteArray* sqlx_pack_INFO(gint64 deadline);

// sqlx-related elements coders ------------------------------------------------

GByteArray* sqlx_encode_TableSequence(struct TableSequence *tabseq,
		GError **err);

// replication handy functions -------------------------------------------------

void peers_restore(gchar **targets, struct sqlx_name_s *name,
		GByteArray *dump, gint64 deadline);

GError * peer_restore(const gchar *target, struct sqlx_name_s *name,
		GByteArray *dump, gint64 deadline);

typedef GError* (*peer_dump_cb)(GByteArray *part, gint64 remaining, gpointer arg);

GError * peer_dump(const gchar *target, struct sqlx_name_s *name, gboolean chunked,
		gint check_type, peer_dump_cb, gpointer cb_arg, gint64 deadline);

#endif /*OIO_SDS__sqliterepo__sqlx_remote_h*/
