/*
OpenIO SDS sqliterepo
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

#ifndef OIO_SDS__sqliterepo__sqlx_remote_h
# define OIO_SDS__sqliterepo__sqlx_remote_h 1

#define NAME_CHECK(C) do {\
	EXTRA_ASSERT((C) != NULL);\
	EXTRA_ASSERT((C)->base != NULL); \
	EXTRA_ASSERT((C)->type != NULL); \
	EXTRA_ASSERT((C)->ns != NULL); \
} while (0)

#define SQLXNAME_CHECK(p) do { EXTRA_ASSERT((p) != NULL); NAME_CHECK(p); } while (0)

# include <metautils/lib/metatypes.h>

struct Row;
struct RowSet;
struct Table;
struct TableSequence;

// Handy structures avoiding passing too many arguments ------------------------

struct sqlx_name_mutable_s
{
	gchar *ns;
	gchar *base;
	gchar *type;
};

struct sqlx_name_s
{
	const char *ns;
	const char *base;
	const char *type;
};

void sqlx_name_clean (struct sqlx_name_mutable_s *n);
void sqlx_name_free  (struct sqlx_name_mutable_s *n);

void sqlx_name_dup   (struct sqlx_name_mutable_s *dst,
		const struct sqlx_name_s *src);

void sqlx_name_fill  (struct sqlx_name_mutable_s *n, struct oio_url_s *url,
		const char *srvtype, gint64 seq);

void sqlx_name_fill_type_asis  (struct sqlx_name_mutable_s *n,
		struct oio_url_s *url, const char *srvtype, gint64 seq);

gboolean sqlx_name_extract (const struct sqlx_name_s *n, struct oio_url_s *url,
		const char *srvtype, gint64 *pseq);

static inline struct sqlx_name_s *
sqlx_name_mutable_to_const(struct sqlx_name_mutable_s *mut)
{
	return (struct sqlx_name_s*)mut;
}

#define SQLXNAME_STACKIFY(N) do { \
	if ((N).ns) STRING_STACKIFY((N).ns); \
	if ((N).base) STRING_STACKIFY((N).base); \
	if ((N).type) STRING_STACKIFY((N).type); \
} while (0)

// sqliterepo-related requests coders ------------------------------------------

GByteArray* sqlx_pack_ENABLE (const struct sqlx_name_s *name);
GByteArray* sqlx_pack_FREEZE (const struct sqlx_name_s *name);
GByteArray* sqlx_pack_DISABLE (const struct sqlx_name_s *name);
GByteArray* sqlx_pack_DISABLE_DISABLED (const struct sqlx_name_s *name);

GByteArray* sqlx_pack_PROPGET (const struct sqlx_name_s *name);
GByteArray* sqlx_pack_PROPDEL (const struct sqlx_name_s *name, const gchar * const *k);

/* @param kv a NULL-terminated array of strings, containing N pairs
 * with for 0 <= i < N:
 *   kv[2i] is the key
 *   kv[2i+1] if the value.
 */
GByteArray* sqlx_pack_PROPSET_tab (const struct sqlx_name_s *name,
		gboolean flush, gchar **kv);

GByteArray* sqlx_pack_EXITELECTION(const struct sqlx_name_s *name);
GByteArray* sqlx_pack_USE(const struct sqlx_name_s *name);
GByteArray* sqlx_pack_DESCR(const struct sqlx_name_s *name);
GByteArray* sqlx_pack_STATUS(const struct sqlx_name_s *name);
GByteArray* sqlx_pack_GETVERS(const struct sqlx_name_s *name);
GByteArray* sqlx_pack_ISMASTER(const struct sqlx_name_s *name);

GByteArray* sqlx_pack_PIPEFROM(const struct sqlx_name_s *name, const gchar *source);
GByteArray* sqlx_pack_PIPETO(const struct sqlx_name_s *name, const gchar *target);
GByteArray* sqlx_pack_RESYNC(const struct sqlx_name_s *name);

GByteArray* sqlx_pack_DUMP(const struct sqlx_name_s *name, gboolean chunked);
GByteArray* sqlx_pack_RESTORE(const struct sqlx_name_s *name, const guint8 *raw, gsize rawsize);

GByteArray* sqlx_pack_REPLICATE(const struct sqlx_name_s *name, struct TableSequence *tabseq);

// service-wide requests
GByteArray* sqlx_pack_LEANIFY(void);
GByteArray* sqlx_pack_INFO(void);

// sqlx requests
GByteArray* sqlx_pack_QUERY(const struct sqlx_name_s *name,
		const gchar *query, struct TableSequence *params, gboolean autocreate);

GByteArray* sqlx_pack_QUERY_single(const struct sqlx_name_s *name,
		const gchar *query, gboolean autocreate);

GByteArray* sqlx_pack_DESTROY(const struct sqlx_name_s *name, gboolean local);

// sqlx-related elements coders ------------------------------------------------

GByteArray* sqlx_encode_TableSequence(struct TableSequence *tabseq,
		GError **err);

// replication handy functions -------------------------------------------------

void peers_restore(gchar **targets, struct sqlx_name_s *name,
		GByteArray *dump);

GError * peer_restore(const gchar *target, struct sqlx_name_s *name,
		GByteArray *dump);

GError * peer_dump_gba(const gchar *target, struct sqlx_name_s *name,
		GByteArray **result);

typedef GError* (*peer_dump_cb)(GByteArray *part, gint64 remaining, gpointer arg);

GError * peer_dump(const gchar *target, struct sqlx_name_s *name, gboolean chunked,
		peer_dump_cb, gpointer cb_arg);

#endif /*OIO_SDS__sqliterepo__sqlx_remote_h*/
