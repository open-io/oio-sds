/**
 * @file sqlx_remote.h
 */

#ifndef HC__SQLX_REMOTE_H
# define HC__SQLX_REMOTE_H 1

/**
 * @defgroup sqliterepo_remote RPC Codec
 * @ingroup sqliterepo
 * @brief
 * @details
 *
 * @{
 */

# include <metautils/lib/metatypes.h>

struct Row;
struct RowSet;
struct Table;
struct TableSequence;

// Handy structures avoiding passing too many arguments ------------------------
struct sqlx_name_s {
	const gchar *ns;
	const gchar *base;
	const gchar *type;
};

struct sqlxsrv_name_s {
	gint64 seq;
	const gchar *ns;
	const container_id_t *cid;
	const gchar *schema;
};

// sqliterepo-related requests coders ------------------------------------------

GByteArray* sqlx_pack_USE(struct sqlx_name_s *name);

/**
 * @param name
 * @return
 */
GByteArray* sqlx_pack_STATUS(struct sqlx_name_s *name);



/**
 * @param name
 * @return
 */
GByteArray* sqlx_pack_ISMASTER(struct sqlx_name_s *name);



/**
 * @param name
 * @param source
 * @return
 */
GByteArray* sqlx_pack_PIPEFROM(struct sqlx_name_s *name,
		const gchar *source);

GByteArray* sqlx_pack_PIPETO(struct sqlx_name_s *name,
		const gchar *target);

GByteArray* sqlx_pack_DUMP(struct sqlx_name_s *name);

GByteArray* sqlx_pack_RESTORE(struct sqlx_name_s *name,
		const guint8 *raw, gsize rawsize);

GByteArray* sqlx_pack_REPLICATE(struct sqlx_name_s *name,
		struct TableSequence *tabseq);

GByteArray* sqlx_pack_GETVERS(struct sqlx_name_s *name);

GByteArray* sqlx_pack_QUERY(struct sqlxsrv_name_s *name,
		const gchar *query, struct TableSequence *params, gboolean autocreate);

GByteArray* sqlx_pack_QUERY_single(struct sqlxsrv_name_s *name,
		const gchar *query, gboolean autocreate);

GByteArray* sqlx_pack_DESTROY(struct sqlxsrv_name_s *name, gboolean local);

GByteArray* sqlx_pack_LOAD(struct sqlx_name_s *name, GByteArray *dump);

GByteArray* sqlx_pack_ADMGET(struct sqlx_name_s *name, const gchar *k);

GByteArray* sqlx_pack_ADMSET(struct sqlx_name_s *name,
		const gchar *k, const gchar *v);

// sqlx-related elements coders ------------------------------------------------

GByteArray* sqlx_encode_Row(struct Row *row, GError **err);

GByteArray* sqlx_encode_RowSet(struct RowSet *rows, GError **err);

GByteArray* sqlx_encode_Table(struct Table *table, GError **err);

GByteArray* sqlx_encode_TableSequence(struct TableSequence *tabseq,
		GError **err);

// replication handy functions -------------------------------------------------

void peers_restore(gchar **targets, struct sqlx_name_s *name,
		GByteArray *dump);

GError * peer_restore(const gchar *target, struct sqlx_name_s *name,
		GByteArray *dump);

GError * peer_dump(const gchar *target, struct sqlx_name_s *name,
		GByteArray **result);

/** @} */

#endif /* HC__SQLX_REMOTE_H */
