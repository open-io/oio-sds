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

# include <glib.h>
# include <metatypes.h>

struct Row;
struct RowSet;
struct Table;
struct TableSequence;

/**
 * Handy structure avoiding passing too many arguments
 */
struct sqlx_name_s {
	const gchar *ns;   /**<  */
	const gchar *base; /**<  */
	const gchar *type; /**<  */
};

/**
 *
 */
struct sqlxsrv_name_s {
	gint64 seq;
	const gchar *ns;           /**<  */
	const container_id_t *cid; /**<  */
	const gchar *schema;       /**<  */
};

/**
 * @param name
 * @return
 */
GByteArray* sqlx_pack_USE(struct sqlx_name_s *name);


/**
 * @param name
 * @param source
 * @return
 */
GByteArray* sqlx_pack_PIPEFROM(struct sqlx_name_s *name,
		const gchar *source);


/**
 * @param name
 * @param target
 * @return
 */
GByteArray* sqlx_pack_PIPETO(struct sqlx_name_s *name,
		const gchar *target);


/**
 * @param name
 * @return
 */
GByteArray* sqlx_pack_DUMP(struct sqlx_name_s *name);


/**
 * @param name
 * @param raw
 * @param rawsize
 * @return
 */
GByteArray* sqlx_pack_RESTORE(struct sqlx_name_s *name,
		const guint8 *raw, gsize rawsize);


/**
 * @param name
 * @param tabseq
 * @return
 */
GByteArray* sqlx_pack_REPLICATE(struct sqlx_name_s *name,
		struct TableSequence *tabseq);


/**
 * @param name
 * @return
 */
GByteArray* sqlx_pack_GETVERS(struct sqlx_name_s *name);


/**
 * @param tabseq
 * @param err
 * @return
 */
GByteArray* sqlx_encode_TableSequence(struct TableSequence *tabseq,
		GError **err);


/**
 * @param row
 * @param err
 * return
 */
GByteArray* sqlx_encode_Row(struct Row *row, GError **err);


/**
 * @param rows
 * @param err
 * @return
 */
GByteArray* sqlx_encode_RowSet(struct RowSet *rows, GError **err);

/**
 * @param table
 * @param err
 * @return
 */
GByteArray* sqlx_encode_Table(struct Table *table, GError **err);

/**
 * @param name
 * @param query
 * @param params
 * @return
 */
GByteArray* sqlx_pack_QUERY(struct sqlxsrv_name_s *name,
		const gchar *query, struct TableSequence *params);

/**
 * @param name
 * @param query
 * @return
 */
GByteArray* sqlx_pack_QUERY_single(struct sqlxsrv_name_s *name,
		const gchar *query);

/**
 * @param target
 * @param name
 * @param dump
 * @param dump_size
 * @return
 */
GError * peer_restore(const gchar *target, struct sqlx_name_s *name,
		guint8 *dump, gsize dump_size);

/**
 * @param target
 * @param name
 * @param result
 * @return
 */
GError * peer_dump(const gchar *target, struct sqlx_name_s *name,
		GByteArray **result);

/** @} */

#endif /* HC__SQLX_REMOTE_H */
