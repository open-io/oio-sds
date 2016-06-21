/*
OpenIO SDS metautils
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

#ifndef OIO_SDS__metautils__lib__metatypes_h
# define OIO_SDS__metautils__lib__metatypes_h 1

# include <glib.h>

/**
 * @defgroup metautils_types Metatypes
 * @ingroup metautils
 * @{
 */

/** The maximum length of a volume name */
#define LIMIT_LENGTH_VOLUMENAME 256

/** The maximum length of a namespace name */
#define LIMIT_LENGTH_NSNAME 64

/** The maximum length of a content name */
#define LIMIT_LENGTH_CONTENTPATH 1024

/** The maximum length of a storage policy name */
#define LIMIT_LENGTH_STGPOLICY 32

/** The maximum length of a service tag name */
#define LIMIT_LENGTH_TAGNAME 32

/** The maximum length of a location name */
#define LIMIT_LENGTH_LOCNAME 64

#define LIMIT_LENGTH_CHUNKURL 512

#define LIMIT_LENGTH_REQID 128

#define LIMIT_LENGTH_BASENAME 256

#define LIMIT_LENGTH_BASETYPE 32

/** The maximum length of a service type name */
#define LIMIT_LENGTH_SRVID 64

/** The maximum length of a service id */
#define LIMIT_LENGTH_SRVTYPE 32

/** The maximum length of service options */
#define LIMIT_LENGTH_SRVARGS 256

/** The maximum length for values of 'admin' table */
#define LIMIT_LENGTH_ADMIN_VALUE 1024

#define TYPE_TO_STRLEN(T)  ((sizeof(T)*2)+1)
#define STRLEN_CHUNKID     TYPE_TO_STRLEN(hash_sha256_t)
#define STRLEN_CONTAINERID TYPE_TO_STRLEN(container_id_t)
#define STRLEN_CHUNKHASH   TYPE_TO_STRLEN(hash_md5_t)
#define STRLEN_ADDRINFO    sizeof("[XXXX:XXXX:XXXX:XXXX:XXXX:XXXX]:SSSSS")
#define STRLEN_SHA256      TYPE_TO_STRLEN(hash_sha256_t)
#define STRLEN_MD5         TYPE_TO_STRLEN(hash_md5_t)

/** Type to store a file size */
typedef gint64 file_size_t;

/** Type to store a sha256 hash */
typedef guint8 hash_sha256_t[32];

/** Type to store a md5 hash */
typedef guint8 hash_md5_t[16];

/** Type to store a message id */
typedef guint32 meta_message_id_t;

/** Type to store a chunk position */
typedef guint32 chunk_position_t;

/** Type to store a chunk size */
typedef gint64 chunk_size_t;

/** Type to store a chunk hash */
typedef hash_md5_t chunk_hash_t;

/** Type to store a content hash */
typedef hash_md5_t content_hash_t;

/** Type to store a container id */
typedef hash_sha256_t container_id_t;

/** Type to store a status */
typedef guint32 status_t;

/** Type to store a content length */
typedef gint64 content_length_t;

/** Type to store a content version */
typedef gint64 content_version_t;

/**
 * The list of address types
 */
enum id_addr_type_e
{
	TADDR_V4,	/**< An IPv4 address */
	TADDR_V6	/**< An IPv6 address */
};

/**
 * A network address binary representation
 */
union ip_addr_u
{
	guint32 v4;	/**< The IPv4 representation */
	guint8 v6[16];	/**< The IPv6 representation */
};

/**
 * Type to store a service network address
 */
typedef struct addr_info_s
{
	union ip_addr_u addr; /**< The network address bin */
	guint16 port; /**< The network port */
	enum id_addr_type_e type : 8; /**< The network address type */
} addr_info_t;

/**
 * Type to store a chunk id
 */
typedef struct chunk_id_s
{
	hash_sha256_t id;			/**< The unique id */
	addr_info_t addr;			/**< The RAWX addr on which the chunk is stored */
	gchar vol[LIMIT_LENGTH_VOLUMENAME];	/**< The volume used by the RAWX on which the chunk is stored */
} chunk_id_t;

/**
 * Type to store a chunk info
 */
typedef struct chunk_info_s
{
	chunk_id_t id;			/**< The chunk id */
	chunk_size_t size;		/**< The chunk size */
	chunk_position_t position;	/**< The chunk position */
	chunk_hash_t hash;		/**< The chunk hash */
	guint32 nb;			/**< The total number of chunks needed for the content this chunk belongs to */
} chunk_info_t;

/**
 * Type to store a namespace info
 */
typedef struct namespace_info_s
{
	gchar name[LIMIT_LENGTH_NSNAME]; /**< The namespace name */
	chunk_size_t chunk_size;	 /**< The chunk size in the namespace */
	GHashTable* options;             /**< A hash of namespace options (gchar*) -> (GByteArray*) */
	GHashTable* storage_policy;	 /**< Storage policies definitions name = STG_CLASS:DATA_SEC:DATA_THREAT */
	GHashTable* data_security;	 /**< Data security definitions name = TYPE:OTHER_INFO */
	GHashTable* storage_class;	 /**< Storage class definitions name = fallback_1:[...]:fallback_N */
} namespace_info_t;

/**
 * Type to store a score
 */
typedef struct score_s
{
	gint32 value;		/**< The score value */
	gint32 timestamp;	/**< The timestamp this score was created */
} score_t;

/**
 * Type to store a META0 info
 */
typedef struct meta0_info_s
{
	addr_info_t addr;	/**< The META0 network address */
	guint8 *prefixes;	/**< The list of container id prefixes in the META0 */
	gsize prefixes_size;	/**< The size of the prefixes list */
} meta0_info_t;

/**
 * Type to store a key/value pair
 */
typedef struct key_value_pair_s
{
	gchar *key;		/**< The key */
	GByteArray *value;	/**< The value */
} key_value_pair_t;

/**
 * Type to store a service tag
 */
typedef struct service_tag_s
{
	char name[LIMIT_LENGTH_TAGNAME];	/**< The tag name */

	/**
	 * The list of tag value types
	 */
	enum service_tag_value_type_e
	{
		STVT_I64 = 1,	/**< An int64 */
		STVT_REAL = 2,	/**< A double */
		STVT_BOOL = 3,	/**< A boolean */
		STVT_STR = 4,	/**< A string */
		STVT_BUF = 5,	/**< A bin buffer */
	} type;					/**< The tag type */
	/**
	 * Type to store a tag value
	 */
	union
	{
		gint64 i;	/**< The int64 representation */
		gdouble r;	/**< The double representation */
		gboolean b;	/**< The boolean representation */
		gchar buf[MAX(sizeof(gint64), 2 * sizeof(gchar *))];	/**< The bin buffer representation */
		gchar *s;	/**< The string representation */
	} value;				/**< The tag value */
} service_tag_t;

/**
 * Type to store a service info
 */
typedef struct service_info_s
{
	gchar ns_name[LIMIT_LENGTH_NSNAME]; /**< The namespace name this service belongs to */
	gchar type[LIMIT_LENGTH_SRVTYPE];   /**< The service type */
	addr_info_t addr;                   /**< The service network address */
	score_t score;                      /**< The service score */
	GPtrArray *tags;                    /**< The list of service tags */
} service_info_t;

/**
 * Represent an ACL rule
 */
typedef struct addr_rule_s
{
	gchar* network_addr; /**< IPv4 in decimal dotted notation */
	gchar* network_mask; /**< IPv4 in decimal dotted notation */
	gboolean authorize;  /**< Allow (TRUE) or deny (FALSE) */
} addr_rule_t;

/** @} */

#endif /*OIO_SDS__metautils__lib__metatypes_h*/
