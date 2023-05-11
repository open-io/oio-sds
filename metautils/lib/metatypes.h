/*
OpenIO SDS metautils
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2020-2023 OVH SAS

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

# include <core/oiourl.h>
# include <glib.h>

/** One plus the maximum length of a volume name
 * i.e. a size enough to store the C string */
#define LIMIT_LENGTH_VOLUMENAME 256

/** One plus the maximum length of a storage policy name
 * i.e. a size enough to store the C string */
#define LIMIT_LENGTH_STGPOLICY 32

/** One plus the maximum length of a service tag name
 * i.e. a size enough to store the C string */
#define LIMIT_LENGTH_TAGNAME 32

/** One plus the maximum length of a chunk URL
 * i.e. a size enough to store the C string */
#define LIMIT_LENGTH_CHUNKURL 512

/** One plus the maximum length of a database name
 * i.e. a size enough to store the C string */
#define LIMIT_LENGTH_BASENAME 256

/** One plus the maximum length of a service type name, with all its subtypes
 * i.e. a size enough to store the C string */
#define LIMIT_LENGTH_SRVTYPE 32

/** One plus the maximum length of a database type, including all its subtypes
 * i.e. a size enough to store the C string */
#define LIMIT_LENGTH_BASETYPE 32

/** One plus the maximum length of a database suffix, including all its subtypes
 * i.e. a size enough to store the C string */
#define LIMIT_LENGTH_BASESUFFIX 32

/** One plus the maximum length of the textual representation of a service id
 * i.e. a size enough to store the C string */
#define LIMIT_LENGTH_SRVID 64

/** One plus the maximum length of a single service option
 * i.e. a size enough to store the C string */
#define LIMIT_LENGTH_SRVARGS 256

#define TYPE_TO_STRLEN(T)  ((sizeof(T)*2)+1)
#define STRLEN_CHUNKID     TYPE_TO_STRLEN(hash_sha256_t)
#define STRLEN_CONTENTID   65
#define STRLEN_CONTAINERID TYPE_TO_STRLEN(container_id_t)
#define STRLEN_CHUNKHASH   TYPE_TO_STRLEN(hash_md5_t)
#define STRLEN_ADDRINFO    sizeof("[XXXX:XXXX:XXXX:XXXX:XXXX:XXXX]:SSSSS")
#define STRLEN_SHA256      TYPE_TO_STRLEN(hash_sha256_t)
#define STRLEN_MD5         TYPE_TO_STRLEN(hash_md5_t)

/** Type to store a sha256 hash */
typedef guint8 hash_sha256_t[32];

/** Type to store a md5 hash */
typedef guint8 hash_md5_t[16];

/** Type to store a chunk hash */
typedef hash_md5_t chunk_hash_t;

/** Type to store a container id */
typedef hash_sha256_t container_id_t;

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
 * Type to store a namespace info
 */
typedef struct namespace_info_s
{
	gchar name[LIMIT_LENGTH_NSNAME]; /**< The namespace name */
	GHashTable* storage_policy;	 /**< Storage policies definitions name = STG_CLASS:DATA_SEC:DATA_THREAT */
	GHashTable* data_security;	 /**< Data security definitions name = TYPE:OTHER_INFO */
	GHashTable* service_pools;   /**< Service policies definitions name = GSList<char*> */
} namespace_info_t;

/**
 * Type to store a score
 */
typedef struct score_s
{
	gint32 value;		/**< The score value */
	// Watch out for 19 Jan 2038 03:14:07
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

enum service_tag_value_type_e
{
	STVT_I64 = 1,	/**< An int64 */
	STVT_REAL = 2,	/**< A double */
	STVT_BOOL = 3,	/**< A boolean */
	STVT_STR = 4,	/**< A string */
	STVT_BUF = 5,	/**< A bin buffer */
};

/**
 * Type to store a service tag
 */
typedef struct service_tag_s
{
	char name[LIMIT_LENGTH_TAGNAME];	/**< The tag name */

	enum service_tag_value_type_e type;

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
	score_t put_score;                  /**< The service score for write operations */
	score_t get_score;                  /**< The service score for read operations */
	GPtrArray *tags;                    /**< The list of service tags */
} service_info_t;

/**
 * Type to store a service info
 */
typedef struct service_info_dated_s
{
	service_info_t *si; /**< The service info */
	time_t lock_mtime;  /**< The modification time of the lock */
	time_t tags_mtime;  /**< The modification time of the tags */
} service_info_dated_t;

#endif /*OIO_SDS__metautils__lib__metatypes_h*/
