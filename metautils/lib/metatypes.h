/**
 * @file metatypes.h
 * The global types definition
 */
#ifndef __METATYPES_H__
# define __METATYPES_H__
# include <glib.h>

/**
 * @defgroup metautils_types Metatypes
 * @ingroup metautils
 * @{
 */

/** The maximum length of a container name */
#define LIMIT_LENGTH_CONTAINERNAME 1024

/** The maximum length of a volume name */
#define LIMIT_LENGTH_VOLUMENAME 256

/** The maximum length of a namespace name */
#define LIMIT_LENGTH_NSNAME 256

/** The maximum length of a storage policy name */
#define LIMIT_LENGTH_STGPOLICY 256

/** The maximum length of a content name */
#define LIMIT_LENGTH_CONTENTPATH 1024

/** The maximum length of a container event message */
#define LIMIT_LENGTH_EVENTMESSAGE 2048

/** The maximum length of a service tag name */
#define LIMIT_LENGTH_TAGNAME 32

/** The maximum length of a service type name */
#define LIMIT_LENGTH_SRVTYPE 32

/** The maximum length of a service storage class */
#define LIMIT_LENGTH_STGCLASS 32

/** The maximum length of a location name */
#define LIMIT_LENGTH_LOCNAME 64

/** The maximum length of a container event type */
#define LIMIT_LENGTH_TYPE 50

/** The maximum length of a container event ref */
#define LIMIT_LENGTH_REF 256

/** The maximum length of a URL query string (including '?') */
#define LIMIT_LENGTH_HCURL_OPTIONS 512

/** The maximum length of a URL
 * (namespace, container, content, options, separators) */
#define LIMIT_LENGTH_HCURL (LIMIT_LENGTH_NSNAME +\
	LIMIT_LENGTH_CONTAINERNAME + LIMIT_LENGTH_CONTENTPATH +\
	LIMIT_LENGTH_HCURL_OPTIONS + 2)

/** The maximum length for values of 'admin' table */
#define LIMIT_LENGTH_ADMIN_VALUE 1024

#define TYPE_TO_STRLEN(T)  ((sizeof(T)*2)+1)
#define STRLEN_CHUNKID     TYPE_TO_STRLEN(hash_sha256_t)
#define STRLEN_CONTAINERID TYPE_TO_STRLEN(container_id_t)
#define STRLEN_CHUNKHASH   TYPE_TO_STRLEN(hash_md5_t)
#define STRLEN_ADDRINFO    sizeof("[XXXX:XXXX:XXXX:XXXX:XXXX:XXXX]:SSSSS")

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
enum id_addr_type_e {
	TADDR_V4,	/**< An IPv4 address */
	TADDR_V6	/**< An IPv6 address */
};

/**
 * A network address binary representation
 */
union ip_addr_u {
	guint32 v4;	/**< The IPv4 representation */
	guint8 v6[16];	/**< The IPv6 representation */
};

/**
 * Type to store a service network address
 */
typedef struct addr_info_s
{
	enum id_addr_type_e type;	/**< The network address type */
	union ip_addr_u addr;		/**< The network address bin */
	guint16 port;			/**< The network port */
	guint16 protocol;		/**< The network protocol */
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
 * Type to store a container info
 */
typedef struct container_info_s
{
        container_id_t id;				/**< The container id */
        gint64 size;					/**< The container size */
} container_info_t;

/**
 * Type to store a path info
 */
typedef struct path_info_s
{
	gchar path[LIMIT_LENGTH_CONTENTPATH];	/**< The content name */
	content_length_t size;			/**< The content size */
	gboolean hasSize;			/**< The has size flag */
	GByteArray *user_metadata;		/**< The content user metadata */
	GByteArray *system_metadata;		/**< The content system metadata */
	gchar *version;				/**< */
	gboolean deleted;			/**< */
} path_info_t;

/**
 * Type to store a namespace info
 */
typedef struct namespace_info_s
{
	gchar name[LIMIT_LENGTH_NSNAME]; /**< The namespace name */
	chunk_size_t chunk_size;	 /**< The chunk size in the namespace */
	addr_info_t addr;                /**< The network address of the conscience */
	GHashTable* options;             /**< A hash of namespace options (gchar*) -> (GByteArray*) */
	struct ns_versions_s {
		gint64 srvcfg;
		gint64 evtcfg;
		gint64 nscfg;
		gint64 snapshot;         /**< Version counter for the grid snapshot*/
		gint64 broken;           /**< Version counter for the broken element list */
	} versions;                      /**< Some counters for the namespace configuration */
	GHashTable* storage_policy;	 /**< Storage policies definitions name = STG_CLASS:DATA_SEC:DATA_THREAT */
	GHashTable* data_security;	 /**< Data security definitions name = TYPE:OTHER_INFO */
	GHashTable* data_treatments;	 /**< Data treatments definitions name = TYPE:OTHER_INFO */
	GHashTable* storage_class;	 /**< Storage class definitions name = fallback_1:[...]:fallback_N */
	GSList *writable_vns;		 /**< List of not full virtual namespaces */
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
 * Type to store a container id prefix in META0
 */
typedef struct prefix_s
{
	guint8 bytes[2];	/**< The prefix */
} prefix_t;

/**
 * Type to store a container id prefix in META1
 */
typedef struct prefix_data_s
{
	guint32 flags;		/**< The state flags */
	GSList *addr;		/**< A list of META1 address ? */
} prefix_data_t;

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
		STVT_MACRO = 6	/**< A macro */
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
		struct
		{
			gchar *type;	/**< The macro type */
			gchar *param;	/**< The macro param */
		} macro;	/**< The macro representation */
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
 * Represents a chunk as it is stored in META2 database
 */
typedef struct meta2_raw_chunk_s
{
        chunk_id_t id;        /**< The chunk id */
        chunk_hash_t hash;    /**< The chunk hash */
        guint32 flags;        /**< The state flags */
        gint64 size;          /**< The chunk size */
        guint32 position;     /**< The chunk position */
        GByteArray *metadata; /**< The chunk metadata */
} meta2_raw_chunk_t;

/**
 * Represents a content as it it stored in the META2 database.
 */
typedef struct meta2_raw_content_s
{
        container_id_t container_id; /**< The container id */
        gchar path[LIMIT_LENGTH_CONTENTPATH + 1]; /**< The content name */
        guint32 flags;               /**< The state flags */
        guint32 nb_chunks;           /**< The number of chunks */
        gint64 size;                 /**< The content size */
        GByteArray *metadata;        /**< The content metadata */
        GByteArray *system_metadata; /**< The content system metadata */
        GSList *raw_chunks;          /**< The list of chunks */
	content_version_t version;   /**< The content version */
	gboolean deleted;	     /**< True if the content is flagged deleted */
	gchar *storage_policy;	/**< The storage policy */
} meta2_raw_content_t;

/**
  * Represents a container as it is stored in META1 database
 */
typedef struct meta1_raw_container_s
{
        container_id_t id;  /**< The container id */
        gchar name[LIMIT_LENGTH_CONTAINERNAME + 1];	/**< The container name */
        GSList *meta2;      /**< The list of META2 addresses hosting this container */
        guint32 flags;      /**< The stat flags */
} meta1_raw_container_t;

/**
 * Represents a chunk info in text format
 */
typedef struct chunk_textinfo_s
{
        gchar *id;           /**< The chunk id */
        gchar *path;         /**< The chunk path */
        gchar *size;         /**< The chunk size */
        gchar *position;     /**< The chunk position */
        gchar *hash;         /**< The chunk hash */
        gchar *metadata;     /**< The chunk metadata */
        gchar *container_id; /**< The container id */
} chunk_textinfo_t;

/**
 * Represents a content info in text format
 */
typedef struct content_textinfo_s
{
        gchar *container_id;    /**< The container id */
        gchar *path;            /**< The content name */
        gchar *size;            /**< The content size */
        gchar *chunk_nb;        /**< The number of chunks */
        gchar *metadata;        /**< The user metadata */
        gchar *system_metadata; /**< The system metadata */
	gchar *storage_policy;	/**< The storage policy */
	gchar *rawx_list; /**< The rawx list (introduced by the rainx service) */
	gchar *spare_rawx_list; /**< The rawx list for reconstruction (introduced by the rainx service) */
	gchar *version; /**< The content version */
} content_textinfo_t;

/**
 * Represents a event on container stored in META2 database.
 */
typedef struct container_event_s
{
	gint64 rowid;                     /**< The position of the event in db */
	gint64 timestamp;                 /**< The date of message */
	gchar type[LIMIT_LENGTH_TYPE +1]; /**< The type of event */
	gchar ref[LIMIT_LENGTH_REF +1];   /**< A reference field, as requested by the ugly BU-men */
	GByteArray *message;              /**< The message */
} container_event_t;

/**
 * Represents a versioned vey/value pair that can be associated to
 * either a container or a content in a META2 service.
 */
typedef struct meta2_property_s
{
	gchar *name;               /**<  */
	content_version_t version; /**<  */
	GByteArray *value;         /**<  */
} meta2_property_t;

/**
 * Represent the content-wide information
 */
typedef struct meta2_raw_content_header_s
{
        container_id_t container_id; /**< The container id */
        gchar path[LIMIT_LENGTH_CONTENTPATH + 1];	/**< The content name */
        guint32 flags;               /**< The state flags */
        guint32 nb_chunks;           /**< The number of chunks */
        gint64 size;                 /**< The content size */
        GByteArray *metadata;        /**< The content metadata */
        GByteArray *system_metadata; /**< The content system metadata */
	content_version_t version;   /**< The content version */
	gboolean deleted;	     /**< The content deleted flag */
	char *policy;			 /**< The content policy */
} meta2_raw_content_header_t;

/**
 * Represents whole information stored about a content, in the meta2
 */
typedef struct meta2_raw_content_v2_s
{
	struct meta2_raw_content_header_s header;
        GSList *raw_chunks;    /**< The list of (meta2_raw_chunk_s*) */
        GSList *raw_services;  /**< The list of (service_info_t*) */
        GSList *properties;    /**< The list of (meta2_property_t*) */
} meta2_raw_content_v2_t;

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

#endif /*__METATYPES_H__*/
