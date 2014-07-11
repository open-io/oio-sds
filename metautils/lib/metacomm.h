#ifndef __METACOMM__H__
# define __METACOMM__H__

/**
 * @file metacomm.h
 * Global communication library
 */

/**
 * @defgroup metautils_comm Metacomm
 * @ingroup metautils
 * @{
 */

# include <metautils/lib/metautils.h>

/* A flag usable in metacnx_ctx_s.flags to keep the connection alive */
#define METACNX_FLAGMASK_KEEPALIVE 0x00000001

#define REPSEQ_FINAL         0x00000001
#define REPSEQ_ERROR         0X00000002
#define REPSEQ_BODYMANDATORY 0x00000004

#define NAME_MSGNAME_METAREPLY "REPLY"
#define NAME_MSGKEY_STATUS "STATUS"
#define NAME_MSGKEY_MESSAGE "MSG"
#define NAME_MSGKEY_FLAG "FLAG"
#define NAME_MSGKEY_PREFIX "PREFIX"
#define NAME_MSGKEY_WARNING "WARNING"
#define NAME_MSGKEY_TIMESTAMP "TIMESTAMP"
#define NAME_MSGKEY_CONTAINERID "CONTAINER_ID"
#define NAME_MSGKEY_VIRTUALNAMESPACE "VIRTUAL_NAMESPACE"
#define NAME_MSGKEY_NAMESPACE "NAMESPACE"
#define NAME_MSGKEY_SRVTYPE "SRVTYPE"
#define NAME_MSGKEY_CONTAINERNAME "CONTAINER_NAME"
#define NAME_MSGKEY_CONTENTPATH "CONTENT_PATH"
#define NAME_MSGKEY_CONTENTLENGTH "CONTENT_LENGTH"
#define NAME_MSGKEY_CHUNKID "CHUNKID"
#define NAME_MSGKEY_STGPOLICY "STORAGE_POLICY"
#define NAME_MSGKEY_M1_MASTER "M1_MASTER"

#define DECLARE_MARSHALLER(Name) \
/**
 * @param l
 * @param d
 * @param dSize
 * @param err
 * @return
 */ \
gint Name (GSList *l, void **d, gsize *dSize, GError **err)

#define DECLARE_MARSHALLER_GBA(Name) \
/**
 * @param l
 * @param err
 * @return
 */ \
GByteArray* Name (GSList *l, GError **err)

#define DECLARE_UNMARSHALLER(Name) \
/**
 * @param l
 * @param s
 * @param sSize
 * @param err
 * @return
 */ \
gint Name (GSList **l, const void *s, gsize *sSize, GError **err)

#define DECLARE_BODY_MANAGER(Name) \
/**
 * @param err
 * @param udata
 * @param code
 * @param body
 * @param bodySize
 * @return
 */ \
gint Name (GError **err, gpointer udata, gint code, guint8 *body, gsize bodySize)

typedef struct message_s *MESSAGE;

/* ------------------------------------------------------------------------- */

/**
 * @defgroup metacomm_metacnx Connections to META services
 * @ingroup metautils_comm
 * @{
 */

struct metacnx_ctx_s;

/**
 * Struct to store a META connection context
 */
struct metacnx_ctx_s
{
	GByteArray *id;		/**< The connection id */
	addr_info_t addr;	/**< The connection server addr */
	int fd;			/**< The connection fd */
	guint8 flags;		/**< The connection configuration flags */
	/**
	 * Struct to store a connection timeout
	 */
	struct
	{
		int cnx;/*<! The connection timeout */
		int req;/*<! The request timeout */
	} timeout;		/*<! The timeouts */
};

/**
 * Allocate a new instance of struct metacnx_ctx_s
 *
 * @param err
 * @return a newly allocated instance of struct metacnx_ctx_s or NULL if an error occured (err is set)
 */
struct metacnx_ctx_s *metacnx_create(GError ** err);

/**
 * Clear a struct metacnx_ctx_s
 * 
 * @param ctx an allocated instance of struct metacnx_ctx_s
 */
void metacnx_clear(struct metacnx_ctx_s *ctx);

/**
 * Free a struct metacnx_ctx_s
 *
 * @param ctx an allocated instance of struct metacnx_ctx_s
 */
void metacnx_destroy(struct metacnx_ctx_s *ctx);

/**
 * Initialize a struct metacnx_ctx_s with host and port
 * 
 * @param ctx an instance of struct metacnx_ctx_s allocated with metacnx_create()
 * @param host the hostname of the service the connection has to be estalished to
 * @param port the port of the service the connection has to be estalished to
 * @param err
 * @return TRUE or FALSE if an error occured (err is set)
 */
gboolean metacnx_init(struct metacnx_ctx_s *ctx, const gchar * host,
		int port, GError ** err);

/**
 * Initialize a struct metacnx_ctx_s with URL IPv4:port or [IPv6]:port
 * 
 * @param ctx an instance of struct metacnx_ctx_s allocated with metacnx_create()
 * @param url the URL of the service the connection has to be estalished to
 * @param err
 * @return TRUE or FALSE if an error occured (err is set)
 */
gboolean metacnx_init_with_url(struct metacnx_ctx_s *ctx, const gchar *url,
		GError ** err);

/**
 * Initialize a struct metacnx_ctx_s with addr_info_t
 * 
 * @param ctx an instance of struct metacnx_ctx_s allocated with metacnx_create()
 * @param addr an addr_info_t representin the address of the target we want to connect to
 * @param err
 * @return TRUE or FALSE if an error occured (err is set)
 */
gboolean metacnx_init_with_addr(struct metacnx_ctx_s *ctx,
		const addr_info_t* addr, GError** err);

/**
 * Open a connection to a META
 *
 * @param ctx an instance of struct metacnx_ctx_s allocated with metacnx_create() and initialized with metacnx_init() or metacnx_init_with_url()
 * @param err
 * @return TRUE or FALSE if an error occured (err is set)
 */
gboolean metacnx_open(struct metacnx_ctx_s *ctx, GError ** err);

/**
 * Check if a connection to a META is opened
 *
 * @param ctx an instance of struct metacnx_ctx_s opened with metacnx_open()
 * @return TRUE if the connection is opened, FALSE otherwise
 */
gboolean metacnx_is_open(struct metacnx_ctx_s *ctx);

/**
 * Close an opened connection to a METAX
 * 
 * @param ctx an instance of struct metacnx_ctx_s opened with metacnx_open()
 */
void metacnx_close(struct metacnx_ctx_s *ctx);

/** @} */

/* ------------------------------------------------------------------------- */

/**
 * @defgroup metacomm_replyseq Manager for sequences of replies
 * @ingroup metautils_comm
 * @{
 */

/**
 * @param err
 * @param udata
 * @param code
 * @param body
 * @param bodySize
 * @return
 */
typedef gboolean(*content_handler_f) (GError ** err, gpointer udata, gint code, guint8 * body, gsize bodySize);

/**
 * @param err
 * @param udata
 * @param code
 * @param rep
 * @return
 */
typedef gboolean(*msg_handler_f) (GError ** err, gpointer udata, gint code, MESSAGE rep);

/**
 *
 */
struct code_handler_s
{
	int code;                          /**<  */
	guint32 flags;                     /**<  */
	content_handler_f content_handler; /**<  */
	msg_handler_f msg_handler;         /**<  */
};

/**
 *
 */
struct reply_sequence_data_s
{
	gpointer udata;               /**<  */
	int nbHandlers;               /**<  */
	struct code_handler_s *codes; /**<  */
};

/**
 * @param err
 * @param ctx
 * @param request
 * @param handlers
 * @return
 */
gboolean metaXClient_reply_sequence_run_context(GError ** err,
		struct metacnx_ctx_s *ctx, MESSAGE request,
		struct reply_sequence_data_s *handlers);

/** Wrapper around metaXClient_reply_sequence_run_context()
 *
 * @param err
 * @param request
 * @param fd
 * @param ms
 * @param data
 * @return
 * @see metaXClient_reply_sequence_run_context()
 * @deprecated
 */
gboolean metaXClient_reply_sequence_run(GError ** err, MESSAGE request,
		int *fd, gint ms, struct reply_sequence_data_s *data);

/** Wrapper around metaXClient_reply_sequence_run_context()
 *
 * @param err
 * @param request
 * @param addr
 * @param ms
 * @param data
 * @return
 * @see metaXClient_reply_sequence_run_context()
 * @deprecated
 */
gboolean metaXClient_reply_sequence_run_from_addrinfo(GError ** err,
		MESSAGE request, addr_info_t * addr, gint ms,
		struct reply_sequence_data_s *data);

/** @} */

/* ------------------------------------------------------------------------- */

/**
 * @defgroup metacomm_message Messages enveloppes
 * @@ingroup metautils_comm
 * @{
 */

/**
 * Builds a simple reply for the given request. This function
 * automates the copy of the required fields from the request,
 * and sets the appropriated fields with the given status and
 * message.
 *
 * The reply pointer wust be freed with message_destroy().
 *
 * @param reply
 * @param request
 * @param status
 * @param msg
 * @param err
 * @return
 */
gint metaXServer_reply_simple(MESSAGE * reply, MESSAGE request, gint status,
		const gchar * msg, GError ** err);


/**
 * Performs the opposite operation : retrieves the core elements
 * of the message (supposed to be a reply).
 *
 * The message returned in the msg pointer is a copy of the original.
 * It is allocated with the g_lib and must be freed with g_free().
 *
 * @param reply
 * @param status
 * @param msg
 * @param err
 * @return
 */
gint metaXClient_reply_simple(MESSAGE reply, gint * status, gchar ** msg,
		GError ** err);


/**
 * Altough the list of fixed parameters is quite small, we do not want a set of
 * accessor and modifier for each parameter.
 * So the parameter's accessor, modifier and deleter take one argument to specify
 * the parameter on wich the action is made.
 */
enum message_param_e
{
	MP_ID,
	/**<Specify an action on the ID parameter*/
	MP_NAME,
	/**<Specify an action on the NAME parameter*/
	MP_VERSION,
	/**<Specify an action on the VERSION parameter*/
	MP_BODY
	/**<Specify an action on the BODY parameter*/
};

#define message_get_ID(M,V,L,E)      message_get_param((M),MP_ID,(V),(L),(E))
#define message_get_NAME(M,V,L,E)    message_get_param((M),MP_NAME,(V),(L),(E))
#define message_get_VERSION(M,V,L,E) message_get_param((M),MP_VERSION,(V),(L),(E))
#define message_get_BODY(M,V,L,E)    message_get_param((M),MP_BODY,(V),(L),(E))

#define message_set_ID(M,V,L,E)      message_set_param((M),MP_ID,(V),(L),(E))
#define message_set_NAME(M,V,L,E)    message_set_param((M),MP_NAME,(V),(L),(E))
#define message_set_VERSION(M,V,L,E) message_set_param((M),MP_VERSION,(V),(L),(E))
#define message_set_BODY(M,V,L,E)    message_set_param((M),MP_BODY,(V),(L),(E))

#define message_has_ID(M,E)      message_has_param((M),MP_ID,(E))
#define message_has_NAME(M,E)    message_has_param((M),MP_NAME,(E))
#define message_has_VERSION(M,E) message_has_param((M),MP_VERSION,(E))
#define message_has_BODY(M,E)    message_has_param((M),MP_BODY,(E))

/**
 * Allocates all the internal structures of a hidden message.
 *
 * @param m a pointer to a message pointer. At the exit of the function,
 * it will be set to the newly allocated value.
 * @param error the error structure that will be set in case of failure
 * @return 1 on success, 0 on error
 */
gint message_create(MESSAGE * m, GError ** error);


/**
 * Frees all the internal structures of the pointed message.
 *
 * @param m a pointer to the message to destroy. The pointer itself won't be
 * freed.
 * @param error the error structure that will be set in case of failure
 * @return 1 on sucess, 0 on error
 */
void message_destroy(MESSAGE m, GError ** error);


/**
 * Returns wether the given message has the targeted parameter or not.
 *
 * @param m the inspected message
 * @param mp the code of the targeted parameter
 * @param error the error structure that will be set in case of failure
 * @return 1 on success and true, 0 on false or error
 */
gint message_has_param(MESSAGE m, enum message_param_e mp, GError ** error);


/**
 * @brief Finds and returns a pointer to a given quick parameter in the given
 * message.
 *
 * The case where the target parameter is not present is cansidered as an error.
 *
 * @param m a pointer to the inspected message
 * @param mp the code of the targeted parameter
 * @param s a pointer destined to hold the pointer to the real parameter buffer.
 * Warning, at exit, this value is not a copy. Any change is the returned buffer
 * really acts on the message. It cannot be NULL.
 * @param sSize a holder pointer to store the size of the parameter buffer. It
 * cannot be NULL.
 * @param error the error structure that will be set in case of failure. It can
 * be NULL.
 * @return 1 on success, 0 on error
 */
gint message_get_param(MESSAGE m, enum message_param_e mp, void **s, gsize * sSize, GError ** error);


/**
 * @brief Sets a new value for the given parameter, in the given message.
 * The given new value will be copied.
 *
 * If this parameter is already present, the existing buffer will be freed
 * and discarded.
 *
 * @param m the inspected message
 * @param mp thet code of the targeted quick parameter
 * @param s a pointer to a memory buffer holding the new value of the parameter.
 * @param sSize the size of the given memory buffer holding the value.
 * @param error the error structure that will be set in case of failure
 * @return 1 on success, 0 on error
 */
gint message_set_param(MESSAGE m, enum message_param_e mp,
		const void *s, gsize sSize, GError ** error);

/**
 * Adds a new custom field in the list of the message. Now check is made to
 * know whether the given field is already present or not. The given new value
 * will be copied.
 *
 * @param m a pointer to a message. It may not be NULL.
 * @param name a not NULL pointer to the name of the new field.
 * @param nameSize the length of the name of the new field.
 * @param value a pointer to the content of the new field.
 * @param valueSize the length of the new value of the field.
 * @param error the error structure that will be set in case of failure
 * @return 1 on success, 0 on error
 */
gint message_add_field(MESSAGE m, const void *name, gsize nameSize,
		const void *value, gsize valueSize, GError ** error);


/**
 * Retrieves a copy of the 
 *
 * @param m
 * @param name
 * @param nameSize
 * @param value
 * @param valueSize
 * @param error the error structure that will be set in case of failure
 * @return 1 on success and found, 0 on not found, 1 on error
 */
gint message_get_field(MESSAGE m, const void *name, gsize nameSize,
		void **value, gsize * valueSize, GError ** error);

/**
 *
 * @param m
 * @param name
 * @param nameSize
 * @param error the error structure that will be set in case of failure
 * @return 1 on success, 0 on error
 */
gint message_del_field(MESSAGE m, const void *name, gsize nameSize,
		GError ** error);


/**
 * Return the names of all the fields in the given message
 *
 * On success, it always return a not-NULL pointer to an array. If no stats
 * have been found, the first entry of the array will be NULL.
 *
 * @param m the message to be inspected.
 * @param error the error structure set in case of failure
 * @return a NULLL terminated array of NULL-terminated character arrays. It
 * has been allocated with g_malloc() calls and should be freed with
 * g_strfreev(). In case of failure, NULL is retrurned.
 * @see g_strfreev() in the glib documentation
 */
gchar **message_get_field_names(MESSAGE m, GError ** error);


/**
 * @param m
 * @param hash
 * @param error
 * @return
 */ 
gint message_get_fields(MESSAGE m, GHashTable ** hash, GError ** error);

/**
 * @param err
 * @param id
 * @param name
 * @param body
 * @param ... a NULL-terminated va_list of GByteArray*
 * @return
 */
MESSAGE message_create_request(GError ** err, GByteArray * id,
		const char *name, GByteArray * body, ...);

/**
 * @param m
 * @param args
 */
void message_add_fieldv_gba(MESSAGE m, va_list args);

/**
 * @param m
 * @param ...
 */
void message_add_fields_gba(MESSAGE m, ...);

/**
 * @param m
 * @param args
 */
void message_add_fieldv_str(MESSAGE m, va_list args);

/**
 * @param m
 * @param ...
 */
void message_add_fields_str(MESSAGE m, ...);

/**
 * Perform the serialization of the message.
 *
 * @param m a pointer to the message to serialzie
 *
 * @param s the buffer that will contain the serialized form of the message
 *
 * @param sSize a pointer to the size of the buffer. When the function is called,
 * it must contain the maximum length of the buffer, and at the exit of the 
 * function, it holds the filled length in the buffer.
 *
 * @param error the error structure that will be set in case of failure
 *
 * @return 1 upon succes, 0 upon error
 */
gint message_marshall(MESSAGE m, void **s, gsize * sSize, GError ** error);

/**
 * @param m
 * @param err
 * @return
 */
GByteArray* message_marshall_gba(MESSAGE m, GError **err);

/**
 * Allocates a new message and Unserializes the given buffer.
 * 
 * @param m a pointer to a message pointer.
 * @param s the source buffer containing the serialized form of the message
 * @param sSize a pointer the size of the source buffer. When the function
 * is called, it must contain the size of the buffer, and at exit, it holds
 * the number of bytes read in the buffer.
 * @param error the error structure that will be set in case of failure
 * @return 0 upon error, 1 upon success
 */
gint message_unmarshall(MESSAGE m, void *s, gsize * sSize, GError ** error);

/**
 * Calls message_marshall_gba() then message_destroy() on 'm'.
 *
 * @see message_marshall_gba
 * @param m
 * @return
 */
GByteArray* message_marshall_gba_and_clean(MESSAGE m);


/**
 * @param msg
 * @param n
 * @param cid
 * @return
 */
GError* message_extract_cid(struct message_s *msg, const gchar *n,
		container_id_t *cid);

/**
 * @param msg
 * @param n
 * @param d
 * @param dsize
 * @return
 */
GError* message_extract_prefix(struct message_s *msg, const gchar *n,
		guint8 *d, gsize *dsize);

/**
 * @param msg
 * @param n
 * @param mandatory
 * @param flag
 * @return
 */
GError* message_extract_flag(struct message_s *msg, const gchar *n,
		gboolean mandatory, gboolean *flag);

/*!
 * @param msg
 * @param n
 * @param mandatory
 * @param flags
 */
GError* message_extract_flags32(struct message_s *msg, const gchar *n,
		gboolean mandatory, guint32 *flags);

/**
 * @param msg
 * @param n
 * @param dst
 * @param dst_size
 * @return
 */
GError* message_extract_string(struct message_s *msg, const gchar *n, gchar *dst,
		gsize dst_size);

/**
 * @param msg
 * @param n
 * @param i64
 * @return
 */
GError* message_extract_strint64(struct message_s *msg, const gchar *n,
		gint64 *i64);

/**
 * @param msg
 * @param n
 * @param u
 * @return
 */
GError* message_extract_struint(struct message_s *msg, const gchar *n,
		guint *u);

/**
 * @param res
 * @param b
 * @param bs
 * @param err
 * @return
 */
typedef gint (body_decoder_f)(GSList **res, const void *b, gsize *bs, GError **err);

/**
 * @param msg
 * @param result
 * @param decoder
 * @return
 */
GError* message_extract_body_encoded(struct message_s *msg, GSList **result,
		body_decoder_f decoder);

/** Upon success, ensures result will be a printable string with a trailing \0
 * @param msg
 * @param result
 * @return
 */
GError* message_extract_body_string(struct message_s *msg, gchar **result);

/**
 * @param msg
 * @param result
 * @return
 */
GError* message_extract_body_gba(struct message_s *msg, GByteArray **result);

/**
 * @param msg
 * @param n
 * @param mandatory
 * @param result
 * @return
 */
GError* message_extract_header_gba(struct message_s *msg, const gchar *n,
		gboolean mandatory, GByteArray **result);

/**
 * @param msg
 * @param result
 * @return
 */
GError* message_extract_body_strv(struct message_s *msg, gchar ***result);


/** @} */

/* ------------------------------------------------------------------------- */

/**
 * @defgroup metacomm_structs ASN.1/BER Codec for various structures
 * @ingroup metautils_comm
 * @{
 */

/**
 * @param ni
 * @param s
 * @param sSize
 * @param err
 * @return
 */
gint namespace_info_unmarshall_one(struct namespace_info_s **ni,
		const void *s, gsize *sSize, GError **err);

DECLARE_MARSHALLER(namespace_info_list_marshall);
DECLARE_MARSHALLER_GBA(namespace_info_list_marshall_gba);
DECLARE_UNMARSHALLER(namespace_info_list_unmarshall);
DECLARE_BODY_MANAGER(namespace_info_concat);

DECLARE_MARSHALLER(chunk_info_marshall);
DECLARE_MARSHALLER_GBA(chunk_info_marshall_gba);
DECLARE_UNMARSHALLER(chunk_info_unmarshall);
DECLARE_BODY_MANAGER(chunk_info_concat);

DECLARE_MARSHALLER(container_info_marshall);
DECLARE_MARSHALLER_GBA(container_info_marshall_gba);
DECLARE_UNMARSHALLER(container_info_unmarshall);
DECLARE_BODY_MANAGER(container_info_concat);

DECLARE_MARSHALLER(addr_info_marshall);
DECLARE_MARSHALLER_GBA(addr_info_marshall_gba);
DECLARE_UNMARSHALLER(addr_info_unmarshall);
DECLARE_BODY_MANAGER(addr_info_concat);

DECLARE_MARSHALLER(path_info_marshall);
DECLARE_MARSHALLER_GBA(path_info_marshall_gba);
DECLARE_UNMARSHALLER(path_info_unmarshall);
DECLARE_BODY_MANAGER(path_info_concat);

DECLARE_MARSHALLER(container_event_marshall);
DECLARE_MARSHALLER_GBA(container_event_marshall_gba);
DECLARE_UNMARSHALLER(container_event_unmarshall);
DECLARE_BODY_MANAGER(container_event_concat);

DECLARE_MARSHALLER(meta0_info_marshall);
DECLARE_MARSHALLER_GBA(meta0_info_marshall_gba);
DECLARE_UNMARSHALLER(meta0_info_unmarshall);

DECLARE_MARSHALLER(key_value_pairs_marshall);
DECLARE_MARSHALLER_GBA(key_value_pairs_marshall_gba);
DECLARE_UNMARSHALLER(key_value_pairs_unmarshall);
DECLARE_BODY_MANAGER(key_value_pairs_concat);

DECLARE_MARSHALLER_GBA(strings_marshall_gba);
DECLARE_UNMARSHALLER(strings_unmarshall);
DECLARE_BODY_MANAGER(strings_concat);

DECLARE_MARSHALLER(service_info_marshall);
DECLARE_UNMARSHALLER(service_info_unmarshall);
DECLARE_MARSHALLER_GBA(service_info_marshall_gba);
DECLARE_BODY_MANAGER(service_info_concat);

DECLARE_MARSHALLER_GBA( meta2_property_marshall_gba);
DECLARE_MARSHALLER(     meta2_property_marshall);
DECLARE_UNMARSHALLER(   meta2_property_unmarshall);
DECLARE_BODY_MANAGER(   meta2_property_concat);

DECLARE_MARSHALLER_GBA( meta2_raw_content_header_marshall_gba);
DECLARE_MARSHALLER(     meta2_raw_content_header_marshall);
DECLARE_UNMARSHALLER(   meta2_raw_content_header_unmarshall);
DECLARE_BODY_MANAGER(   meta2_raw_content_header_concat);

DECLARE_MARSHALLER_GBA( meta2_raw_content_v2_marshall_gba);
DECLARE_MARSHALLER(     meta2_raw_content_v2_marshall);
DECLARE_UNMARSHALLER(   meta2_raw_content_v2_unmarshall);
DECLARE_BODY_MANAGER(   meta2_raw_content_v2_concat);

DECLARE_MARSHALLER_GBA( meta2_raw_chunk_marshall_gba);
DECLARE_MARSHALLER(     meta2_raw_chunk_marshall);
DECLARE_UNMARSHALLER(   meta2_raw_chunk_unmarshall);
DECLARE_BODY_MANAGER(   meta2_raw_chunk_concat);


/**
 * @param si the structure to be serialized. NULL is an error
 * @param err a pointer to the error structure being returned
 * @return NULL in case of error or a valid ASN.1 form of the given servccie_info
 */
GByteArray* service_info_marshall_1(service_info_t *si, GError **err);

/**
 * @param cnx
 * @param err
 * @param req_name
 * @param body
 * @param ...
 * @return
 */
GSList *service_info_sequence_request(struct metacnx_ctx_s *cnx, GError ** err,
		const gchar * req_name, GByteArray * body, ...);

/**
 * @param container
 * @param err
 * @return
 */
GByteArray *meta1_raw_container_marshall(struct meta1_raw_container_s *container,
		GError ** err);

/**
 * @param buf
 * @param buf_len
 * @param err
 * @return
 */
struct meta1_raw_container_s *meta1_raw_container_unmarshall(guint8 * buf,
		gsize buf_len, GError ** err);

/**
 * @param bytes
 * @param size
 * @param result
 * @return
 */
gboolean simple_integer_unmarshall(const guint8 * bytes, gsize size,
		gint64 * result);

/**
 * @param i64
 * @param err
 * @return
 */
GByteArray* simple_integer_marshall_gba(gint64 i64, GError **err);

/**
 * Serializes the content structure into its ASN.1 representation.
 * @param content
 * @param err
 * @return
 */
GByteArray *meta2_maintenance_marshall_content(
		struct meta2_raw_content_s *content, GError ** err);

/**
 * Unserializes the ASN.1 encoded content structure. The returned
 * structure has to be freed with the meta2_maintenance_destroy_content()
 * function
 * @param encoded_content
 * @param err
 * @return
 */
struct meta2_raw_content_s *meta2_maintenance_content_unmarshall_bytearray(
		GByteArray * encoded_content, GError ** err);

/**
 * @param buf
 * @param buf_size
 * @param err
 * @return
 */
struct meta2_raw_content_s *meta2_maintenance_content_unmarshall_buffer(
		guint8 * buf, gsize buf_size, GError ** err);

/**
 * @param chunkId
 * @param err
 * @return
 */
GByteArray *chunk_id_marshall(const chunk_id_t * chunkId, GError ** err);

/**
 * @param chunkId
 * @param src
 * @param srcSize
 * @param err
 * @return
 */
gint chunk_id_unmarshall(chunk_id_t * chunkId, void *src, gsize srcSize, GError ** err);

/**
 * Returns the unserialized form of the String sequence as a linked list
 * of GByteArrays
 *
 * @param encoded_form
 * @param err
 * @return
 */
GSList *meta2_maintenance_arrays_unmarshall_bytearray(
		GByteArray * encoded_form, GError ** err);

/**
 * Returns the unserialized form of the String sequence as a linked list
 * of GByteArrays
 *
 * @param buf
 * @param buf_len
 * @param err
 * @return
 */
GSList *meta2_maintenance_arrays_unmarshall_buffer(guint8 * buf, gsize buf_len, GError ** err);

/**
 * Returns the unserialized form of the String sequence as a linked list
 * of NULL-terminated character strings
 *
 * @param encoded_form
 * @param err
 * @return
 */
GSList *meta2_maintenance_names_unmarshall_bytearray(GByteArray * encoded_form, GError ** err);

/**
 * Returns the unserialized form of the String sequence as a linked list
 * of NULL-terminated character strings
 *
 * @param buf
 * @param buf_len
 * @param err
 */
GSList *meta2_maintenance_names_unmarshall_buffer(const guint8 * buf, gsize buf_len, GError ** err);

/**
 * @param names
 * @param err
 * @return
 */
GByteArray *meta2_maintenance_names_marshall(GSList * names, GError ** err);

/**
 * @param arrays
 * @param err
 * @return
 */
GByteArray *meta2_maintenance_arrays_marshall(GSList * arrays, GError ** err);

/**
 * @param buf
 * @param buf_len
 * @param array_size
 * @param err
 * @return
 */
GSList *meta2_maintenance_sized_arrays_unmarshall_buffer(guint8 * buf, gsize buf_len, gsize array_size,
		GError ** err);

/**
 * @param encoded
 * @param array_size
 * @param err
 * @return
 */
GSList *meta2_maintenance_sized_arrays_unmarshall_bytearray(GByteArray * encoded, gsize array_size, GError ** err);

/**
 * Serializes a list of arrays of fixed sized (given as the second argument)
 * @param arrays
 * @param array_size
 * @param err
 * @return
 */
GByteArray *meta2_maintenance_sized_arrays_marshall(GSList * arrays, gsize array_size, GError ** err);


/**
 * Serialize a namespace_info to ASN1
 *
 * @param namespace_info the namespace_info_t to serialize
 * @param err
 * @return the serialized ASN1 data in a GByteArray
 */
GByteArray* namespace_info_marshall(struct namespace_info_s * namespace_info, const char *version, GError ** err);

/**
 * Unserialize a namespace_info from ASN1
 *
 * @param buf the ASN1 serialized data
 * @param buf_len the size of the ASN1 data
 * @param err
 * @return the namespace_info_t struct
 */
namespace_info_t* namespace_info_unmarshall(const guint8 * buf, gsize buf_len, GError ** err);

/** @} */

#endif /*__METACOMM__H__*/
