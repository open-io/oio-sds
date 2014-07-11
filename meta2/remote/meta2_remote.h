/**
 * @file meta2_remote.h
 * META2 remote
 */
#ifndef __META2_REMOTE_H__
#define __META2_REMOTE_H__

/**
 * @defgroup meta2_remote Remote
 * @ingroup meta2
 * @{
 */

#include <metautils/lib/metatypes.h>
#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <glib.h>

/*
 * ---------------------------
 *   Raw requests management
 * ---------------------------
 */

#define NAME_MSGNAME_M2_INFO "REQ_M2_INFO"
#define NAME_MSGNAME_M2_CREATE  "REQ_M2_CREATE"
#define NAME_MSGNAME_M2_DESTROY "REQ_M2_DESTROY"
#define NAME_MSGNAME_M2_OPEN    "REQ_M2_OPEN"
#define NAME_MSGNAME_M2_CLOSE   "REQ_M2_CLOSE"
#define NAME_MSGNAME_M2_LIST    "REQ_M2_LIST"
#define NAME_MSGNAME_M2_GETFLAG "REQ_M2_GETFLAG"
#define NAME_MSGNAME_M2_SETFLAG "REQ_M2_SETFLAG"
#define NAME_MSGNAME_M2_CONTENTSPARE    "REQ_M2_CONTENTSPARE"
#define NAME_MSGNAME_M2_CONTENTADD      "REQ_M2_CONTENTADD"
#define NAME_MSGNAME_M2_CONTENTREMOVE   "REQ_M2_CONTENTREMOVE"
#define NAME_MSGNAME_M2_CONTENTRETRIEVE "REQ_M2_CONTENTRETRIEVE"
#define NAME_MSGNAME_M2_CONTENTCOMMIT   "REQ_M2_CONTENTCOMMIT"
#define NAME_MSGNAME_M2_CONTENTROLLBACK "REQ_M2_CONTENTROLLBACK"
#define NAME_MSGNAME_M2_CONTENTAPPEND   "REQ_M2_CONTENTAPPEND"

#define NAME_MSGNAME_M2_CHUNK_COMMIT   "REQ_M2_CHUNK_COMMIT"

#define REMOTECONTAINER_FLAG_OK       0x00000000
#define REMOTECONTAINER_FLAG_FROZEN   0x00000001
#define REMOTECONTAINER_FLAG_DISABLED 0x00000002

#define META2TOUCH_FLAGS_UPDATECSIZE     0x00000001
#define META2TOUCH_FLAGS_RECALCCSIZE     0x00000002

#define NAME_MSGNAME_M2RAW_GETCONTENTS "REQ_M2RAW_CONTENT_GETALL"
#define NAME_MSGNAME_M2RAW_GETCONTENTBYPATH  "REQ_M2RAW_CONTENT_GETBYPATH"
#define NAME_MSGNAME_M2RAW_GETCONTENTBYCHUNK "REQ_M2RAW_CONTENT_GETBYCHUNK"
#define NAME_MSGNAME_M2RAW_SETCONTENT  "REQ_M2RAW_CONTENT_SET"
#define NAME_MSGNAME_M2RAW_DELCONTENT  "REQ_M2RAW_CONTENT_DEL"
#define NAME_MSGNAME_M2RAW_GETCHUNKS   "REQ_M2RAW_CHUNKS_GET"
#define NAME_MSGNAME_M2RAW_SETCHUNKS   "REQ_M2RAW_CHUNKS_SET"
#define NAME_MSGNAME_M2RAW_DELCHUNKS   "REQ_M2RAW_CHUNKS_DEL"
#define NAME_MSGNAME_M2RAW_MARK_REPAIRED  "REQ_M2RAW_MARK_REPAIRED"

#define NAME_MSGNAME_M2ADMIN_GETALL "REQ_M2RAW_ADMIN_GETALL"
#define NAME_MSGNAME_M2ADMIN_SETONE "REQ_M2RAW_ADMIN_SETONE"

#define NAME_HEADER_METADATA_USR "METADATA_USR"
#define NAME_HEADER_METADATA_SYS "METADATA_SYS"
#define NAME_HEADER_NAMESPACE "NS"
#define NAME_HEADER_CONFIGURATION "CFG"
#define NAME_HEADER_CONTAINERNAME "CONTAINER_NAME"
#define NAME_HEADER_VIRTUALNAMESPACE "VIRTUAL_NAMESPACE"
#define NAME_HEADER_ADMIN_KEY "ADMIN_KEY"
#define NAME_HEADER_ADMIN_VALUE "ADMIN_VALUE"
#define NAME_HEADER_ADMIN_VALUE_SIZE "ADMIN_VALUE_SIZE"
#define NAME_HEADER_CHECKFLAGS "CHECK_FLAGS"
#define NAME_HEADER_STORAGEPOLICY "STORAGE_POLICY"
#define NAME_HEADER_VERSIONPOLICY "VERSION_POLICY"

/**
  *	Get infos about this meta2
  *
  *	@deprecated
  *	@param ctx
  *	@param err     a pointer to an error structure set in case of function failure
  *	@return NULL in case of error, or a valid hashtable in case of success. It maps
  *             NULL-temrinated character arrays (i.e. strings) to other strings. Some
  *             well known keys wil be present: NAME_HEADER_NAMESPACE (the namespace),
  *		NAME_HEADER_CONFIGURATION (the configuration string of the server).
 */
GHashTable *meta2_remote_info(struct metacnx_ctx_s *ctx, GError ** err);

/**
 * @see meta2_remote_info()
 * @param fd
 * @param ms
 * @param err
 * @return
 */
GHashTable *meta2_remote_info_with_fd(int fd, gint ms, GError ** err);

/**
 * @see meta2_remote_info()
 * @param m2_addr
 * @param ms
 * @param err
 * @return
 */
GHashTable *meta2_remote_info_with_addr(addr_info_t * m2_addr, gint ms, GError ** err);

/**
 * @param ctx
 * @param err
 * @param container_id
 * @param content_path
 * @param content_length
 * @return
 */
GSList *meta2_remote_content_append(struct metacnx_ctx_s *ctx, GError ** err,
    const container_id_t container_id, const gchar * content_path, content_length_t content_length);

/**
 * @param ctx
 * @param err
 * @param virtual_namespace
 * @param container_id
 * @param content_path
 * @param content_length
 * @return
 */
GSList *meta2_remote_content_append_v2(struct metacnx_ctx_s *ctx, GError ** err,
    gchar *virtual_namespace, const container_id_t container_id, const gchar * content_path, content_length_t content_length);


/**
 * Change the flags on a distant container identified by its ID
 *
 * @param m2_addr the address of the meta2 server managing our container
 * @param ms      the maximum number of milliseconds spent in network latencies
 * @param err     a pointer to an error structure set in case of function failure
 * @param container_id     the binary identifier of the container
 * @param flag    the new flag to be set
 *
 * @return TRUE if the function succeeds (the distant flag is now set), FALSE elsewhere and err is set
 */
gboolean meta2_remote_container_set_flag(addr_info_t * m2_addr, gint ms, GError ** err, const container_id_t container_id,
    guint32 flag);


/**
 * Get the flags on a distant container identified by its ID
 *
 * @param m2_addr the address of the meta2 server managing our container
 * @param ms the maximum number of milliseconds spent in network latencies
 * @param err a pointer to an error structure set in case of function failure
 * @param container_id the binary identifier of the container
 * @param flag a pointer to an integer. At exit, if the function succeeds, its
 *             value is the flag set on the container.
 *
 * @return TRUE if the function succeeds (flag succesfully retrieved), FALSE
 *         elsewhere and err is set
 */
gboolean meta2_remote_container_get_flag(addr_info_t * m2_addr, gint ms, GError ** err, const container_id_t container_id,
    guint32 * flag);


/**
 * Get the list of contents of ths container.
 *
 * An empty list (represented by a NULL pointer returned) is not an error.
 * The error is the combinatino of a NULL return AND the err pointer
 * set. BE CAREFUL : if the err parameter is NULL or was already filled
 * before the call of the function, it won't be possible to detect an error.
 *
 * @param m2_addr the address of the meta2 server managing our container
 * @param ms the maximum number of milliseconds spent in network latencies
 * @param err a pointer to an error structure set in case of function failure
 * @param container_id the binary identifier of the container
 *
 * @return a --maybe empty-- list of path_info_t* structures.
 */
GSList *meta2_remote_container_list(addr_info_t * m2_addr, gint ms, GError ** err, const container_id_t container_id);


/**
 * Creates a container on the distant META2 server.
 *
 * @param m2_addr the address of the meta2 server managing our container
 * @param ms the maximum number of milliseconds spent in network latencies
 * @param err a pointer to an error structure set in case of function failure
 * @param container_id the binary identifier of the container
 * @param name
 * @return TRUE if the container was created, FALSE elsewhere and err is set
 */
gboolean meta2_remote_container_create(addr_info_t * m2_addr, gint ms, GError ** err, const container_id_t container_id,
    const gchar * name);


/**
 * @param m2_addr
 * @param ms
 * @param err
 * @param container_id
 * @param name
 * @param virtual_namespace
 * @return
 */
gboolean meta2_remote_container_create_v2(addr_info_t * m2_addr, gint ms, GError ** err, const container_id_t container_id,
    const gchar * name, const gchar * virtual_namespace);


/**
 * @param m2
 * @param ms
 * @param ns
 * @param cname
 * @param cid
 * @param stgpol
 * @param e
 * @return
 */
gboolean meta2_remote_container_create_v3 (const addr_info_t *m2, gint ms, const char *ns, const char *cname,
                const container_id_t cid, const char *stgpol, GError **e);

/**
 * Destroys the container with the given ID on the remote container
 *
 * @param m2_addr the address of the meta2 server managing our container
 * @param ms the maximum number of milliseconds spent in network latencies
 * @param err a pointer to an error structure set in case of function failure
 * @param container_id the binary identifier of the container
 *
 * @return TRUE if the container was created, FALSE elsewhere and err is set
 */
gboolean meta2_remote_container_destroy(addr_info_t * m2_addr, gint ms, GError ** err, const container_id_t container_id);


/**
 * Open the container on the distant META2 server.
 *
 * @param m2_addr the address of the meta2 server managing our container
 * @param ms the maximum number of milliseconds spent in network latencies
 * @param err a pointer to an error structure set in case of function failure
 * @param container_id the binary identifier of the container
 *
 * @return
 */
gboolean meta2_remote_container_open(addr_info_t * m2_addr, gint ms, GError ** err, const container_id_t container_id);


/**
 * Closes the container on the distant META2 server
 *
 * @param m2_addr the address of the meta2 server managing our container
 * @param ms the maximum number of milliseconds spent in network latencies
 * @param err a pointer to an error structure set in case of function failure
 * @param container_id the binary identifier of the container
 *
 * @return
 */
gboolean meta2_remote_container_close(addr_info_t * m2_addr, gint ms, GError ** err, const container_id_t container_id);


/**
 * Add a new content in the container (identified by the container ID) on the
 * distant META2 server.
 *
 * A NULL return well indicates an error, because even the empty contents
 * contains at least one chunk whom size is zero.
 *
 * @param m2_addr the address of the meta2 server managing our container
 * @param ms the maximum number of milliseconds spent in network latencies
 * @param err a pointer to an error structure set in case of function failure
 * @param container_id the binary identifier of the container
 * @param content_path a not NULL pointer to a NULL terminated byte array
 * @param content_length the positive length of the content_path pointed array
 * @param system_metadata
 * @param new_system_metadata
 * @return NULL in case of error (and then err is set) or a list of chunk_info_t*
 */
GSList *meta2_remote_content_add(addr_info_t * m2_addr, gint ms, GError ** err,
    const container_id_t container_id, const gchar * content_path, content_length_t content_length,
    GByteArray * system_metadata, GByteArray ** new_system_metadata);

/**
 * Add new spare chunks to the remote content chunk's list, and returns their
 * address
 *
 * A NULL return well indicates an error
 *
 * @param m2_addr the address of the meta2 server managing our container
 * @param ms the maximum number of milliseconds spent in network latencies
 * @param err a pointer to an error structure set in case of function failure
 * @param container_id the binary identifier of the container
 * @param content_path a not NULL pointer to a NULL terminated byte array
 *
 * @return NULL in case of error (and then err is set) or a list of chunk_info_t*
 */
GSList *meta2_remote_content_spare(addr_info_t * m2_addr, gint ms, GError ** err, const container_id_t container_id,
    const gchar * content_path);


/**
 * Mark for removal the give content from the given container, on the
 * targeted META2 server.
 *
 * Currently, there is no management of META2 replications in the removal
 * operations. After this step a COMMIT or a ROLLBACK on the content is
 * necessary. Before this step, the content won't be accessible.
 *
 * @param m2_addr the address of the meta2 server managing our container
 * @param ms the maximum number of milliseconds spent in network latencies
 * @param err a pointer to an error structure set in case of function failure
 * @param container_id the binary identifier of the container
 * @param content_path a not NULL pointer to a NULL-terminated character array
 * @return TRUE if the content could be marked for removal
 */
gboolean meta2_remote_content_remove(addr_info_t * m2_addr, gint ms, GError ** err, const container_id_t container_id,
    const gchar * content_path);


/**
 * Commit (approve) the last operation on the given content in the given container.
 *
 * @param m2_addr the address of the meta2 server managing our container
 * @param ms the maximum number of milliseconds spent in network latencies
 * @param err a pointer to an error structure set in case of function failure
 * @param container_id the binary identifier of the container
 * @param content_path
 * @return
 */
gboolean meta2_remote_content_commit(addr_info_t * m2_addr, gint ms, GError ** err, const container_id_t container_id,
    const gchar * content_path);


/**
 * Rollback on the last operation performed on the given content in the
 * given container.
 *
 * @param m2_addr the address of the meta2 server managing our container
 * @param ms the maximum number of milliseconds spent in network latencies
 * @param err a pointer to an error structure set in case of function failure
 * @param container_id the binary identifier of the container
 * @param content_path
 * @return
 */
gboolean meta2_remote_content_rollback(addr_info_t * m2_addr, gint ms, GError ** err, const container_id_t container_id,
    const gchar * content_path);

/**
 * Get the chunks locations of the given content in the givan container.
 *
 * To be successful, the retrieval must target an opened container and
 * an online content.
 *
 * @param m2_addr the address of the meta2 server managing our container
 * @param ms the maximum number of milliseconds spent in network latencies
 * @param err a pointer to an error structure set in case of function failure
 * @param container_id the binary identifier of the container
 * @param content_path
 * @return NULL in case of error (and err is set), or a list of chunk_info_t*
 */
GSList *meta2_remote_content_retrieve(addr_info_t * m2_addr, gint ms, GError ** err, const container_id_t container_id,
    const gchar * content_path);


/**
 * Commit the state of the provided chunks, belonging to the given content
 * in the given container.
 *
 * @param m2_addr the address of the meta2 server managing our container
 * @param ms the maximum number of milliseconds spent in network latencies
 * @param err a pointer to an error structure set in case of function failure
 * @param container_id the binary identifier of the container
 * @param content_path
 * @param chunks
 * @return TRUE if all the changes succeeded, FALSE elsewhere (and err is set).
 */
gboolean meta2_remote_chunk_commit(addr_info_t * m2_addr, gint ms, GError ** err, const container_id_t container_id,
    const gchar * content_path, GSList * chunks);

/**
 * Returns all the information about the content with the given path in the
 * given container. This content must be available.
 *
 * The returned structure is the same as those returned by meta2raw_remote_get_chunks()
 * on an available content.
 *
 * @param cnx
 * @param cid
 * @param path
 * @param path_len
 * @param error
 * @return NULL if the request failed (see the error structure) or a pointer to
 *         a well initiated struct meta2_raw_content_s.
 */
struct meta2_raw_content_s *meta2_remote_stat_content(struct metacnx_ctx_s *cnx,
	const container_id_t cid, const gchar *path, gsize path_len, GError **error);

/* ------------------------------------------------------------------------- */


/**
 * @see meta2_remote_container_list()
 * @param fd an opened and  connected socket to the META2 server
 * @param ms
 * @param err
 * @param container_id
 * @return
 */
GSList *meta2_remote_container_list_in_fd(int *fd, gint ms, GError ** err, const container_id_t container_id);

/**
 * @see meta2_remote_container_create()
 * @param fd an opened and  connected socket to the META2 server
 * @param ms
 * @param err
 * @param container_id
 * @param name
 * @return
 */
gboolean meta2_remote_container_create_in_fd(int *fd, gint ms, GError ** err, const container_id_t container_id,
    const gchar * name);


/**
 * @see meta2_remote_container_destroy()
 * @param fd an opened and  connected socket to the META2 server
 * @param ms
 * @param err
 * @param container_id
 * @return
 */
gboolean meta2_remote_container_destroy_in_fd(int *fd, gint ms, GError ** err, const container_id_t container_id);


/**
 * @see meta2_remote_container_open()
 * @param fd an opened and  connected socket to the META2 server
 * @param ms
 * @param err
 * @param container_id
 * @return
 */
gboolean meta2_remote_container_open_in_fd(int *fd, gint ms, GError ** err, const container_id_t container_id);


/**
 * @see meta2_remote_container_close()
 * @param fd an opened and  connected socket to the META2 server
 * @param ms
 * @param err
 * @param container_id
 * @return
 */
gboolean meta2_remote_container_close_in_fd(int *fd, gint ms, GError ** err, const container_id_t container_id);


/**
 * @see meta2_remote_content_add()
 * @param fd an opened and  connected socket to the META2 server
 * @param ms
 * @param err
 * @param container_id
 * @param content_path
 * @param content_length
 * @param system_metadata
 * @param new_system_metadata
 * @return
 */
GSList *meta2_remote_content_add_in_fd(int *fd, gint ms, GError ** err,
    const container_id_t container_id, const gchar * content_path, content_length_t content_length,
    GByteArray * system_metadata, GByteArray ** new_system_metadata);

/**
 * @see meta2_remote_content_add()
 * @param fd an opened and  connected socket to the META2 server
 */
GSList *meta2_remote_content_add_in_fd_v2(int *fd, gint ms, GError ** err,
    const container_id_t container_id, const gchar * content_path, content_length_t content_length,
    GByteArray *user_metadata, GByteArray * system_metadata, GByteArray ** new_system_metadata);


/**
 * @see meta2_remote_content_add()
 * @param fd an opened and  connected socket to the META2 server
 * @param ms
 * @param err
 * @param container_id
 * @param content_path
 * @return
 */
GSList *meta2_remote_content_spare_in_fd(int *fd, gint ms, GError ** err, const container_id_t container_id,
    const gchar * content_path);

/**
 *
 * @param fd
 * @param ms
 * @param err
 * @param container_id
 * @param content_path
 * @param count
 * @param distance
 * @param notin
 * @param broken
 * @return
 */
GSList* meta2_remote_content_spare_in_fd_full (int *fd, gint ms, GError **err, const container_id_t container_id,
		const gchar *content_path, gint count, gint distance, const gchar *notin, const gchar *broken);

/**
 * @see meta2_remote_content_remove()
 * @param fd an opened and  connected socket to the META2 server
 * @param ms
 * @param err
 * @param container_id
 * @param content_path
 * @return
 */
gboolean meta2_remote_content_remove_in_fd(int *fd, gint ms, GError ** err, const container_id_t container_id,
    const gchar * content_path);


/**
 * @see meta2_remote_content_commit()
 * @param fd an opened and  connected socket to the META2 server
 * @param ms
 * @param err
 * @param container_id
 * @param content_path
 * @return
 */
gboolean meta2_remote_content_commit_in_fd(int *fd, gint ms, GError ** err, const container_id_t container_id,
    const gchar * content_path);


/**
 * @see meta2_remote_content_rollback()
 * @param fd an opened and  connected socket to the META2 server
 * @param ms
 * @param err
 * @param container_id
 * @param content_path
 * @return
 */
gboolean meta2_remote_content_rollback_in_fd(int *fd, gint ms, GError ** err, const container_id_t container_id,
    const gchar * content_path);


/**
 * @param fd an opened and  connected socket to the META2 server
 * @param ms
 * @param err
 * @param container_id
 * @param content_path
 * @return
 */
GSList *meta2_remote_content_retrieve_in_fd(int *fd, gint ms, GError ** err, const container_id_t container_id,
    const gchar * content_path);


/**
 * @see meta2_remote_chunk_commit()
 * @param fd an opened and  connected socket to the META2 server
 * @param ms
 * @param err
 * @param container_id
 * @param content_path
 * @param chunks
 * @return
 */
gboolean meta2_remote_chunk_commit_in_fd(int *fd, gint ms, GError ** err, const container_id_t container_id,
    const gchar * content_path, GSList * chunks);


/**
 * @param fd
 * @param ms
 * @param err
 * @param container_id
 * @param content_path
 * @param content_length
 * @return
 */
GSList *meta2_remote_content_append_in_fd(int *fd, gint ms, GError ** err, const container_id_t container_id,
    const gchar * content_path, content_length_t content_length);

/**
 * @param fd
 * @param ms
 * @param err
 * @param container_id
 * @param content_path
 * @param content_length
 * @return
 */
GSList *meta2_remote_content_append_in_fd_v2(int *fd, gint ms, GError ** err, const container_id_t container_id,
    const gchar * content_path, content_length_t content_length, GByteArray **sys_metadata);

/**
 * @param fd
 * @param ms
 * @param err
 * @param container_id
 * @return
 */
gboolean meta2raw_remote_mark_container_repaired_in_fd(int *fd, gint ms, GError ** err, const container_id_t container_id);


/**
 * @param ai
 * @param ms
 * @param err
 * @param container_id
 * @return
 */
gboolean meta2raw_remote_mark_container_repaired(addr_info_t * ai, gint ms, GError ** err, const container_id_t container_id);


/* ------------------------------------------------------------------------- */

/**
 *
 * @param ctx
 * @param err
 * @param content
 * @param allow_update
 * @return
 */
gboolean meta2raw_remote_update_chunks(struct metacnx_ctx_s *ctx, GError ** err,
    struct meta2_raw_content_s *content, gboolean allow_update, char *position_prefix);


/**
 *
 * @param ctx
 * @param err
 * @param content
 * @param allow_update
 * @return
 */
gboolean meta2raw_remote_update_content(struct metacnx_ctx_s *ctx, GError ** err,
    struct meta2_raw_content_s *content, gboolean allow_update);


/** 
 *
 * @param ctx
 * @param err
 * @param content
 * @return
 */
gboolean meta2raw_remote_delete_chunks(struct metacnx_ctx_s *ctx, GError ** err, struct meta2_raw_content_s *content);


/**
 * @param ctx
 * @param err
 * @param container_id
 * @param path
 * @param path_len
 * @return
 */
gboolean meta2raw_remote_delete_content(struct metacnx_ctx_s *ctx, GError ** err,
    const container_id_t container_id, const gchar * path, gsize path_len);


/**
 * @param ctx
 * @param err
 * @param container_id
 * @param path
 * @param path_len
 * @return
 */
struct meta2_raw_content_s *meta2raw_remote_get_content_from_name(struct metacnx_ctx_s *ctx, GError ** err,
    const container_id_t container_id, const gchar * path, gsize path_len);


/**
 * @param ctx
 * @param err
 * @param container_id
 * @param id
 * @return
 */
struct meta2_raw_content_s *meta2raw_remote_get_content_from_chunkid(struct metacnx_ctx_s *ctx, GError ** err,
    const container_id_t container_id, const chunk_id_t * id);


/**
 * Get the contents elements including its chunks, nevermind its availability.
 *
 * @param ctx
 * @param err
 * @param container_id
 * @param path
 * @param path_len
 * @return
 */
struct meta2_raw_content_s *meta2raw_remote_get_chunks(struct metacnx_ctx_s *ctx, GError ** err,
    const container_id_t container_id, const char *path, gsize path_len);


/**
 * Returns a list of contents names known in the given container,  nevermind
 * their availability.
 *
 * @param ctx
 * @param error
 * @param container_id
 * @return a (GSList*) of (gchar*) to be freed with g_free, g_slist_foreach, g_slist_free...
 */
GSList *meta2raw_remote_get_contents_names(struct metacnx_ctx_s *ctx, GError ** error,
    const container_id_t container_id);


/**
 * Returns a GHashTable* mapping (gchar*) to (gchar*)
 * 
 * @param ctx
 * @param error
 * @param container_id
 * @return
 */
GHashTable *meta2raw_remote_get_admin_entries(struct metacnx_ctx_s *ctx, GError ** error,
    const container_id_t container_id);


/**
 * Set a key/value pair in the admin table of the specified container
 *
 * @param ctx
 * @param error
 * @param container_id
 * @param key the key name
 * @param value a pointer to the value
 * @param value_size the size of value
 */
gboolean meta2raw_remote_set_admin_entry(struct metacnx_ctx_s *ctx, GError ** error,
    const container_id_t container_id, const gchar * key, void *value, gsize value_size);


/**
 * @param ctx
 * @param var_0
 * @param var_1
 * @param err
 * @return
 */
status_t meta2_remote_touch_content(struct metacnx_ctx_s *ctx,
		const container_id_t var_0, const gchar* var_1, GError **err);


/**
 * @param ctx
 * @param var_0
 * @param err
 * @return
 */
status_t meta2_remote_touch_container(struct metacnx_ctx_s *ctx, const container_id_t var_0, GError **err);

/**
 * @param ctx
 * @param var_0
 * @param err
 * @return
 */
status_t meta2_remote_touch_container_ex(struct metacnx_ctx_s *ctx, const container_id_t var_0, 
	unsigned int flags, GError **err);



/* ------------------------------------------------------------------------- */

/**
 */
struct meta2_dumpv1_hooks_remote_s
{
	/*!
	 * @brief Notify a raw content has been found
	 * @warning The hooks is reponsible for the 'p' liberation
	 * @param u the arbitrary context pointer
	 * @param p a valid pointer to an object found
	 * @return TRUE to continue the dump, FALSE to stop it
	 */
	gboolean (*on_content)  (gpointer u, meta2_raw_content_v2_t *p);

	/*!
	 * @brief Notify a KeyValue pair (admin table) has been found
	 * @warning The hooks is reponsible for the 'p' liberation
	 * @param u the arbitrary context pointer
	 * @param p a valid pointer to an object found
	 * @return TRUE to continue the dump, FALSE to stop it
	 */
	gboolean (*on_admin)    (gpointer u, key_value_pair_t *p);

	/*!
	 * @brief Notify a container property has been found
	 * @warning The hooks is reponsible for the 'p' liberation
	 * @param u the arbitrary context pointer
	 * @param p a valid pointer to an object found
	 * @return TRUE to continue the dump, FALSE to stop it
	 */
	gboolean (*on_property) (gpointer u, meta2_property_t *p);

	/*!
	 * @brief Notify a container_event has been found
	 * @warning The hooks is reponsible for the 'p' liberation
	 * @param u the arbitrary context pointer
	 * @param p a valid pointer to an object found
	 * @return TRUE to continue the dump, FALSE to stop it
	 */
	gboolean (*on_event)    (gpointer u, container_event_t *p);
};

/**
 * @param cnx
 * @param cid
 * @param hooks
 * @param u
 * @param err
 * @return
 */
status_t meta2_remote_dumpv1_container(struct metacnx_ctx_s *cnx, const container_id_t cid,
		struct meta2_dumpv1_hooks_remote_s *hooks, gpointer u,
		GError **err);

/* ------------------------------------------------------------------------- */

/**
 * @param dst_cnx
 * @param dst_cid
 * @param src_addr
 * @param src_cid
 * @param err
 * @return
 */
status_t meta2_remote_restorev1_container(
		struct metacnx_ctx_s *dst_cnx, const container_id_t dst_cid,
		const addr_info_t *src_addr, const container_id_t src_cid,
		GError **err);
		
/** @} */

#endif /*__META2_REMOTE_H__*/
