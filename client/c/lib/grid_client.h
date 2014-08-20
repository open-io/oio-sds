#ifndef __GRID_CLIENT_H__
#define __GRID_CLIENT_H__

/**
 * @defgroup client_public Public
 * @ingroup client
 * @{
 */

#include <stdint.h>

#include <sys/types.h>
#include <netdb.h>

#define GS_OK    ((gs_status_t)1)
#define GS_ERROR ((gs_status_t)0)

#define GS_ENVKEY_METACDSOCK "GS_METACD_SOCKET"
#define GS_DEFAULT_METACDSOCK "/GRID/common/run/metacd.sock"

#define GS_ENVKEY_MAXSPARE "GS_MAX_SPARE"
#define GS_DEFAULT_MAXSPARE "5"

#define GS_SNAPSHOT_MAXLENGTH 256

/**
 * The hidden type that represents the connection to a Grid Storage platform
 */
typedef struct gs_grid_storage_s gs_grid_storage_t;


/**
 * The public information about a remote container on a grid storage
 * platform.
 */
typedef struct {
	gs_grid_storage_t *gs; /**< the grid storage platform the current container
	                            belongs to */
	char               name [1024]; /**< the name of this container ( a NULL
	                                     terminated character array that should
					     only contain ASCII characters (altough
					     this is not mandatory). */
} gs_container_info_t ;


/**
 * The hidden remote container type.
 * This structure starts with a gs_container_info_t member, thus a pointer to
 * a container might be cast into a gs_container_t to access its fields.
 */
typedef struct gs_container_s gs_container_t;


/**
 * The public information about
 */
typedef struct {
	gs_container_t *container; /**< the remote container the content belongs to*/
	char            path[1024]; /**< the path of the content in this container */
	int64_t         size;
} gs_content_info_t;


/**
 * A hidden type holding the complete information about a remote content.
 * This structure starts with a gs_content_info_t member. Thus a pointer
 * to a gs_content_t might be cast into a pointer to a gs_content_info_t
 */
typedef struct gs_content_s gs_content_t;

/**
 * A simple type for functions returning simple return codes.
 */
typedef int gs_status_t;


/**
 * A structure set by functions in case of failure, with the reason of the
 * failure.
 */
typedef struct {
	int code; /**<  */
	char *msg; /**<  */
} gs_error_t;


#define GS_CODE_ERROR                 1
#define GS_CODE_CONTAINER_ERROR       2
#define GS_CODE_CONTAINER_UNAVAILABLE 3
#define GS_CODE_CONTAINER_CLOSED      4
#define GS_CODE_CONTAINER_NOTFOUND    5
#define GS_CODE_CONTENT_NOTFOUND      6
#define GS_CODE_CONTENT_ERROR         7

#define GS_CONTAINER_PROPERTY_STORAGE_POLICY "sys.storage_policy"
#define GS_CONTAINER_PROPERTY_VERSIONING     "sys.versioning_policy"
#define GS_CONTAINER_PROPERTY_QUOTA    "sys.quota"
#define GS_CONTAINER_PROPERTY_SIZE     "sys.container_size"

/**
 * frees the given gs_container_t structure and all the associated internal
 * data
 *
 * @param container the container to be destroyed
 */
void gs_container_free (gs_container_t *container);


/**
 * frees the given gs_content_t structure and all the associated internal
 * data
 *
 * @param content a pointer to th structure to be destroyed. 
 */
void gs_content_free (gs_content_t *content);


/**
 * Cleans the gs_grid_storage_t structure and all the associated internal
 * data.
 *
 * @param gs a pointer to a gs_grid_storage_t, initiated by a
 *           call to gs_init_grid_storage().
 */
void gs_grid_storage_free (gs_grid_storage_t *gs);


/**
 * Collects basic informations about the remote container
 *
 * @param container
 * @param info
 * @param err
 * @return
 */
gs_status_t gs_container_get_info (const gs_container_t *container,
	gs_container_info_t *info, gs_error_t **err);


/**
 * Collects basic information about the given remote content.
 *
 * Some of this information are returned directly in the pointed
 * info parameter. The other information is available through 
 * calls to other functions as gs_content_get_metadata() or
 * gs_content_get_system_metadata().
 *
 * @param content a pointer to a valid remote content
 * @param info a pointer to a valid structure that will be filled
 * @param err a double pointer to an error structure, that will be set
 *            if the function fails.
 * @return 1 in case of success, 0 in case of failure
 */
gs_status_t gs_content_get_info (const gs_content_t *content,
	gs_content_info_t *info, gs_error_t **err);

/**
 * Fills the pointed buffer with the metadata available for this content.
 * The pointed size argument is updated with the number of bytes really
 * written in the given buffer.
 *
 * Such metadata are not loaded systematically when the content is returned
 * from the container. But since this function needs fresh information about
 * the content and might trigger a (network) call to the distant meta2
 * if the targeted info is unavailable.
 */
gs_status_t gs_content_get_metadata(gs_content_t *content, uint8_t *dst, size_t *dst_size, gs_error_t **err);

/**
 * @see gs_content_get_metadata()
 */
gs_status_t gs_content_get_system_metadata(gs_content_t *content, uint8_t *dst, size_t *dst_size, gs_error_t **err);

/**
 * Change the metadata associated to the current content in the distant
 * container.
 */
gs_status_t gs_content_set_metadata(gs_content_t *content, uint8_t *src, size_t src_size, gs_error_t **err);

/**
 * A filter function type
 * @param content a valid pointer to the inspected remote content structure
 * @param user_data an arbitrary pointer previously fed to the list
 *                  function
 * @return three possible values:
 * - 1 if the function is successful and the content may be kept
 * - 0 if the function is successful and the content cannot be kept
 * - -1 if the iteration must be stopped
 */
typedef int (*gs_content_filter_f) (gs_content_t *content, void *user_data);


/**
 * Callback function destined to give data to the upload function of the API.
 *
 * @param buffer a pointer to a memory buffer where the next available data
 *               has to be stored
 * @param buffer_size the strictly positive size of the memory buffer.
 * @param user_data an arbitrary pointer previously fed to the upload function
 * @return several values are possible:
 * - the number of bytes available
 * - 0 if no more byte will be available (the end of content has been reached)
 * - -1 if an error occured and no more data are available.
 */
typedef ssize_t (*gs_input_f) (void *uData, char *b, size_t bSize);


/**
 * Callback type as provided to the download function. 
 *
 * The implementation is not forced to manage all the bytes. I.e. it is
 * not an error if the return value is positive but less than bSize.
 *
 * @param uData an arbitrary user data originally passed to the download function
 * @param b a pointer to the memory buffer holding the downloaded bytes
 * @param bSize the size of the buffer
 * @return the number of written bytes or a negative number of bytes on error.
 */
typedef ssize_t (*gs_output_f) (void *uData, const char *b, const size_t bSize);


/**
 * A handy structure holding useful information to download
 * the remote content
 */
typedef struct gs_download_info_s
{
	int64_t      offset; /**< the offset in the file at which the download
	                          must start */
	int64_t      size; /**< the number of bytes expected by the downloader */
	gs_output_f  writer; /**< a callback function used to transmit the
	                          downloaded bytes */
	void        *user_data; /**< an arbitrary pointer that will be fed to
								 the writer callback */
} gs_download_info_t ;


/* --- Grid Storage main operations ---------------------------------------- */


/**
 * Creates allocates a new gs_grid_storage_t structure and inits it to be 
 * ready to refresh on the given.
 *
 * The only information needed by a grid storage to start its work is
 * the location of a META0 refname directory.
 *
 * @param meta0_url the url of the META0 refname. It must have one of
 * the followinf formats:<ul>
 * <li>HOST:PORT where HOST is a resolvable fully qualified domain name</li>
 * <li>[IP]:PORT for IPv6 and IPv4 addresses</li>
 * <li>IP:PORT only for IPv4 addresses</li>
 * </ul>
 * @param err a double pointer to an error structure, that will be set
 *            if the function fails.
 * @return NULL if the function fails (if the META0 refname cannot be
 *              joigned) or a pointer to a valid gs_grid_storage_t structure.
 */
gs_grid_storage_t* gs_grid_storage_init (const char *meta0_url,
	gs_error_t **err);

gs_grid_storage_t* gs_grid_storage_init2 (const char *meta0_url,
	int to_cnx, int to_req, gs_error_t **err);

typedef enum gs_timeout_e {
	GS_TO_RAWX_CNX=0,
	GS_TO_RAWX_OP=1,
	GS_TO_M0_CNX=2,
	GS_TO_M0_OP=3,
	GS_TO_M1_CNX=4,
	GS_TO_M1_OP=5,
	GS_TO_M2_CNX=6,
	GS_TO_M2_OP=7,
	GS_TO_MCD_CNX=8,
	GS_TO_MCD_OP=9
} gs_timeout_t;


gs_status_t gs_grid_storage_set_timeout (gs_grid_storage_t *gs,
	gs_timeout_t to, int val, gs_error_t **err);


gs_status_t gs_grid_storage_get_timeout (gs_grid_storage_t *gs, gs_timeout_t to);

const char* gs_get_namespace(gs_grid_storage_t *gs);

/**
 * Get the "virtual" part of the namespace.
 */
const char* gs_get_virtual_namespace(gs_grid_storage_t *gs);

/**
 * Get the full virtual namespace name, including the physical namespace part.
 */
const char* gs_get_full_vns(gs_grid_storage_t *gs);

/* Allows to replace the configured NS by another virtual namespace in the
 * same physical namespace. */
int gs_set_namespace(gs_grid_storage_t *gs, const char *vns);

/* --- Container operations ------------------------------------------------ */


/**
 * Get a refname to a remote container.
 *
 * This resolves its location (i.e. where it should be located) but
 * it does not ensure the remote container exists (and, of course, it
 * it does not open the container).
 *
 * @param gs A pointer to the local configuration of the grid storage
 * @param container_name a pointer to a NULL terminated character array
 *                       containing the name of the container. In facts
 *                       the container's name must not only contain 
 *                       printable characters.
 * @param auto_create a boolean value telling if the container must be
 *                    created if it does not exists.
 * @param err a double pointer to an error structure, that will be set
 *            if the function fails.
 * @return NULL in case of failure, a non-NULL pointer to a valid
 *         gs_container_t if the function succeeds
 */
gs_container_t* gs_get_container (gs_grid_storage_t *gs,
	const char *container_name, int auto_create, gs_error_t **err);

/**
 * @param gs
 * @param hex_id
 * @param err
 * @return
 */
gs_container_t* gs_get_container_by_hexid (gs_grid_storage_t *gs,
	const char *hex_id, int auto_create, gs_error_t **err);


/**
 * Opens a remote container
 *
 * The container becomes useable of at least one call to
 * gs_open_container() has been made by one client.
 *
 * @param container a structure prepared by gs_get_container()
 * @param err a double pointer to an error structure that will be set
 *            if the function fails
 * @return 1 in case of success, 0 in case of failure
 */
gs_status_t gs_open_container (gs_container_t *container, gs_error_t **err);


/**
 * Closes a remote container
 *
 * The container is still useable if more subsequent calls to
 * gs_open_container() than to gs_close_container() have been
 * made.
 *
 * @param container a structure prepared by gs_get_container()
 * @param err a double pointer to an error structure that will be set
 *            if the function fails
 * @return 1 in case of success, 0 in case of failure
 */
gs_status_t gs_close_container (gs_container_t *container, gs_error_t **err);


/**
 * Checks the state of the container
 * @param container a not-NULL pointer to a valid container structure
 * @param err a double pointer to an error structure that will be set
 *            if the function fails
 * @return 0 if the container is closed, 1 if it is opened, -1 upon error
 */
int gs_container_is_open (gs_container_t *container, gs_error_t **err);


/**
 * Destroys the remote container.
 *
 * Pay attention to the given structure that remains useable, even if it
 * does not refer anymore to a real container. It should be freed with
 * gs_container_free().
 *
 * @param container a not-NULL pointer to a valid gs_container_t structure
 * @param err a double pointer to an error structure, that will be set
 *            if the function fails.
 * @return 1 if the destruction succeed, 0 in case of error (and the err
 *           parameter is set).
 */
gs_status_t gs_destroy_container (gs_container_t *container,
	gs_error_t **err);

/**
 * Same as gs_destroy_container but supports flags.
 *
 * @param container a not-NULL pointer to a valid gs_container_t structure
 * @param flags one of
 *   M2V2_DESTROY_FORCE: destroy container even if it still has contents
 *   M2V2_DESTROY_FLUSH: remove all contents before destroying container
 * @param err a double pointer to an error structure, that will be set
 *            if the function fails.
 * @return 1 if the destruction succeed, 0 in case of error (and the err
 *           parameter is set). */
gs_status_t gs_destroy_container_flags (gs_container_t *container,
	unsigned int flags, gs_error_t **err);

/**
 * Destroys all the online contents in the given remote container.
 */
gs_status_t gs_flush_container (gs_container_t *container, gs_error_t **err);


/* ------------------------------------------------------------------------- */


/**
 * List the content of the given remote container.
 *
 * If a content successfully passes the filter, it won't be freed!
 * In this case, is an error array pointer is provided, it will be
 * stored in the pointed array. But if no array if provided, it is
 * the responsibility of the user filter to free the content with
 * gs_content_free().
 * If the content doesn't pass the filter (return is less or equal
 * to 0), the content will be freed!
 * If no filter is given but an array pointer is, the content won't
 * be freed but will systematically be stored in the new array.
 * If no filter and no array pointer is provided, it is an error
 *
 * @param container a valid pointer to an opened remote container.
 * @param result if given, it will contain a NULL terminated array
 *               of pointers, filled with the contents that passed
 *               the filter (the filter returned TRUE).
 * @param filter a callback function applied to each remote content
 *               found in the remote container. No need to free the
 *               gs_content_t pointrer in the callback.
 * @param user_data an arbitrary pointer that will be fed to each call
 *                  to the callback function.
 * @param err a double pointer to an error structure, that will be set
 *            if the function fails.
 * @return 1 if the function succeeded, 0 in case of failure
 */
gs_status_t gs_list_container (gs_container_t *container, gs_content_t*** result,
	gs_content_filter_f filter, void *user_data, gs_error_t **err);

/**
 * Same as gs_list_container but takes a snapshot parameter.
 *
 * @param snapshot List only contents belonging to this snapshot
 */
gs_status_t gs_list_container_snapshot(gs_container_t *container,
		gs_content_t*** result, gs_content_filter_f filter, void *user_data,
		const char *snapshot, gs_error_t **err);

/**
 * Puts a new content in the given remote container
 *
 * The pointer to the newly uploaded content might be obtained with
 * gs_get_content_from_path()
 *
 * @param container the base remote container
 * @param name the name of the content in this container
 * @param size the exact size of the content
 * @param feeder a callback function used to get the next data chunk
 * @param user_data a pointer to an arbitrary data, will be fed to each
 *                  call to the feeder callback
 * @param err a double pointer to an error structure, that will be set
 *            if the function fails.
 * @return 1 if the function succeeded, 0 in case of failure
 */
gs_status_t gs_upload_content (gs_container_t *container,
	const char *name, const int64_t size,
	gs_input_f feeder, void *user_data, gs_error_t **err);

/**
 * Puts a new content in the given remote container
 *
 * The pointer to the newly uploaded content might be obtained with
 * gs_get_content_from_path()
 *
 * @param container the base remote container
 * @param content_name the name of the content in this container
 * @param content_size the exact size of the content
 * @param feeder a callback function used to get the next data chunk
 * @param user_data a pointer to an arbitrary data, will be fed to each
 *                  call to the feeder callback
 * @param user_metadata a pointer to a byte array, which contains the
 *		user_metadata to set to the content
 * @param sys_metadata a pointer to a byte array, which contains the
 *		system metadata to set to the content
 * @param err a double pointer to an error structure, that will be set
 *            if the function fails.
 * @return 1 if the function succeeded, 0 in case of failure
 */
gs_status_t gs_upload_content_v2 (gs_container_t *container,
		const char *content_name, const int64_t content_size,
		gs_input_f feeder, void *user_data, const char *user_metadata,
		const char *sys_metadata, gs_error_t **err);

/**
 * Puts a new content in the given remote container
 *
 * The pointer to the newly uploaded content might be obtained with
 * gs_get_content_from_path()
 *
 * @param container the base remote container
 * @param content_name the name of the content in this container
 * @param content_size the exact size of the content
 * @param feeder a callback function used to get the next data chunk
 * @param user_data a pointer to an arbitrary data, will be fed to each
 *                  call to the feeder callback
 * @param mdusr a pointer to a byte array, which contains the
 *		user_metadata to set to the content
 * @param mdsys a pointer to a byte array, which contains the
 *		system metadata to set to the content
 * @param stgpol storage policy name to apply to the uploaded content
 * @param err a double pointer to an error structure, that will be set
 *            if the function fails.
 * @return 1 if the function succeeded, 0 in case of failure
 */
gs_status_t gs_upload (gs_container_t *container, const char *content_name,
		const int64_t content_size, gs_input_f feeder, void *user_data,
		const char *mdusr, const char *mdsys, const char *stgpol,
		gs_error_t **err);

/**
 * Puts a new content in the given remote container
 *
 * The pointer to the newly uploaded content might be obtained with
 * gs_get_content_from_path()
 *
 * @param container the base remote container
 * @param content_name the name of the content in this container
 * @param content_size the exact size of the content
 * @param content_version the version of the content
 * @param feeder a callback function used to get the next data chunk
 * @param user_data a pointer to an arbitrary data, will be fed to each
 *                  call to the feeder callback
 * @param user_metadata a pointer to a byte array, which contains the
 *		user_metadata to set to the content
 * @param sys_metadata a pointer to a byte array, which contains the
 *		system metadata to set to the content
 * @param err a double pointer to an error structure, that will be set
 *            if the function fails.
 * @return 1 if the function succeeded, 0 in case of failure
 */
gs_status_t gs_upload_content_v2_with_version (gs_container_t *container,
		const char *content_name, const int64_t content_size, const char *content_version,
		gs_input_f feeder, void *user_data, const char *user_metadata,
		const char *sys_metadata, gs_error_t **err);

/**
 * Append data to an existing content in the given container
 * @param container
 * @param name
 * @param size
 * @param feeder
 * @param user_data
 * @param err
 * @return
 */
gs_status_t gs_append_content (gs_container_t *container,
	const char *name, const int64_t size,
	gs_input_f feeder, void *user_data, gs_error_t **err); 

/**
 * Get a portion of the remote content.
 *
 * @param container the remote container
 * @param name the name of the content in the distant container
 * @param dl_info a non-NULL pointer to the callback information
 * @param err a double pointer to an error structure, that will be set
 *            if the function fails.
 * @return 1 if the download succeeded, 0 in case of failure (err is set)
 */
gs_status_t gs_download_content_by_name(gs_container_t *container,
	const char *name, gs_download_info_t *dl_info, gs_error_t **err);

/**
 * Get a portion of the remote content with a specified version.
 *
 * @param container the remote container
 * @param name the name of the content in the distant container
 * @param version the version of the content
 * @param dl_info a non-NULL pointer to the callback information
 * @param err a double pointer to an error structure, that will be set
 *            if the function fails.
 * @return 1 if the download succeeded, 0 in case of failure (err is set)
 */
gs_status_t gs_download_content_by_name_and_version(gs_container_t *container,
	const char *name, const char *version, gs_download_info_t *dl_info, gs_error_t **err);

/**
 * Get a portion of the remote content with a specified version.
 *
 * @param container the remote container
 * @param name the name of the content in the distant container
 * @param version the version of the content
 * @param stgpol content storage policy
 * @param dl_info a non-NULL pointer to the callback information
 * @param err a double pointer to an error structure, that will be set
 *            if the function fails.
 * @return 1 if the download succeeded, 0 in case of failure (err is set)
 */
gs_status_t gs_download_content_by_name_full(gs_container_t *container,
	const char *name, const char *version, const char *stgpol, gs_download_info_t *dl_info, gs_error_t **err);

/**
 * Destroys the remote content
 *
 * Pay attention to the local structure that remains allocated and useable.
 *
 * @param container a handle to the remote container of the content to be destroyed.
 * @param name the name of the content in the distant container
 * @param err a double pointer to an error structure, that will be set
 *            if the function fails.
 * @return 1 in case of success, 0 in case of failure.
 */
gs_status_t gs_delete_content_by_name(gs_container_t *container,
	const char *name, gs_error_t **err);


/* --- Content operations -------------------------------------------------- */


/**
 * Looks up in the given remote container for a content with the given
 * name.
 *
 * If the content is found a new gs_content_t structure is initiated and
 * returned
 *
 * @param container a pointer to a rmeote container structure, returned
 *                  by a previous call to gs_get_container()
 * @param name a NULL terminated ASCII character string, the name of
 *             the targeted content
 * @param err a double pointer to an error structure, that will be set
 *            if the function fails.
 * @return NULL if the function fails, or a properly allocated remote
 *         content structure.
 */
gs_content_t* gs_get_content_from_path (gs_container_t *container,
	const char *name, gs_error_t **err);

/**
 * Looks up in the given remote container for a content with the given
 * name and version.
 *
 * If the content is found a new gs_content_t structure is initiated and
 * returned.
 *
 * @param container a pointer to a rmeote container structure, returned
 *                  by a previous call to gs_get_container()
 * @param name a NULL terminated ASCII character string, the name of
 *             the targeted content
 * @param version	a NULL terminated ASCII character string, the version of
 * 				the targeted content.
 * @param p_filtered a pointer to a GSList* that will hold filtered out beans
 * 				(eg parity chunks for RAIN). Can be NULL if not needed.
 * @param p_beans a pointer to a GSList* that will hold all beans.  Can be NULL if not needed.
 * @param err a double pointer to an error structure, that will be set
 *            if the function fails.
 * @return NULL if the function fails, or a properly allocated remote
 *         content structure.
 */
gs_content_t* gs_get_content_from_path_full (gs_container_t *container,
		const char *name, const char *version, void *p_filtered, void *p_beans, gs_error_t **err);

/**
 * Looks up in the given remote container for a content with the given
 * name and version.
 *
 * If the content is found a new gs_content_t structure is initiated and
 * returned.
 *
 * @param container a pointer to a rmeote container structure, returned
 *                  by a previous call to gs_get_container()
 * @param name a NULL terminated ASCII character string, the name of
 *             the targeted content
 * @param version	a NULL terminated ASCII character string, the version of
 * 				the targeted content.
 * @param err a double pointer to an error structure, that will be set
 *            if the function fails.
 * @return NULL if the function fails, or a properly allocated remote
 *         content structure.
 */
gs_content_t* gs_get_content_from_path_and_version (gs_container_t *container,
		const char *name, const char *version, gs_error_t **err);

/**
 * Get a portion of the remote content.
 *
 * @param content the remote content to be downloaded
 * @param dl_info
 * @param stgpol storage policy
 * @param filtered a list of filtered out beans
 * @param beans the list of all beans
 * @param err a double pointer to an error structure, that will be set
 *            if the function fails.
 * @return 1 if the download succeeded, 0 in case of failure (err is set)
 */
gs_status_t gs_download_content_full (gs_content_t *content,
		gs_download_info_t *dl_info, const char *stgpol, void *filtered, void *beans, gs_error_t **err);

/**
 * Get a portion of the remote content.
 *
 * @param content the remote content to be downloaded
 * @param dl_info
 * @param stgpol storage policy
 * @param err a double pointer to an error structure, that will be set
 *            if the function fails.
 * @return 1 if the download succeeded, 0 in case of failure (err is set)
 */
gs_status_t gs_download_content (gs_content_t *content,
		gs_download_info_t *dl_info, gs_error_t **err);

/**
 * Destroys the remote content
 *
 * Pay attention to the local structure that remains allocated and useable.
 *
 * @param content to remote content to be destroyed.
 *
 * @param err a double pointer to an error structure, that will be set
 *            if the function fails.
 * @return 1 in case of success, 0 in case of failure.
 */
gs_status_t gs_destroy_content (gs_content_t *content, gs_error_t **err);

int64_t gs_content_get_size(gs_content_t *content);

/**
 * Destroys the given error structure.
 * The given pointer may be NULL.
 */
void gs_error_free (gs_error_t *err);


/**
 * Returns a pointer to the internal message of the error structure.
 * This function always return a message even if the error structure
 * is not set or has no message. Do not free it.
 *
 * @param err a possibily NULL pointer to an error structure.
 * @return a never-NULL pointer to a valid printable string that cannot be
 * directly freed.
 */
const char* gs_error_get_message (gs_error_t *err);

/**
 * Returns the integer error code stored in the error structure.
 *
 * @param err a possibly NULL pointer to an error structure.
 *
 * @returns >=0 if a valid error code has been found, -1 if the error
 *          structure is not set.
 */
int gs_error_get_code (gs_error_t *err);

/* ------------------------------------------------------------------------- */

typedef struct gs_service_s gs_service_t;

/**
 * Writes a textual representation of the IP/PORT couple in the given
 * destination buffer. The size of this character string is returned.
 *
 * The size returned does not contain the terminal NULL character. The format
 * of the string will be BBB.BBB.BBB.BBB:SSSSS for an IPv4 address or
 * [HH:HH:HH:HH:HH:HH]:SSSSS for an IPv6 address.
 *
 * @param service
 * @param dst
 * @param dst_size
 * @return 
 */
size_t gs_service_get_url(const gs_service_t *service, char *dst, size_t dst_size);

socklen_t gs_service_get_address(const gs_service_t *service, struct sockaddr *sa, socklen_t sa_size);

/**
 * Returns a textual representation of the service-type name.
 *
 * The returned string might be directly extracted from the hidden
 * structure, so there is no need to free it, it will be freed with the
 * service structure. 
 *
 * @param service
 * @return
 */
const char* gs_service_get_type(const gs_service_t *service);

/**
 * Free the structure and all its components.
 *
 * @param service
 */
void gs_free_service( gs_service_t *service );

/**
 * @param services
 */
void gs_service_free_array( gs_service_t **services);

/* ------------------------------------------------------------------------- */

/**
 * Retrieves the indexer refname of an already indexed content in a given
 * container.
 * 
 * This function does not change the service refname status, thus there is
 * no need to {in,}validate anything.
 *
 * There is no caching feature for the services in a container. Then a call
 * to gs_index_get_service_from_path() might fail if the same content is being
 * indexed elsewhere, but has not yet been validated by the other caller (even
 * if it is performed in the same * thread, on the same gs_container_t
 * structure).
 *
 * @param container a valid and open container
 * @param srvtype
 * @param paths a NULL terminated array or NULL-terminated character strings
 * @param err a double pointer to an error structure, that will be set
 *            if the function fails. err may be NULL.
 * @return
 */
gs_service_t** gs_get_services_for_paths( gs_container_t *container, const char *srvtype, char **paths, gs_error_t **err);

/**
 * Returns a single service refname to store all the object paths provided.
 * 
 * @param container
 * @param srvtype
 * @param paths
 * @param err
 * @return
 */
gs_service_t* gs_choose_service_for_paths( gs_container_t *container, const char *srvtype, char **paths, gs_error_t **err);

/**
 * There is no need to {in,}validate the change made to the service, this
 * operation is atomical.
 * 
 * @param container
 * @param srvtype
 * @param paths a NULL-terminated array or NULL-terminated character strings
 * @param removed if provided, filled with an array of strings containing the subset of paths that was really marked for removal
 * @param services
 * @param err a double pointer to an error structure, that will be set
 *            if the function fails. err may be NULL.
 * @return FALSE if no error occured (no path failed)
 */
gs_status_t gs_delete_services_for_paths( gs_container_t *container, const char *srvtype, char **paths,
	char ***removed, gs_service_t ***services, gs_error_t **err);

/**
 * @param container
 * @param srvtype
 * @param err
 * @return
 */
gs_service_t ** gs_service_flush(gs_container_t *container, const char *srvtype, gs_error_t **err);

/**
 * Commit the changes made on the given contents.
 *
 * @param container
 * @param paths a NULL terminated array or NULL-terminated character strings
 * @param srvtype
 * @param paths
 * @param err a double pointer to an error structure, that will be set
 *            if the function fails. err may be NULL.
 * @return NULL if validate succeeded, the list of failed path otherwise
 */
char** gs_validate_changes_on_paths( gs_container_t *container, const char *srvtype, char **paths, gs_error_t **err);

/**
 * Rollback the changes made on the given list on contents.
 *
 * @param container an opened container
 * @param srvtype
 * @param paths a NULL terminated array or NULL-terminated character strings
 * @param err a double pointer to an error structure, that will be set
 *            if the function fails. err may be NULL.
 * @return
 */
char** gs_invalidate_changes_on_paths( gs_container_t *container, const char *srvtype, char **paths, gs_error_t **err);

/** 
 * Get all services used by commited contents in a container
 *
 * @param container
 * @param srvtype
 * @param err set on error if not NULL
 * @return NULL on error, a (maybe empty) service array (free it with gs_service_free_array())
 */
gs_service_t** gs_get_all_services_used( gs_container_t *container, const char *srvtype, gs_error_t **err);

/* ------------------------------------------------------------------------- */

/**
 * Retrieves the indexer refname of an already indexed content in a given
 * container.
 * 
 * This function does not change the service refname status, thus there is
 * no need to {in,}validate anything.
 *
 * There is no caching feature for the services in a container. Then a call
 * to gs_index_get_service_from_path() might fail if the same content is being
 * indexed elsewhere, but has not yet been validated by the other caller (even
 * if it is performed in the same * thread, on the same gs_container_t
 * structure).
 *
 * @param container a valid and open container
 * @param paths a NULL terminated array or NULL-terminated character strings
 * @param err a double pointer to an error structure, that will be set
 *            if the function fails. err may be NULL.
 * @return
 */
gs_service_t** gs_index_get_services_for_paths( gs_container_t *container, char **paths, gs_error_t **err);

/**
 * Returns a single service refname to store all the object paths provided.
 * 
 * @param container an opened container refname
 * @param paths a NULL terminated array or NULL-terminated character strings
 * @param err a double pointer to an error structure, that will be set
 *            if the function fails. err may be NULL.
 * @return
 */
gs_service_t* gs_index_choose_service_for_paths( gs_container_t *container, char **paths, gs_error_t **err);

/**
 * There is no need to {in,}validate the change made to the service, this
 * operation is atomical.
 * 
 * @param container
 * @param paths a NULL-terminated array or NULL-terminated character strings
 * @param removed if provided, filled with an array of strings containing the subset of paths that was really marked for removal
 * @param services
 * @param err a double pointer to an error structure, that will be set
 *            if the function fails. err may be NULL.
 * @return FALSE if no error occured (no path failed)
 */
gs_status_t gs_index_delete_services_for_paths( gs_container_t *container,
		char **paths, char ***removed, gs_service_t ***services,
		gs_error_t **err);

/**
 * @param container
 * @param err
 * @return
 */
gs_service_t ** gs_index_flush(gs_container_t *container, gs_error_t **err);

/**
 * Commit the changes made on the given contents.
 *
 * @param container
 * @param paths a NULL terminated array or NULL-terminated character strings
 * @param err a double pointer to an error structure, that will be set
 *            if the function fails. err may be NULL.
 * @return NULL if validate succeeded, the list of failed path otherwise
 */
char** gs_index_validate_changes_on_paths( gs_container_t *container,
		char **paths, gs_error_t **err);

/**
 * Rollback the changes made on the given list on contents.
 *
 * @param container an opened container
 * @param paths a NULL terminated array or NULL-terminated character strings
 * @param err a double pointer to an error structure, that will be set
 *            if the function fails. err may be NULL.
 * @return
 */
char** gs_index_invalidate_changes_on_paths( gs_container_t *container,
		char **paths, gs_error_t **err);

/** 
 * Get all services used by commited contents in a container
 *
 * @param container
 * @param err set on error if not NULL
 * @return NULL on error, a (maybe empty) service array (free it with gs_service_free_array())
 */
gs_service_t** gs_index_get_all_services_used( gs_container_t *container,
		gs_error_t **err);

/**
 * @param container
 * @param srvtype
 * @param err
 * @return
 */
gs_service_t** gs_container_service_get_available(gs_container_t *container,
		const char *srvtype, gs_error_t **err);

/**
 * @param container
 * @param srvtype
 * @param err
 * @return
 */
gs_service_t** gs_container_service_get_all(gs_container_t *container,
		const char *srvtype, gs_error_t **err);

/* ------------------------------------------------------------------------- */

/**
 * To free such a structure, use gs_container_location_free() or, by yourself,
 * free all the member allocated strings with free(), free the m2_url pointed
 * strings with free and m2_url itself with free().
 */
struct gs_container_location_s {
	char *m0_url;
	char **m1_url;/**< NULL terminated array of strings*/
	char **m2_url;/**< NULL terminated array of strings*/
	char *container_hexid;
	char *container_name;
};

/**
 * @param container
 * @param gserr
 * @return
 */
struct gs_container_location_s * gs_locate_container(gs_container_t *container,
	gs_error_t **gserr);

/**
 * @param client
 * @param hexid
 * @param gserr
 * @return
 */
struct gs_container_location_s * gs_locate_container_by_hexid(gs_grid_storage_t *client,
	const char *hexid, gs_error_t **gserr);


/**
 *  * @param client
 *   * @param hexid
 *    * @param gserr
 *     * @return
 *      */
struct gs_container_location_s * gs_locate_container_by_hexid_v2(gs_grid_storage_t *client,
    const char *hexid, char** out_nsname_on_m1, gs_error_t **gserr);




/**
 * @param client
 * @param name
 * @param gserr
 * @return
 */
struct gs_container_location_s * gs_locate_container_by_name(gs_grid_storage_t *client,
	const char *name, gs_error_t **gserr);

/**
 * @param location
 */
void gs_container_location_free(struct gs_container_location_s *location);

/**
 * @param gs
 * @param container_name
 * @param auto_create
 * @param gs_err
 * @return
 */
gs_container_t* hc_resolve_meta2_entry(gs_grid_storage_t *gs,
		const char *container_name, int auto_create, gs_error_t **gs_err);

/**
 * @param gs
 * @param container_name
 * @param auto_create
 * @param gs_err
 * @return
 */
gs_container_t* gs_get_storage_container(gs_grid_storage_t *gs,
		const char *container_name, const char *stgpol, int auto_create, gs_error_t **gs_err);


gs_container_t* gs_get_storage_container_v2(gs_grid_storage_t *gs,
        const char *container_name, const char *stgpol, const char *verspol, int auto_create, gs_error_t **gs_err);




/* V2 functions */

/**
 * @param hc
 * @param reference
 * @return
 */
gs_error_t* hc_create_reference(gs_grid_storage_t *hc, const char *reference);

/**
 * @param hc
 * @param reference
 * @return
 */
gs_error_t* hc_has_reference(gs_grid_storage_t *hc, const char *reference);

/**
 * @param hc
 * @param reference
 * @return
 */
gs_error_t* hc_delete_reference(gs_grid_storage_t *hc, const char *reference);


/* Services ---------------------------------------------------------------- */

/**
 * @param hc
 * @param reference
 * @param srv_type
 * @param result
 * @return
 */
gs_error_t* hc_link_service_to_reference(gs_grid_storage_t *hc, const char *reference, const char *srv_type, char ***result);

/**
 * @param hc
 * @param reference
 * @param srv_type
 * @param result
 * @return
 */
gs_error_t* hc_list_reference_services(gs_grid_storage_t *hc, const char *reference, const char *srv_type, char ***result);

/**
 * @param hc
 * @param reference
 * @param srv_type
 * @return
 */
gs_error_t* hc_unlink_reference_service(gs_grid_storage_t *hc, const char *reference, const char *srv_type);

/**
 * Inserts the service, even if a service is already up and in use.
 *
 * @param hc
 * @param ref
 * @param url
 * @return
 */
gs_error_t* hc_force_service(gs_grid_storage_t *hc, const char *ref,
		const char *url);

/**
 * Poll a service and fills srv with the newly affected service url.
 *
 * @param hc
 * @param ref
 * @param srvtype
 * @param srv output variable
 * @return
 */
gs_error_t* hc_poll_service(gs_grid_storage_t *hc, const char *ref,
		const char *srvtype, char **srv);

/**
 * Contacts the dorectory and modifies the arguments part of the URL
 *
 * @param hc
 * @param ref
 * @param url
 * @return
 */
gs_error_t* hc_configure_service(gs_grid_storage_t *hc, const char *ref,
		const char *url);

/* Properties -------------------------------------------------------------- */

/**
 * @param hc
 * @param ref
 * @param key
 * @param value
 * @return
 */
gs_error_t* hc_set_reference_property(gs_grid_storage_t *hc,
		const char *ref, const char *key, const char *value);

/**
 * @param hc
 * @param ref
 * @param keys
 * @param result
 * @return
 */
gs_error_t* hc_get_reference_property(gs_grid_storage_t *hc,
		const char *ref, char **keys, char ***result);

/**
 * @param hc
 * @param ref
 * @param keys
 * @return
 */
gs_error_t* hc_delete_reference_property(gs_grid_storage_t *hc,
		const char *ref, char **keys);

/**
 * @param container
 * @param gs_err
 * @return
 */
char** hc_get_container_admin_entries(gs_container_t *container, gs_error_t **gs_err);

/**
 * @param container the targeted container
 * @param storage_policy the storage policy to set to the container
 * @return an error their is an issue while setting the storage policy
 */
gs_error_t* hc_set_container_storage_policy(gs_container_t *container, const char *storage_policy);

/**
 * @param container the targeted container
 * @param storage_policy the storage policy to set to the container
 * @return an error their is an issue while setting the storage policy
 */
gs_error_t* hc_set_container_quota(gs_container_t *container, const char *storage_policy);

/**
 * Sets the given versioning to the given container.
 * @param container the targeted container
 * @param versioning the versioning to set to the container
 * @return an error their is an issue while setting the versioning
 */
gs_error_t* hc_set_container_versioning(gs_container_t *container, const char *versioning);

/**
 * Deletes the versioning of this given container.
 * @param container the targeted container
 * @return an error there is an issue while deleting the versioning
 */
gs_error_t* hc_del_container_versioning(gs_container_t *container);

/**
 * @param container the targeted container 
 * @param path the content to set the policy
 * @param storage_policy the storage policy to set to the container
 * @return an error their is an issue while setting the storage policy
 */
gs_status_t hc_set_content_storage_policy(gs_container_t *c, const char *path, const char *stgpol, gs_error_t **e);

/**
 * add or update content properties
 * @param content the targeted content
 * @param props the properites key=value 
 * @return an error their is an issue while setting the property
 */
gs_status_t hc_set_content_property(gs_content_t *content, char **props,gs_error_t **e);

/**
 * get content properties
 * @param content the targeted content
 * @param result the content properties
 * @return an error their is an issue while getting the property
 */

gs_status_t hc_get_content_properties(gs_content_t *content, char ***result, gs_error_t **e);

/**
 * delete a property to content
 * @param content the targeted content
 * @param keys the list of properties keys  
 * @return an error their is an issue while deleting the property
 */
gs_status_t hc_delete_content_property(gs_content_t *content, char ** keys, gs_error_t **e);

/**
 * Create a copy of a content 
 * @param c
 * @param src  
 * @param dst  
 * @return an error their is an issue while deleting the property
 */
gs_status_t hc_copy_content(gs_container_t *c, const char *src, const char *dst,
			gs_error_t **e);


/* Snapshots --------------------------------------------------------------- */

/**
 * The hidden type that represents a snapshot.
 */
typedef struct redc_snapshot_s redc_snapshot_t;

/**
 * Take a snapshot of a container.
 *
 * @param container The targeted container
 * @param snapshot_name A name for the snapshot (must not start with a digit)
 * @return An error if there is an issue while taking the snapshot, NULL otherwise
 */
gs_error_t* redc_take_snapshot(gs_container_t *container,
		const char *snapshot_name);

/**
 * Delete a snapshot.
 *
 * @param container The targeted container
 * @param snapshot_name The name of the snapshot to delete
 * @return An error if there is an issue while deleting the snapshot, NULL otherwise
 */
gs_error_t* redc_delete_snapshot(gs_container_t *container,
		const char *snapshot_name);

/**
 * Restore a snapshot.
 *
 * @param container The targeted container
 * @param snapshot_name The name of the snapshot to restore
 * @param hard_restore If true, erase all contents and snapshots more recent
 *   than the specified snapshot (instead of just making contents reappear)
 * @return An error if there is an issue while restoring the snapshot, NULL otherwise
 */
gs_error_t* redc_restore_snapshot(gs_container_t *container,
		const char *snapshot_name, int hard_restore);

/**
 * Restore a content from snapshot.
 *
 * @param container The targeted container
 * @param content The name of the content to restore
 * @param snapshot_name The name of the snapshot to restore from
 * @return An error if there is an issue while restoring the snapshot, NULL otherwise
 */
gs_error_t* redc_restore_snapshot_alias(gs_container_t *container,
		const char *content, const char *snapshot_name);

/**
 * Get the list of snapshots of a container.
 *
 * @param container The targeted container
 * @param[out] snapshots A pointer where to store the snapshots
 * @return An error if there is an issue while listing snapshots, NULL otherwise
 *
 * @note The snapshots array is NULL-terminated,
 *   and should be freed by redc_snapshot_array_clean
 */
gs_error_t* redc_list_snapshots(gs_container_t *container,
		redc_snapshot_t ***snapshots);

/**
 * Get the name of a snapshot.
 *
 * @param snapshot The snapshot to get name of
 * @return The name of the snapshot
 */
const char* redc_snapshot_get_name(redc_snapshot_t *snapshot);

/**
 * Clean an array of snapshots.
 *
 * @param snapshots The array of snapshots to clean.
 */
void redc_snapshot_array_clean(redc_snapshot_t **snapshots);

/** @} */

#endif /*__GRID_CLIENT_H__*/
