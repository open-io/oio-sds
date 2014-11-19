/**
 * @file gs_internals.h
 * Client internals
 */
#ifndef _GS_INTERNALS_H__
#define _GS_INTERNALS_H__

/**
 * @defgroup private Private
 * @ingroup client
 * @defgroup internals Internals
 * @ingroup private
 * @{
 */

#ifndef  G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.client"
#endif

#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/poll.h>

#include <neon/ne_basic.h>
#include <neon/ne_request.h>
#include <neon/ne_session.h>

#include <metautils/lib/metatypes.h>
#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include <cluster/lib/gridcluster.h>
#include <meta0v2/meta0_remote.h>
#include <meta0v2/meta0_utils.h>
#include <meta1v2/meta1_remote.h>
#include <meta2/remote/meta2_remote.h>
#include <meta2/remote/meta2_services_remote.h>
#include <meta2v2/meta2_utils.h>
#include <meta2v2/meta2v2_remote.h>
#include <meta2v2/autogen.h>
#include <meta2v2/generic.h>
#include <resolver/hc_resolver.h>

#include "./grid_client.h"
#include "./meta_resolver_explicit.h"
#include "./meta_resolver_metacd.h"
#include "./metacd_remote.h"
#include "./loc_context.h"
#include "./grid_client_shortcuts.h"

#ifndef  CS_TOCNX_DEFAULT
# define CS_TOCNX_DEFAULT  60000
#endif
#ifndef  CS_TOREQ_DEFAULT
# define CS_TOREQ_DEFAULT  90000
#endif

#ifndef  M0_TOCNX_DEFAULT
# define M0_TOCNX_DEFAULT  60000
#endif
#ifndef  M0_TOREQ_DEFAULT
# define M0_TOREQ_DEFAULT  90000
#endif

#ifndef  M1_TOCNX_DEFAULT
# define M1_TOCNX_DEFAULT  60000
#endif
#ifndef  M1_TOREQ_DEFAULT
# define M1_TOREQ_DEFAULT  90000
#endif

#ifndef  M2_TOCNX_DEFAULT
# define M2_TOCNX_DEFAULT  60000
#endif
#ifndef  M2_TOREQ_DEFAULT
# define M2_TOREQ_DEFAULT  90000
#endif

#ifndef  RAWX_TOCNX_DEFAULT
# define RAWX_TOCNX_DEFAULT  60000
#endif
#ifndef  RAWX_TOREQ_DEFAULT
# define RAWX_TOREQ_DEFAULT  90000
#endif

#ifndef  METACD_TOCNX_DEFAULT
# define METACD_TOCNX_DEFAULT  60000
#endif
#ifndef  METACD_TOREQ_DEFAULT
# define METACD_TOREQ_DEFAULT  90000
#endif

#define GSCLIENT_NOINIT 0x01

#define CI_FULLPATHLEN (LIMIT_LENGTH_VOLUMENAME+1+(2*sizeof(chunk_id_t))+1+64)

#define CODE_RETRY_CONTAINER(C) ((C)==CODE_CONTAINER_LOCKED)

#define CODE_RECONNECT_CONTAINER(C) ((C)<100)

#define CODE_REFRESH_CONTAINER(C)  (\
	   ((C)==CODE_CONTAINER_MIGRATED) \
	|| ((C)==CODE_CONTAINER_NOTFOUND) \
	|| ((C)==CODE_CONTAINER_DISABLED))

#define CODE_REFRESH_META0(C)    (\
	   ((C)==CODE_RANGE_MIGRATING) \
	|| ((C)==CODE_RANGE_NOTFOUND) )

#define ZERO(A) memset((A), 0x00, sizeof(A));

#ifndef NO_ASSERT
# include <assert.h>
# define MYASSERT(C) assert(C)
#else
# define MYASSERT(C)
#endif

#define ENV_LOG4C_ENABLE "GS_DEBUG_ENABLE"
#define ENV_LOG4C_LOAD "GS_DEBUG_PATH"
#define ENV_GLIB2_ENABLE "GS_DEBUG_GLIB2"
#define ENV_WAIT_ON_FAILED_ADD "GS_RETRY_DELAY"

#define NB_ATTEMPTS_RESOLVE_M1 3
#define NB_ATTEMPTS_UPDATE_M1 2
#define NB_ATTEMPTS_RESOLVE_M2 3
#define NB_ATTEMPTS_GET_CONTAINER 2
#define NB_ATTEMPTS_AUTOCREATE 2

#ifndef NAME_SRVTYPE_INDEX
# define NAME_SRVTYPE_INDEX "solr"
#endif

#ifndef  MAX_ATTEMPTS_CLOSE
# define MAX_ATTEMPTS_CLOSE 3
#endif

#ifndef  MAX_ATTEMPTS_ROLLBACK_DELETE
# define MAX_ATTEMPTS_ROLLBACK_DELETE 1
#endif

#ifndef  MAX_ATTEMPTS_ROLLBACK_UPLOAD
# define MAX_ATTEMPTS_ROLLBACK_UPLOAD 2
#endif

#define NB_RELOADS_GET 2 /* how many chunks list reload when the conditions match */
#define NB_DOWNLOADS_GET 3 /* how many attempts on a same chunk position */

/**
 * There is currently no support for META1 redundancy
 */
struct gs_grid_storage_s {
	namespace_info_t ni;
	
	struct {
		struct {
			gint cnx;
			gint op;
		} m2;
		struct {
			gint cnx;
			gint op;
		} rawx;
	} timeout;

	struct metacd_s *metacd_resolver;
	resolver_direct_t *direct_resolver;
	char *full_vns;
	char *physical_namespace;
};

struct gs_container_s {
	gs_container_info_t  info;
	container_id_t       cID;
	char                 str_cID[STRLEN_CONTAINERID];
	addr_info_t          meta2_addr;
	int 		     meta2_cnx;/**<a socket descriptor*/
	char                 opened;/**<used for its boolean value*/
	int		     ac;/**<if autocreation specified while creating the container*/
};

struct gs_content_s {
	gs_content_info_t	info;
	gboolean			loaded_from_cache;
	GSList				*chunk_list;
	GByteArray			*gba_md;
	GByteArray			*gba_sysmd;
	gchar				*version;
	gboolean			deleted;
	gchar				*policy;
};

typedef struct gs_chunk_s {
	gs_content_t *content;
	chunk_info_t *ci;
} gs_chunk_t;

struct gs_service_s {
	gs_container_t *gss_container;
	struct service_info_s *gss_si;
};

#define C0_NAME(pC)     ((pC)->info.name)
#define C0_ID(pC)       ((pC)->cID)
#define C0_IDSTR(pC)    ((pC)->str_cID)
#define C0_CNX(pC)      &((pC)->meta2_cnx)
#define C0_RAWX_TO_CNX(pC)  gs_grid_storage_get_timeout((pC)->info.gs, GS_TO_RAWX_CNX)
#define C0_RAWX_TO_OP(pC)  gs_grid_storage_get_timeout((pC)->info.gs, GS_TO_RAWX_OP)
#define C0_M2TO_CNX(pC) gs_grid_storage_get_timeout((pC)->info.gs, GS_TO_M2_CNX)
#define C0_M2TO(pC)     gs_grid_storage_get_timeout((pC)->info.gs, GS_TO_M2_OP)
#define C0_M1CNX(pC)     gs_grid_storage_get_timeout((pC)->info.gs, GS_TO_M1_CNX)
#define C0_M1TO(pC)     gs_grid_storage_get_timeout((pC)->info.gs, GS_TO_M1_OP)
#define C0_M0TO(pC)     gs_grid_storage_get_timeout((pC)->info.gs, GS_TO_M0_OP)

#define C1_C0(pContent) (pContent)->info.container

#define C1_ID(pC)       C0_ID(C1_C0(pC))
#define C1_IDSTR(pC)    C0_IDSTR(C1_C0(pC))
#define C1_CNX(pC)      C0_CNX(C1_C0(pC))
#define C1_NAME(pC)     C0_NAME(C1_C0(pC))
#define C1_RAWX_TO_CNX(pC)  C0_RAWX_TO_CNX(C1_C0(pC))
#define C1_RAWX_TO_OP(pC)  C0_RAWX_TO_OP(C1_C0(pC))
#define C1_M2TO_CNX(pC) C0_M2TO_CNX(C1_C0(pC))
#define C1_M2TO(pC)     C0_M2TO(C1_C0(pC))
#define C1_M1TO(pC)     C0_M1TO(C1_C0(pC))
#define C1_M0TO(pC)     C0_M0TO(C1_C0(pC))
#define C1_PATH(pC)     (pC->info.path)
#define C1_VERSION(pC)     (pC->version)


#define GSERRORSET(E,FMT,...) gs_error_set((E),0,(FMT),##__VA_ARGS__)

#define GSERRORCODE(E,C,FMT,...) gs_error_set((E),(C),(FMT),##__VA_ARGS__)

#define GSERRORCAUSE(E,GE,FMT,...) gs_error_set_cause((E),(GE),(FMT),##__VA_ARGS__)


void gs_error_set (gs_error_t **err, int code, const char *format, ...);

/**
 * Transmits the 'ge' parameter to the given 'err' error structure.
 */
void gs_error_set_cause (gs_error_t **err, GError *ge, const char *format, ...);

/**
 * If not null, call gs_error_free on the structure pointer pointed by
 * the parameter and set it to NULL.
 * If the parameter is a NULL pointer, nothing will be done.
 */
void gs_error_clear (gs_error_t **err);


/* Reloads the internal chunk set of the given content */
gboolean gs_content_reload (gs_content_t *content, gboolean allow_meta2, gboolean allow_cache, gs_error_t **err);
gboolean gs_content_reload_with_filtered (gs_content_t *content, gboolean allow_meta2, gboolean allow_cache,
		GSList **p_filtered, GSList **p_beans, gs_error_t **err);

/* sort the chunk_info_t following the ascending order of their positions */
gint chunkinfo_sort_position_ASC (gconstpointer c1, gconstpointer c2);


/* sort the chunk_info_t following the descending order of their positions */
gint chunkinfo_sort_position_DESC (gconstpointer c1, gconstpointer c2);


/**
 * Split the given URL into 2 buffers.
 * The URL must have the format [IP]:PORT where IP is an IPv4 address
 * in dotted notation, or an IPv6 address in hexadecimal representation.
 * If the format is good, the address part is resolved using getnameinfo */
gboolean gs_url_split (const gchar *url, gchar **host, gchar **port);


/**
 * Explicitely refresh a reference to a remote container.
 * The remote container won't be closed
 *
 * @param container
 * @param err
 *
 * @return
 */
gs_status_t gs_container_refresh (gs_container_t *container, GError **err);

/**
 * Reopens the connection to a remote container server (i.e. a META2 server)
 * The refresh flag specified in the parameters tells the function wether
 * refresh the META2 reference if error occurs, errors that could due to a
 * out-of-sync structure a refresh could repair.
 *
 * @param container
 * @param err
 *
 * @return
 */
gs_status_t gs_container_reconnect (gs_container_t *container, GError **err);


/**
 *
 */
gs_status_t gs_container_reconnect_if_necessary (gs_container_t *container, GError **err);

/**/
gs_status_t gs_manage_container_error (gs_container_t *container, const char *caller, guint line, GError **err);

/**
 * Closes the connection to a meta2 directory and mark the structure to
 * represent this state.
 */
void gs_container_close_cnx (gs_container_t *container);


/**
 * Utility function that returns a pointer to the internal message
 * of the GError structure. Do not free it, do not touch it, no ...
 * nothing! Just print it.
 * It always returns a valid NULL terminated pointer.
 */
const char* g_error_get_message (GError *err);


/**
 * Returns a static string explaining quickly the error code.
 */
const char* gs_error_code_to_error (int code);

/**
 *
 */
gs_error_t* gs_error_new(int code, const gchar *fmt, ...);

/* ------------------------------------------------------------------------- */


/* Tells the given grid storage to decache its information about the given
 * container identifier. If the only_resolver is not NULL, only this
 * resolver will be contacted, otherwise all the resolvers will be
 * decached. 
 */
void gs_decache_container (gs_grid_storage_t *gs, container_id_t cID);

/* decache all the META1 and the META0 cache */
void gs_decache_all (gs_grid_storage_t *gs);

/**
 * Resolv a list of META2 addr hosting the given container_id
 * Run the resolvers until a answer can be received
 *
 * @param gs an initialized gs_gridstorage (gs_grid_storage_init())
 * @param cID the container id we're looking the META2 for
 * @param err
 *
 * @return a list of META2 addr_info_t or NULL if an error occured (err is set)
 */
GSList* gs_resolve_meta2 (gs_grid_storage_t *gs, container_id_t cID, GError **err);

/* Run the resolvers for a meta1 address list */
addr_info_t* gs_resolve_meta1 (gs_grid_storage_t *gs, container_id_t cID, GError **err);

addr_info_t* gs_resolve_meta1v2 (gs_grid_storage_t *gs,
		const container_id_t cID, const gchar *cname, int read_only,
		GSList **exclude, GError **err);

addr_info_t* gs_resolve_meta1v2_v2(gs_grid_storage_t *gs,
		const container_id_t cID, const gchar *cname, int read_only,
		GSList **exclude, gboolean has_before_create, GError **err);

int gs_update_meta1_master (gs_grid_storage_t *gs, const container_id_t cID, const char *m1);

struct meta2_raw_content_s* gs_resolve_content(gs_container_t *container, GError **err, const gchar *path);

gs_status_t gs_container_reconnect_and_refresh (gs_container_t *container, GError **err, gboolean may_refresh);

gs_status_t gs_check_chunk_agregate (GSList *agregate, gs_error_t **gserr);

void gs_decache_chunks_in_metacd(gs_content_t *content);

#define C0_LIST(C,E) meta2_remote_container_list_in_fd (C0_CNX(C), C0_M2TO(C), (E), C0_ID(C))
#define C0_DESTROY(A,C,E) meta1_remote_destroy_container_by_id ((A), C0_M1TO(C), (E), C0_ID(C))

#define C1_GET(C,E) meta2_remote_content_retrieve_in_fd (C1_CNX(C), C1_M2TO(C), (E), C1_ID(C), C1_PATH(C))
#define C1_COMMIT(C,E) meta2_remote_content_commit_in_fd (C1_CNX(content), C1_M2TO(content), &localError, C1_ID(content), C1_PATH(content))
#define C1_ROLLBACK(C,E) meta2_remote_content_rollback_in_fd (C1_CNX(content), C1_M2TO(content), &localError, C1_ID(content), C1_PATH(content))
#define C1_REMOVE(C,E) meta2_remote_content_remove_in_fd (C1_CNX(content), C1_M2TO(content), &localError, C1_ID(content), C1_PATH(content))

#define CONTAINER_REFRESH(C,Error,Label,Msg) do\
{ if (GS_OK != gs_manage_container_error(C,__FILE__,__LINE__,&Error)) goto Label; } while (0)

extern long unsigned int wait_on_add_failed;

void map_content_from_raw(gs_content_t *content,
		struct meta2_raw_content_s *raw_content);

gboolean map_raw_content_from_beans(struct meta2_raw_content_s *raw_content, GSList *beans, GSList **filtered, gboolean force_keep_position);

gboolean map_properties_from_beans(GSList **properties, GSList *beans);
gboolean map_policy_from_beans(gchar **policy, GSList *beans);
struct bean_CHUNKS_s *get_chunk_matching_content(GSList *beans, struct bean_CONTENTS_s *content);
void fill_chunk_id_from_url(const char * const url, chunk_id_t *ci);
void fill_hcurl_from_container(gs_container_t *c, struct hc_url_s **url);
void fill_hcurl_from_content(gs_content_t *content, struct hc_url_s **url);

struct dl_status_s {
	struct gs_download_info_s dl_info;/*< as transmitted by the client */

	int64_t content_dl; /*< How many bytes have been read yet */

	int64_t chunk_dl; /*< size already downloaded IN THE CURRENT CHUNK, for debug purposes */

	int64_t chunk_start_offset; /*< The offset of the chunk's agregate start in the content's chunks sequence */
	int64_t chunk_dl_offset; /*< offset IN THE CURRENT CHUNK, for the next download */
	int64_t chunk_dl_size; /*< size to be downloaded IN THE CURRENT CHUNK, for the next download */

	chunk_position_t last_position;
	guint last_position_attempts;
	gboolean caller_stopped;
	gboolean caller_error;
};

gs_container_t* gs_init_container(gs_grid_storage_t *gs,
	const char *container_name, int ac, gs_error_t **err);

gs_grid_storage_t* gs_grid_storage_init_flags(const gchar *ns, uint32_t flags,
		int to_cnx, int to_req, gs_error_t **err);

/*
 * Same as gs_get_storage_container (from grid_client.h) but takes
 * m2v2_create_params_s as third parameter.
 */
gs_container_t* gs_get_storage_container2(gs_grid_storage_t *gs,
		const char *container_name, struct m2v2_create_params_s *params,
		int auto_create, gs_error_t **gs_err);

/**
 * @param container
 * @param err
 * @return
 */
gboolean gs_reload_container(gs_container_t *container, GError **err);

/**
 * @param container
 * @param err
 * @return
 */
gboolean gs_relink_container(gs_container_t *container, GError **err);

// ----- PROPERTIES ------
gs_error_t* hc_set_container_global_property(gs_container_t *container,
		const char *prop_name, const char *prop_val);

gs_error_t* hc_del_container_global_property(gs_container_t *container,
		const char *prop_name);

gs_error_t *hc_get_container_global_properties(gs_container_t *container,
		char ***result);

#include "./rawx.h"
#include "./rainx.h"
#include "./rainx_remote.h"

/** @} */

#endif /*_GS_INTERNALS_H__*/
