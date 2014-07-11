#ifndef GRID__UTILS_INTERNALS__H
# define GRID__UTILS_INTERNALS__H 1

/**
 * @defgroup server_misc Misc. features
 * @ingroup server
 * @brief
 * @details
 *
 * @{
 */

#include <metautils/lib/metautils.h>


# ifndef GRID_STAT_PREFIX_REQ
#  define GRID_STAT_PREFIX_REQ "gridd.counter.req"
# endif

# ifndef GRID_STAT_PREFIX_TIME
#  define GRID_STAT_PREFIX_TIME "gridd.counter.time"
# endif

# ifndef HTTP_STAT_PREFIX_REQ
#  define HTTP_STAT_PREFIX_REQ "http.counter.req"
# endif

# ifndef HTTP_STAT_PREFIX_TIME
#  define HTTP_STAT_PREFIX_TIME "http.counter.time"
# endif

#ifndef SERVER_DEFAULT_MAX_IDLEDELAY
# define SERVER_DEFAULT_MAX_IDLEDELAY 300
#endif

#ifndef SERVER_DEFAULT_MAX_WORKERS
# define SERVER_DEFAULT_MAX_WORKERS 200
#endif

/** @} */

#endif /* GRID__UTILS_INTERNALS__H */
