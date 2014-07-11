/**
 * @file gs_manifest.h
 *
 */

#ifndef  GS_MANIFEST__H
# define GS_MANIFEST__H 1

/**
 * @defgroup metautils_manifest Manifest 
 * @ingroup metautils_utils
 * @{
 */

# ifndef  GS_MANIFEST_KEY_NS
#  define GS_MANIFEST_KEY_NS   "gs.service.namespace"
# endif

# ifndef  GS_MANIFEST_KEY_TYPE
#  define GS_MANIFEST_KEY_TYPE "gs.service.type"
# endif

# ifndef  GS_MANIFEST_KEY_NAME
#  define GS_MANIFEST_KEY_NAME  "gs.service.name"
# endif

# include <stdarg.h>
# include <glib.h>

/**
 * @brief
 *
 * The optional arguments consist in a NULL terminated sequence of
 * valid character strings (NULL-terminated gchar*) coming by pair,
 * e.g. in: "k1", "v1", "k2", "v2", NULL
 *
 * Mandatory keys: "ns", "name", "type".
 *
 * @param path
 * @param prefix
 * @param error
 * @return 0 in case of error, 1 upon success
 */
extern int gs_manifest_testandset(const gchar *path, const gchar *prefix, GError **error, ...);

/**
 * @param path
 * @param prefix
 * @param error
 * @return
 */
extern GHashTable* gs_manifest_read(const gchar *path, const gchar *prefix, GError **error);

/** @} */

#endif /* GS_MANIFEST__H */
