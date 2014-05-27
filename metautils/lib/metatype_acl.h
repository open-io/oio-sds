#ifndef __REDCURRANT_metatype_acl__h
#define __REDCURRANT_metatype_acl__h 1
#include <glib/gtypes.h>

/**
 * @defgroup metautils_utils_acl ACL 
 * @ingroup metautils_utils
 * @brief ACL utils
 * @details Handles access control lists got from the conscience.
 * @{
 */

/**
 * @param addr
 * @param acl
 * @return
 */
gboolean authorized_personal_only(const gchar* addr, GSList* acl);


/**
 * @param acl_byte
 * @param authorize
 * @return
 */
GSList* parse_acl(const GByteArray* acl_byte, gboolean authorize);


/**
 * @param file_path
 * @param error
 * @return
 */
GSList* parse_acl_conf_file(const gchar* file_path, GError **error);


/**
 * @param addr_rule
 * @return
 */
gchar* access_rule_to_string(const addr_rule_t* addr_rule);


/**
 * @param data
 */
void addr_rule_g_free(gpointer data);

#endif // __REDCURRANT_metatype_acl__h
