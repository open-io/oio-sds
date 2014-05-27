/**
 *  * @file meta0_prefixassign.h
 *   */

#ifndef GRID__META0_PREFIXASSIGN__H
# define GRID__META0_PREFIXASSIGN__H 1

/**
 *  * @addtogroup meta0v2_prefixassign
 *   * @{
 *    */

struct meta0_assign_meta1_s;

GError* meta0_assign_prefix_to_meta1(struct meta0_backend_s *m0, gchar *ns_name, gboolean nocheck);

GError* meta0_assign_disable_meta1(struct meta0_backend_s *m0, gchar *ns_name,char **m1urls, gboolean nocheck);

GError* meta0_assign_fill(struct meta0_backend_s *m0, gchar *ns_name, guint replicas, gboolean nodist);
/** @} */

#endif /* GRID__META0_PREFIXASSIGN__H */
