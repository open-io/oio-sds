/**
 * @file zk_manager.h
 */

#ifndef ZK_MANAGER_H
# define ZK_MANAGER_H 1

# include <glib.h>

struct zk_manager_s;

struct zk_node_s {
	gchar *path;
	gchar *content;
};

/** Creates the service manager to manage node in ZK
 *
 * @param ns
 * @param url
 * @param srvType
 * @param GError
 * @return zk_manager_s
 */
GError * zk_srv_manager_create(gchar *ns, gchar *url, gchar *srvType,
		struct zk_manager_s **result);

/**
 *
 */
void zk_manager_clean(struct zk_manager_s *manager);

/**
 *
 */
void free_zknode(struct zk_node_s *n);

/** Create a service node in ZK
 * @param zk_manager_s
 * @param name
 * @return GError
 */
GError * create_zk_node(struct zk_manager_s *manager, gchar *subdir,
		gchar *name, gchar *data);


/** Create a service node in ZK
 * @param zk_manager_s
 * @param name
 * @param result
 * @return GError
 */
GError * list_zk_children_node(struct zk_manager_s *manager, gchar *name,
		GSList **result);

/** Create a service node in ZK
 * @param zk_manager_s
 * @param subdir
 * @param name
 * @return GError
 */
GError * delete_zk_node(struct zk_manager_s *manager, gchar *subdir,
		gchar *name);

/** @} */
#endif

