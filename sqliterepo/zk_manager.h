/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
 * @param namespace
 * @param url
 * @param srvType
 * @param GError
 * @return zk_manager_s
 */
GError *
zk_srv_manager_create(gchar *namespace, gchar *url, gchar *srvType, struct zk_manager_s **result);

void
zk_manager_clean(struct zk_manager_s *manager);

void
free_zknode(gpointer d,gpointer l);

/** Create a service node in ZK
 * @param zk_manager_s
 * @param name
 * @return GError
 */
GError *
create_zk_node(struct zk_manager_s *manager, gchar *subdir,gchar *name, gchar *data);


/** Create a service node in ZK
 * @param zk_manager_s
 * @param name
 * @param result
 * @return GError
 */
GError *
list_zk_children_node(struct zk_manager_s *manager, gchar *name, GSList **result);

/** Create a service node in ZK
 * @param zk_manager_s
 * @param subdir
 * @param name
 * @return GError
 */
GError *
delete_zk_node(struct zk_manager_s *manager, gchar *subdir, gchar *name);

/** @} */
#endif

