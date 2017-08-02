/*
OpenIO SDS meta0v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef OIO_SDS__sqliterepo__zk_manager_h
# define OIO_SDS__sqliterepo__zk_manager_h 1

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

#endif /*OIO_SDS__sqliterepo__zk_manager_h*/