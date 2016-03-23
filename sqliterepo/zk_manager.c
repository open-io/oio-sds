/*
OpenIO SDS sqliterepo
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <zookeeper.h>

#include <metautils/lib/metautils.h>

#include "sqliterepo.h"
#include "hash.h"
#include "zk_manager.h"
#include "internals.h"
#include "synchro.h"

struct zk_manager_s
{
	gchar *zk_url;
	zhandle_t *zh;
	gchar zk_dir[256];
};

/* ------------------------------------------------------------------------- */

static gchar*
get_fullpath(struct zk_manager_s *manager, gchar *subdir, gchar* name)
{
	gchar * result;
	if (subdir)
		result = g_strdup_printf("%s/%s",manager->zk_dir,subdir);
	else
		result =  g_strdup(manager->zk_dir);

	if ( name ) {
		struct sqlx_name_s n = {"", "", ""};
		n.base = name;
		struct hashstr_s *key = sqliterepo_hash_name(&n);
		oio_str_reuse (&result, g_strdup_printf("%s/%s", result, hashstr_str(key)));
		g_free(key);
	}

	return result;
}

static void
free_string_vector(struct String_vector * sv)
{
	int i;
	for (i=0; i<sv->count; i++) {
		if ( sv->data[i] != NULL )
			free(sv->data[i]);
	}
	free(sv->data);
	sv->data=NULL;
	sv->count=0;
}

// TODO: factorize with the similar function in sqliterepo/synchro.h
static void
zk_main_watch(zhandle_t *zh, int type, int state, const char *path,
		void *watcherCtx)
{
	metautils_ignore_signals();

	GRID_DEBUG("%s(%p,%d,%d,%s,%p)", __FUNCTION__,
			zh, type, state, path, watcherCtx);

	struct zk_manager_s *manager = watcherCtx;
	const char *zkurl = manager->zk_url;

	if (type != ZOO_SESSION_EVENT)
		return;

	if (state == ZOO_EXPIRED_SESSION_STATE) {
		GRID_WARN("Zookeeper: (re)connecting to [%s]", zkurl);
		if (manager->zh)
			zookeeper_close(manager->zh);

		/* XXX(jfs): forget the previous ID and reconnect */
		manager->zh = zookeeper_init(manager->zk_url, zk_main_watch,
				SQLX_SYNC_DEFAULT_ZK_TIMEOUT, NULL, manager, 0);
		if (!manager->zh) {
			GRID_ERROR("ZooKeeper init failure: (%d) %s",
					errno, strerror(errno));
			abort();
		}
	}
	else if (state == ZOO_AUTH_FAILED_STATE) {
		GRID_WARN("Zookeeper: auth problem to [%s]", zkurl);
	}
	else if (state == ZOO_ASSOCIATING_STATE) {
		GRID_DEBUG("Zookeeper: associating to [%s]", zkurl);
	}
	else if (state == ZOO_CONNECTED_STATE) {
		GRID_INFO("Zookeeper: connected to [%s]", zkurl);
	}
	else {
		GRID_INFO("Zookeeper: unmanaged event [%s]", zkurl);
	}
}

/* ------------------------------------------------------------------------- */

GError *
zk_srv_manager_create(gchar *namespace, gchar *url, gchar *srvType,
		struct zk_manager_s **result)
{
	EXTRA_ASSERT(namespace != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(srvType != NULL);

	struct zk_manager_s *manager;
	struct Stat my_stat;
	int rc;

	manager = g_malloc0(sizeof(*manager));

	manager->zk_url = g_strdup(url);
	g_snprintf(manager->zk_dir, sizeof(manager->zk_dir),
			"/hc/ns/%s/srv/%s", namespace, srvType);

	manager->zh = zookeeper_init(url, zk_main_watch,
			SQLX_SYNC_DEFAULT_ZK_TIMEOUT, NULL, manager, 0);
	if (!manager->zh)
		return NEWERROR(errno, "ZooKeeper init failure: %s", strerror(errno));

	/* Check if zk_dir node exists.
	 * zk_dir node should be created by zk-boostrap.py */
	rc = zoo_exists(manager->zh, manager->zk_dir, 0, &my_stat);
	if (rc == ZNONODE) {
		GRID_WARN("zk base node [%s] doesn't exist, zk code (%d). "
				"Please run zk-bootstrap.py.",
				manager->zk_dir, rc);
	} else if (rc != ZOK) {
		GRID_WARN("Failed to connect to zookeeper, zk code (%d)", rc);
	}

	*result = manager;
	return NULL;
}

void
zk_manager_clean(struct zk_manager_s *manager)
{
	EXTRA_ASSERT(manager != NULL);

	if (manager->zh)
		zookeeper_close(manager->zh);
	oio_str_clean (&manager->zk_url);

	g_free(manager);
}

void
free_zknode(struct zk_node_s *n)
{
	if (!n)
		return;
	oio_str_clean(&(n->path));
	oio_str_clean(&(n->content));
	g_free(n);
}

GError *
create_zk_node(struct zk_manager_s *manager, gchar *subdir, gchar *name, gchar *data)
{
	EXTRA_ASSERT(manager != NULL);
	EXTRA_ASSERT(name != NULL);

	gchar buffer[512];
	memset(buffer, 0, sizeof(buffer));

	gchar *path = get_fullpath(manager, subdir, name);
	STRING_STACKIFY(path);

	GRID_TRACE("create node %s, full path [%s]", name, path);

	errno = 0;
	int rc = zoo_create(manager->zh, path, data, strlen(data),
			&ZOO_OPEN_ACL_UNSAFE, 0, buffer, sizeof(buffer)-1);

	if (rc != ZOK && rc != ZNODEEXISTS) {
		const char prefix[] = "Failed to create Zk node [%s]: (%d) %s";
		switch (rc) {
		case ZCONNECTIONLOSS:
			return NEWERROR(CODE_NETWORK_ERROR, prefix, name, rc,
					"no connection to zookeeper");
		case ZNONODE:
			return NEWERROR(0, prefix, name, rc, "missing parent node");
		default:
			return NEWERROR(0, prefix, name, rc, "");
		}
	}
	return NULL;
}

GError *
list_zk_children_node(struct zk_manager_s *manager, gchar *sub_dir, GSList **result)
{
	struct Stat my_stat;
	GError *err = NULL;
	struct zk_node_s *zknode;
	GSList *list=NULL;

	gchar *dirpath = get_fullpath(manager,sub_dir,NULL);
	STRING_STACKIFY(dirpath);

	struct String_vector sv = {0};
	memset(&sv, '\0', sizeof(struct String_vector));
	int rc = zoo_get_children(manager->zh, dirpath, 0, &sv);

	if ( rc != ZOK ) {
		err = NEWERROR(0, "Failed to find zk children node [%s] , zk code [%d]",
				dirpath,rc);
		goto end_error;
	}

	for (int i=0; i<sv.count; i++) {
		gchar buffer[512] = {0};
		int buflen = sizeof(buffer)-1;
		zknode = g_malloc0(sizeof(struct zk_node_s));
		gchar *fullpath = g_strdup_printf("%s/%s",dirpath,sv.data[i]);
		rc = zoo_get(manager->zh, fullpath, 1, buffer , &buflen, &my_stat);
		if ( rc != ZOK ) {
			g_free (fullpath);
			err =  NEWERROR(0, "Failed to get node [%s] , zk code [%d]", fullpath, rc);
			goto end_error;
		}

		zknode->path = fullpath;
		fullpath = NULL;
		if ( buflen > 0 )
			zknode->content=g_strdup(buffer);
		list = g_slist_prepend(list,zknode);
	}
	*result=list;

end_error :
	free_string_vector(&sv);
	if ( err ) {
		g_slist_free_full(list, (GDestroyNotify) free_zknode);
		*result=NULL;
	}
	return err;
}

GError *
delete_zk_node(struct zk_manager_s *manager, gchar *subdir, gchar *name)
{
	EXTRA_ASSERT(manager != NULL);
	EXTRA_ASSERT(name != NULL);

	gchar *fullpath = get_fullpath(manager,subdir,name);
	STRING_STACKIFY(fullpath);

	GRID_TRACE("create node %s , full path [%s]", name, fullpath);

	int rc = zoo_delete(manager->zh, fullpath, -1);
	if ( rc != ZOK && rc != ZNONODE )
		return  NEWERROR(0, "Failed to delete zk  node [%s], zk code [%d]", name, rc);
	return NULL;
}

