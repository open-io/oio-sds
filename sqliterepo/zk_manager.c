#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "sqliterepo"
#endif

#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <zookeeper/zookeeper.h>

#include <metautils/lib/metautils.h>

#include "sqliterepo.h"
#include "hash.h"
#include "zk_manager.h"
#include "internals.h"

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
	struct hashstr_s *key;
	gchar * result;
	if (subdir)
		result = g_strdup_printf("%s/%s",manager->zk_dir,subdir);
	else
		result =  g_strdup(manager->zk_dir);

	if ( name ) {
		key = sqliterepo_hash_name(name,"");
		result =  g_strdup_printf("%s/%s",result,hashstr_str(key));
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

static void
zk_main_watch(zhandle_t *zh, int type, int state, const char *path,
		void *watcherCtx)
{
	const gchar *zkurl;
	struct zk_manager_s *manager;

	GRID_INFO("%s(%p,%d,%d,%s,%p)", __FUNCTION__,
			zh, type, state, path, watcherCtx);

	manager = watcherCtx;
	zkurl = manager->zk_url;

	if (type == ZOO_SESSION_EVENT) {
		if (state == ZOO_CONNECTING_STATE) {
			zookeeper_close(manager->zh);
			manager->zh = zookeeper_init(manager->zk_url, zk_main_watch,
					4000, NULL, manager, 0);
			if (!manager->zh) {
				GRID_ERROR("ZooKeeper init failure: (%d) %s",
						errno, strerror(errno));
				abort();
			}
		}
	}
	else {
		if (state == ZOO_EXPIRED_SESSION_STATE) {
			GRID_WARN("Zookeeper: expired session to [%s]", zkurl);
		}
		else if (state == ZOO_AUTH_FAILED_STATE) {
			GRID_WARN("Zookeeper: auth problem to [%s]", zkurl);
		}
		else if (state == ZOO_CONNECTING_STATE) {
			GRID_WARN("Zookeeper: (re)connecting to [%s]", zkurl);
		}
		else if (state == ZOO_ASSOCIATING_STATE) {
			GRID_DEBUG("Zookeeper: associating to [%s]", zkurl);
		}
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
	struct Stat stat;
	int rc;

	manager = g_malloc0(sizeof(*manager));

	manager->zk_url = g_strdup(url);
	g_snprintf(manager->zk_dir, sizeof(manager->zk_dir),
		"/hc/ns/%s/srv/%s", namespace,srvType);

	manager->zh = zookeeper_init( url, zk_main_watch, 4000, NULL, manager, 0);
	if ( !manager->zh )
		return NEWERROR(errno, "ZooKeeper init failure: %s", strerror(errno));

	//check if zk_dir node exist . zk_dir Node should be created by zk-boostrap.py
	rc = zoo_exists(manager->zh, manager->zk_dir, 0, &stat);
	if ( rc == ZNONODE ) {
		return NEWERROR(0, "zk base node [%s] doesn't exist, zk code [%d]",
				manager->zk_dir, rc);
	}

	if ( rc != ZOK) {
		GRID_WARN("Failed to connect to zookeeper, zk code [%d]",rc);
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

	memset(manager, 0, sizeof(*manager));
	g_free(manager);
}

void
free_zknode(struct zk_node_s *n)
{
	if (!n)
		return;
	metautils_str_clean(&(n->path));
	metautils_str_clean(&(n->content));
	g_free(n);
}

GError *
create_zk_node(struct zk_manager_s *manager, gchar *subdir, gchar *name, gchar *data)
{
	EXTRA_ASSERT(manager != NULL);
	EXTRA_ASSERT(name != NULL);

	int rc;
	gchar buffer[512], *path;

	memset(buffer, 0, sizeof(buffer));
	path = get_fullpath(manager, subdir, name);
	GRID_TRACE("create node %s , full path [%s]", name, path);

	rc = zoo_create(manager->zh, path, data, strlen(data),
			&ZOO_OPEN_ACL_UNSAFE, 0, buffer, sizeof(buffer)-1);
	g_free(path);

	if (rc != ZOK && rc != ZNODEEXISTS)
		return  NEWERROR(0, "Failed to create Zk node [%s], zk code [%d]", name, rc );
	return NULL;
}


GError *
list_zk_children_node(struct zk_manager_s *manager, gchar *sub_dir, GSList **result)
{
	struct String_vector sv;
	int i, rc;
	gchar buffer[512];
	struct Stat stat;
	gchar *fullpath=NULL;
	gchar *dirpath=NULL;
	GError *err = NULL;
	struct zk_node_s *zknode;
	GSList *list=NULL;
	int buflen=0;

	memset(&sv, '\0', sizeof(struct String_vector));
	dirpath = get_fullpath(manager,sub_dir,NULL);
	rc = zoo_get_children(manager->zh, dirpath, 0, &sv);

	if ( rc != ZOK ) {
		err = NEWERROR(0, "Failed to find zk children node [%s] , zk code [%d]",
				dirpath,rc);
		goto end_error;
	}

	for (i=0; i<sv.count; i++) {
		memset( buffer, 0, 512 );
		buflen= sizeof(buffer)-1;
		zknode = g_malloc0(sizeof(struct zk_node_s));
		fullpath = g_strdup_printf("%s/%s",dirpath,sv.data[i]);
		rc = zoo_get(manager->zh, fullpath, 1, buffer , &buflen, &stat);
		if ( rc != ZOK ) {
			err =  NEWERROR(0, "Failed to get node [%s] , zk code [%d]",fullpath,rc);
			goto end_error;
		}

		zknode->path=g_strdup(fullpath);
		if ( buflen > 0 )
			zknode->content=g_strdup(buffer);
		list = g_slist_prepend(list,zknode);
	}
	*result=list;

end_error :
	free_string_vector(&sv);
	if (fullpath)
		g_free(fullpath);
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

	int rc;

	GRID_TRACE("create node %s , full path [%s]", name,
			get_fullpath(manager,subdir,name));

	rc = zoo_delete(manager->zh,get_fullpath(manager,subdir,name),-1);

	if ( rc != ZOK && rc != ZNONODE )
		return  NEWERROR(0, "Failed to delete zk  node [%s], zk code [%d]", name, rc);
	return NULL;
}

