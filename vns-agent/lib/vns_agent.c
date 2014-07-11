#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "grid.vns_agent.backend"
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <cluster/lib/gridcluster.h>
#include <cluster/remote/gridcluster_remote.h>
#include <meta1v2/meta1_remote.h>

#include "vns_agent_internals.h"

struct vns_agent_handle_s *vns_agent_handle = NULL;

GStaticRWLock vns_table_mutex = G_STATIC_RW_LOCK_INIT;

status_t
vns_agent_info(char *ns_name, GError ** error)
{
        (void) error;
        strcpy(ns_name, vns_agent_handle->ns_info.name);
        return (1);
}

static void
aggregate_vns_space_used(gpointer key, gpointer value, gpointer udata)
{
	(void) udata;
	gint64 ns_space = 0;
	gchar *value_str = NULL;
	gint64 to_add = 0;
	GByteArray *tmp = g_hash_table_lookup(vns_agent_handle->vns_space_used, (gchar*)key);
	if(tmp && tmp->data)
		ns_space =  g_ascii_strtoll((gchar*)tmp->data, NULL, 10);
	value_str = (gchar*)((GByteArray*)value)->data;
	if(value_str)
		to_add = g_ascii_strtoll(value_str, NULL, 10);
	ns_space += to_add;
	gchar ns_space_str[256];
	bzero(ns_space_str, sizeof(ns_space_str));
	g_snprintf(ns_space_str, sizeof(ns_space_str), "%"G_GINT64_FORMAT, ns_space);
	g_hash_table_replace(vns_agent_handle->vns_space_used, g_strdup(key), g_byte_array_append(g_byte_array_new(), (guint8*)ns_space_str, strlen(ns_space_str) + 1));
	DEBUG("%"G_GINT64_FORMAT" total space used of VNS %s", ns_space, (gchar*)key);
}

static void
collect_vns_space_used(gpointer data, gpointer udata)
{
	(void) udata;
	GHashTable *response = NULL;
	GError *error = NULL;

	response = meta1_remote_get_virtual_ns_state(&(((service_info_t*)data)->addr), 4000, &error);
	if(!response) {
		WARN("Failed to get virtual namespaces state from meta1");
		return;
	} else {
		if(g_hash_table_size(response) > 0)
			g_hash_table_foreach(response, aggregate_vns_space_used, NULL);
		g_hash_table_destroy(response);
	}
}

void
vns_agent_space_used_refresh(gpointer d)
{
	(void) d;
	GSList *m1_list = NULL;
	GError *error = NULL;
	addr_info_t ns_addr;
	DEBUG("Firing vns space used refresh");

	/* get conscience addr */
	memset(&ns_addr, '\0', sizeof(addr_info_t));
	memcpy(&ns_addr, &(vns_agent_handle->ns_info.addr), sizeof(addr_info_t));

	/* get all ns_m1 */
	m1_list = list_namespace_services(vns_agent_handle->ns_info.name, "meta1", &error);
	if(!m1_list) {
		WARN("list_namespace_services meta1 return a NULL pointer, cannot aggregate VNS space used");
		return;
	}
	/* lock vns space used table */
	g_static_rw_lock_writer_lock(&vns_table_mutex);
	/* remove old informations */
	g_hash_table_remove_all(vns_agent_handle->vns_space_used);
	/* request all M1 vns info and fill the table */
	g_slist_foreach(m1_list, collect_vns_space_used, NULL);
	/* send the result map to the conscience */
	gcluster_push_virtual_ns_space_used(&ns_addr, 4000, vns_agent_handle->vns_space_used, &error);
	/* unlock the table */
	g_static_rw_lock_writer_unlock(&vns_table_mutex);
	
	/* free m1 info list */
	g_slist_foreach(m1_list, service_info_gclean, NULL);
	g_slist_free(m1_list);
}

static struct vns_agent_handle_s*
vns_agent_handle_create(get_namespace_info_f f, GError ** err)
{
 	struct vns_agent_handle_s *vnsah;
        namespace_info_t *ns_info;

        if (!f) {
                GSETERROR(err, "Invalid parameter (f=%p)", f);
                return NULL;
        }

        vnsah = g_try_malloc0(sizeof(struct vns_agent_handle_s));
        if (!vnsah) {
                GSETERROR(err, "Memory allocation failure");
                return NULL;
        }

        ns_info = f(err);
        if (ns_info == NULL) {
                g_free(vnsah);
                GSETERROR(err, "Failed to retrieves namespace info");
                return NULL;
        }

        if (!namespace_info_copy(ns_info, &(vnsah->ns_info), err)) {
                g_free(vnsah);
                namespace_info_free(ns_info);
                GSETERROR(err, "Failed to copy namespace_info");
                return NULL;
        }

	vnsah->get_namespace_info = f;
	vnsah->vns_space_used = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, metautils_gba_unref);

	namespace_info_free(ns_info);

	return vnsah;
}

status_t
vns_agent_init(GHashTable * params, GError ** error)
{
	get_namespace_info_f get_ns_info = NULL;

        get_ns_info = g_hash_table_lookup(params, KEY_NS_INFO_FUNC);

	if(!get_ns_info) {
                GSETCODE(error, VNS_AGENT_ERRCODE_CONFIG, "Failed to get namespace info function from hash table");
                return (0);
	}

	vns_agent_handle = vns_agent_handle_create(get_ns_info, error);

	return 1;
}

void
vns_agent_close(void)
{
	g_hash_table_destroy(vns_agent_handle->vns_space_used);
	namespace_info_free(&vns_agent_handle->ns_info);
}
