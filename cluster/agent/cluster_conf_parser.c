#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "gridcluster.agent.cluster_conf_parser"
#endif

#include <stdlib.h>
#include <string.h>

#include <metautils/lib/metautils.h>

#include "./cluster_conf_parser.h"
#include "./agent.h"

#define NS_KEY "namespace"
#define NS_NAME_KEY "name"
#define NS_CHUNK_SIZE_KEY "chunk_size"
#define M2_KEY "meta2"
#define M2_NB_KEY "number"
#define M2_ADDRV4_KEY "%d.addr.ipv4"
#define M2_ADDRV6_KEY "%d.addr.ipv6"
#define M2_PORT_KEY "%d.addr.port"
#define M2_SCORE_KEY "%d.score"
#define VOL_KEY "volumes"
#define VOL_ADDRV4_KEY "%d.addr.ipv4"
#define VOL_ADDRV6_KEY "%d.addr.ipv6"
#define VOL_PORT_KEY "%d.addr.port"
#define VOL_NAME_KEY "%d.name"
#define VOL_SCORE_KEY "%d.score"
#define VOL_NB_KEY "number"

int parse_cluster_conf(const char *file_path, namespace_data_t *ns_data, GError **error) {
	GKeyFile *key_file = NULL;
	gchar *value = NULL;

	/* Load config file */
        key_file = g_key_file_new();
        if (!g_key_file_load_from_file(key_file, file_path, 0, error)) {
		GSETERROR(error, "Failed to load key file %s", file_path);
		return(0);
	}

	/* Parse namespace infos */
        if (g_key_file_has_group(key_file, NS_KEY)) {

                memset(&(ns_data->ns_info), 0, sizeof(namespace_info_t));

                if (g_key_file_has_key(key_file, NS_KEY, NS_NAME_KEY, error)) {
			value = g_key_file_get_value(key_file, NS_KEY, NS_NAME_KEY, error);
                        strncpy(ns_data->ns_info.name, value, LIMIT_LENGTH_NSNAME);
			g_free(value);
                } else {
			GSETERROR(error, "Namespace name is missing (add a %s= in %s group)", NS_NAME_KEY, NS_KEY);
			return(0);
		}

                if (g_key_file_has_key(key_file, NS_KEY, NS_CHUNK_SIZE_KEY, error)) {
                        ns_data->ns_info.chunk_size = g_key_file_get_integer(key_file, NS_KEY, NS_CHUNK_SIZE_KEY, error);
                } else {
			GSETERROR(error, "Namespace chunk_size is missing (add a %s= in %s group)", NS_CHUNK_SIZE_KEY, NS_KEY);
			return(0);
		}

                DEBUG("Set namespace info name(%s) chunk_size(%"G_GINT64_FORMAT") in conf", ns_data->ns_info.name, ns_data->ns_info.chunk_size);
        } else {
		GSETERROR(error, "No namespace info found in config");
		return(0);
	}

	/* Parse meta2 infos */
	g_key_file_free(key_file);

	return(1);
}
