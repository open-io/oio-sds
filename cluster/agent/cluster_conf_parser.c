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

#ifndef LOG_DOMAIN
#define LOG_DOMAIN "gridcluster.agent.cluster_conf_parser"
#endif
#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include <metautils.h>

#include "cluster_conf_parser.h"
#include "agent.h"

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

#if 0
static gint vol_sort_func(gconstpointer a, gconstpointer b) {
        volume_info_t *vol1 = (volume_info_t *)a;
        volume_info_t *vol2 = (volume_info_t *)b;

        if (vol1->score.value < vol2->score.value)
                return(1);

        if (vol1->score.value == vol2->score.value)
                return(0);

        if (vol1->score.value > vol2->score.value)
                return(-1);

        return(0);
}

static gint meta2_sort_func(gconstpointer a, gconstpointer b) {
        meta2_info_t *m1 = (meta2_info_t *)a;
        meta2_info_t *m2 = (meta2_info_t *)b;

        if (m1->score.value < m2->score.value)
                return(1);

        if (m1->score.value == m2->score.value)
                return(0);

        if (m1->score.value > m2->score.value)
                return(-1);

        return(0);
}
#endif

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
/*
        if (g_key_file_has_group(key_file, M2_KEY) && g_key_file_has_key(key_file, M2_KEY, M2_NB_KEY, error)) {
                int list_size, i, port;
		gchar *ip = NULL;
		char key[1024];
		meta2_info_t m2_info;
		addr_info_t *addr = NULL;

		list_size = g_key_file_get_integer(key_file, M2_KEY, M2_NB_KEY, error);
                ns_data->meta2 = NULL;

                for(i=0; i < list_size; i++) {

                        memset(&m2_info, 0, sizeof(meta2_info_t));

			memset(key, '\0', sizeof(key));
                        snprintf(key, sizeof(key), M2_ADDRV4_KEY, i);

                        if (g_key_file_has_key(key_file, M2_KEY, key, error)) {
                                m2_info.addr.type = TADDR_V4;
                                ip = g_key_file_get_value(key_file, M2_KEY, key, error);
                        }

			memset(key, '\0', sizeof(key));
                        snprintf(key, sizeof(key), M2_ADDRV6_KEY, i);

			if (g_key_file_has_key(key_file, M2_KEY, key, error)) {
				m2_info.addr.type = TADDR_V6;
				ip = g_key_file_get_value(key_file, M2_KEY, key, error);
                        }

			if (ip == NULL) {
				GSETERROR(error, "No ip found for %dnth meta2", i+1);
				return(0);
			}

			memset(key, '\0', sizeof(key));
                        snprintf(key, sizeof(key), M2_PORT_KEY, i);

			if (g_key_file_has_key(key_file, M2_KEY, key, error)) {
				port = g_key_file_get_integer(key_file, M2_KEY, key, error);
			} else {
				GSETERROR(error, "No port found for %dnth meta2", i+1);
				g_free(ip);
				return(0);
			}

                        addr = build_addr_info(ip, port, error);
                        if (addr == NULL) {
				GSETERROR(error, "Failed to build addr_info for %dth meta2", i+1);
				g_free(ip);
				return(0);
			}

                        memcpy(&(m2_info.addr), addr, sizeof(addr_info_t));
                        g_free(addr);
                        
			memset(key, '\0', sizeof(key));
                        snprintf(key, sizeof(key), M2_SCORE_KEY, i);

			if (g_key_file_has_key(key_file, M2_KEY, key, error)) {
				m2_info.score.value = g_key_file_get_integer(key_file, M2_KEY, key, error);
			} else {
				GSETERROR(error, "No score found for %dnth meta2", i+1);
				g_free(ip);
				return(0);
			}

                        ns_data->meta2 = g_slist_prepend(ns_data->meta2, g_memdup(&m2_info, sizeof(meta2_info_t)));

			DEBUG("Add a new meta2 in namespace : addr[%s] port[%d] score[%d]", ip, port, m2_info.score.value);

			g_free(ip);
                }

                ns_data->m2_lb_info.max_score = ((meta2_info_t *)ns_data->meta2->data)->score.value;
                ns_data->m2_lb_info.current_score = ns_data->m2_lb_info.max_score;

                ns_data->meta2 = g_slist_sort(ns_data->meta2, meta2_sort_func);
        }
*/

	g_key_file_free(key_file);

	return(1);
}
