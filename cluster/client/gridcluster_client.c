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
# define LOG_DOMAIN "cluster.client"
#endif
#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <metautils.h>
#include "gridcluster_ipc.h"
#include "gridcluster.h"

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

int main(int argc, char **argv) {
	addr_info_t *addr;
	GError *err = NULL;
	int i, port = 0, list_size = 0, data_size = 0;
	void *data = NULL;
	GKeyFile *key_file = NULL;
	cluster_data_header_t header;
	meta1_info_t m1_info;
	meta2_info_t m2_info, *mi = NULL;
	volume_info_t volume_info, *vi = NULL;
	namespace_info_t ns_info;
	char *vol_name = NULL;
	char key[1024];
	char *ip = NULL;
	struct in_addr in;
	GSList *list = NULL, *tmp = NULL;

	if (!argv[1]) {
		ERROR("Usage : %s <config file>", argv[0]);
		return 1;
	}

	memset(key, '\0', 1024);

	key_file = g_key_file_new();
	g_key_file_load_from_file(key_file, argv[1], 0, &err);

	if (g_key_file_has_group(key_file, "meta1") && g_key_file_has_key(key_file, "meta1", "number", &err)) {

		list_size = g_key_file_get_integer(key_file, "meta1", "number", &err);
		data_size = sizeof(cluster_data_header_t) +list_size*sizeof(meta1_info_t);

		data = get_data(META1_IPC_NAME, &err);
		if (data == NULL) {
			if (!release_data(META1_IPC_NAME, data, &err))
				FATAL("Release failed : %s", err->message);
			DEBUG("Try to create a new shm");
			data = create_data(META1_IPC_NAME, data_size, &err);
			if (data == NULL) {
				ERROR("Failed to get meta1 data from shm");
				return 1;
			}

		} else if (((cluster_data_header_t *)data)->list_size < list_size) {
			/* We need to recreate a bigger shm */
			DEBUG("Data segment is to small => recreation needed");
			if (!release_data(META1_IPC_NAME, data, &err)) {
				ERROR("Release failed : %s", err->message);
				return 1;
			}

			if (!remove_data(META1_IPC_NAME, &err)) {
				ERROR("Remove failed : %s", err->message);
				return 1;
			}

			if (!release_data(META1_IPC_NAME, NULL, &err)) {
				ERROR("Release failed : %s", err->message);
				return 1;
			}

			data = create_data(META1_IPC_NAME, data_size, &err);
			if (data == NULL) {
				ERROR("Create failed : %s", err->message);
				return 1;
			}
		}

		header.list_size = list_size;
		header.last_used = 0;
		memcpy(data, &header, sizeof(cluster_data_header_t));

		for(i=0; i < list_size; i++) {

			memset(&m1_info, 0, sizeof(meta1_info_t));

			snprintf(key, 1024, "%d.addr.ipv4", i);

			if (g_key_file_has_key(key_file, "meta1", key, &err)) {

				m1_info.addr.type = TADDR_V4;
				ip = g_key_file_get_value(key_file, "meta1", key, &err);

				snprintf(key, 1024, "%d.addr.port", i);
				port = g_key_file_get_integer(key_file, "meta1", key, &err);

			} else {

				snprintf(key, 1024, "%d.addr.ipv6", i);

				if (g_key_file_has_key(key_file, "meta1", key, &err)) {

					m1_info.addr.type = TADDR_V6;

					ip = g_key_file_get_value(key_file, "meta1", key, &err);

					snprintf(key, 1024, "%d.addr.port", i);
					port = g_key_file_get_integer(key_file, "meta1", key, &err);
				}
			}

			addr = build_addr_info(ip, port, &err);
			if (!addr)
				goto errorLabel;

			memcpy(&(m1_info.addr), addr, sizeof(addr_info_t));

			snprintf(key, 1024, "%d.score", i);
			m1_info.score.value = g_key_file_get_integer(key_file, "meta1", key, &err);

			in.s_addr = m1_info.addr.addr.v4;
			DEBUG("Adding meta1 to shm ip(%s) port(%u), score(%d)", inet_ntoa(in), ntohs(m1_info.addr.port), m1_info.score);
			memcpy(data +sizeof(cluster_data_header_t) +i*sizeof(meta1_info_t), &m1_info, sizeof(meta1_info_t));

			g_free(addr);
		}

		release_data(META1_IPC_NAME, data, &err);
	}


	if (g_key_file_has_group(key_file, "meta2") && g_key_file_has_key(key_file, "meta2", "number", &err)) {

		list_size = g_key_file_get_integer(key_file, "meta2", "number", &err);
		data_size = sizeof(cluster_data_header_t) +list_size*sizeof(meta2_info_t);

		data = get_data(META2_IPC_NAME, &err);
		if (data == NULL) {
			if (!release_data(META2_IPC_NAME, data, &err)) {
				ERROR("Release failed : %s", err->message);
				return 1;
			}
			DEBUG("Try to create a new shm");
			data = create_data(META2_IPC_NAME, data_size, &err);
			if (data == NULL) {
				ERROR("Failed to get meta2 data from shm");
				return 1;
			}

		} else if (((cluster_data_header_t *)data)->list_size < list_size) {
			/* We need to recreate a bigger shm */
			DEBUG("Data segment is to small => recreation needed");
			if (!release_data(META2_IPC_NAME, data, &err)) {
				ERROR("Release failed : %s", err->message);
				return 1;
			}

			if (!remove_data(META2_IPC_NAME, &err)) {
				FATAL("Remove failed : %s", err->message);
				return 1;
			}

			if (!release_data(META2_IPC_NAME, NULL, &err)) {
				FATAL("Release failed : %s", err->message);
				return 1;
			}

			data = create_data(META2_IPC_NAME, data_size, &err);
			if (data == NULL) {
				FATAL("Create failed : %s", err->message);
				return 1;
			}
		}

		list = NULL;

		for(i=0; i < list_size; i++) {

			memset(&m2_info, 0, sizeof(meta2_info_t));

			snprintf(key, 1024, "%d.addr.ipv4", i);

			if (g_key_file_has_key(key_file, "meta2", key, &err)) {

				m2_info.addr.type = TADDR_V4;
				ip = g_key_file_get_value(key_file, "meta2", key, &err);

				snprintf(key, 1024, "%d.addr.port", i);
				port = g_key_file_get_integer(key_file, "meta2", key, &err);

			} else {

				snprintf(key, 1024, "%d.addr.ipv6", i);
				if (g_key_file_has_key(key_file, "meta2", key, &err)) {

					m2_info.addr.type = TADDR_V6;
					ip = g_key_file_get_value(key_file, "meta2", key, &err);

					snprintf(key, 1024, "%d.addr.port", i);
					port = g_key_file_get_integer(key_file, "meta2", key, &err);
				}
			}

			addr = build_addr_info(ip, port, &err);
			if (!addr)
				goto errorLabel;

			memcpy(&(m2_info.addr), addr, sizeof(addr_info_t));
			
			snprintf(key, 1024, "%d.score", i);
			m2_info.score.value = g_key_file_get_integer(key_file, "meta2", key, &err);

			list = g_slist_prepend(list, g_memdup(&m2_info, sizeof(meta2_info_t)));

			g_free(addr);
		}

		/* sort the meta list */
		list = g_slist_sort(list, meta2_sort_func);

		header.list_size = list_size;
		header.last_used = 0;
		header.max_score = ((meta2_info_t *)list->data)->score.value;
		header.last_score =  header.max_score;
		memcpy(data, &header, sizeof(cluster_data_header_t));

		for (tmp = list, i = 0; tmp && tmp->data; tmp = tmp->next, i++) {
			mi = (meta2_info_t *)tmp->data;
			in.s_addr = mi->addr.addr.v4;
			DEBUG("Adding meta2 to shm ip(%s) port(%u), score(%d)", inet_ntoa(in), ntohs(mi->addr.port), mi->score.value);
			memcpy(data +sizeof(cluster_data_header_t) +i*sizeof(meta2_info_t), mi, sizeof(meta2_info_t));
		}

		release_data(META2_IPC_NAME, data, &err);
	}

	if (g_key_file_has_group(key_file, "volumes") && g_key_file_has_key(key_file, "volumes", "number", &err)) {

		list_size = g_key_file_get_integer(key_file, "volumes", "number", &err);
		data_size = sizeof(cluster_data_header_t) +list_size*sizeof(volume_info_t);

		data = get_data(VOL_IPC_NAME, &err);
		if (data == NULL) {
			if (!release_data(VOL_IPC_NAME, data, &err)) {
				FATAL("Release failed : %s", err->message);
				return 1;
			}
			DEBUG("Try to create a new shm");
			data = create_data(VOL_IPC_NAME, data_size, &err);
			if (data == NULL) {
				FATAL("Failed to get volume data from shm");
				return 1;
			}

		} else if (((cluster_data_header_t *)data)->list_size < list_size) {
			/* We need to recreate a bigger shm */
			DEBUG("Data segment is to small => recreation needed");
			if (!release_data(VOL_IPC_NAME, data, &err)) {
				FATAL("Release failed : %s", err->message);
				return 1;
			}

			if (!remove_data(VOL_IPC_NAME, &err)) {
				FATAL("Remove failed : %s", err->message);
				return 1;
			}

			if (!release_data(VOL_IPC_NAME, NULL, &err)) {
				FATAL("Release failed : %s", err->message);
				return 1;
			}

			data = create_data(VOL_IPC_NAME, data_size, &err);
			if (data == NULL) {
				FATAL("Create failed : %s", err->message);
				return 1;
			}
		}

		list = NULL;

		for(i=0; i < list_size; i++) {

			memset(&volume_info, 0, sizeof(volume_info_t));

			snprintf(key, 1024, "%d.addr.ipv4", i);

			if (g_key_file_has_key(key_file, "volumes", key, &err)) {

				volume_info.addr.type = TADDR_V4;
				ip = g_key_file_get_value(key_file, "volumes", key, &err);

				snprintf(key, 1024, "%d.addr.port", i);
				port = g_key_file_get_integer(key_file, "volumes", key, &err);

			} else {

				snprintf(key, 1024, "%d.addr.ipv6", i);

				if (g_key_file_has_key(key_file, "volumes", key, &err)) {

					volume_info.addr.type = TADDR_V6;
					ip = g_key_file_get_value(key_file, "volumes", key, &err);

					snprintf(key, 1024, "%d.addr.port", i);
					port = g_key_file_get_integer(key_file, "volumes", key, &err);
				}
			}

			addr = build_addr_info(ip, port, &err);
			if (!addr)
				goto errorLabel;

			memcpy(&(volume_info.addr), addr, sizeof(addr_info_t));

			snprintf(key, 1024, "%d.score", i);
			volume_info.score.value = g_key_file_get_integer(key_file, "volumes", key, &err);

			snprintf(key, 1024, "%d.name", i);
			vol_name = g_key_file_get_value(key_file, "volumes", key, &err);
			memcpy(&(volume_info.name), vol_name, LIMIT_LENGTH_VOLUMENAME);

			list = g_slist_prepend(list, g_memdup(&volume_info, sizeof(volume_info_t)));

			g_free(addr);
		}

		/* sort the vol list */
		list = g_slist_sort(list, vol_sort_func);

		header.list_size = list_size;
		header.last_used = 0;
		header.max_score = ((volume_info_t *)list->data)->score.value;
		header.last_score =  header.max_score;
		memcpy(data, &header, sizeof(cluster_data_header_t));

		for (tmp = list, i = 0; tmp && tmp->data; tmp = tmp->next, i++) {
			vi = (volume_info_t *)tmp->data;
			in.s_addr = vi->addr.addr.v4;
			DEBUG("Adding volume to shm ip(%s) port(%u), score(%d), name(%s)",
					inet_ntoa(in), ntohs(vi->addr.port), vi->score.value, vi->name);
			memcpy(data +sizeof(cluster_data_header_t) +i*sizeof(volume_info_t), vi, sizeof(volume_info_t));
		}

		release_data(VOL_IPC_NAME, data, &err);
	}

	if (g_key_file_has_group(key_file, "namespace")) {

		data = get_data(NS_IPC_NAME, &err);
		if (data == NULL) {
			if (!release_data(NS_IPC_NAME, data, &err)) {
				FATAL("Release failed : %s", err->message);
				return 1;
			}
			DEBUG("Try to create a new shm");
			data = create_data(NS_IPC_NAME, data_size, &err);
			if (data == NULL) {
				FATAL("Failed to get namespace data from shm");
				return 1;
			}

		}

		memset(&ns_info, 0, sizeof(namespace_info_t));

		if (g_key_file_has_key(key_file, "namespace", "name", &err)) {
			memcpy(&(ns_info.name), g_key_file_get_value(key_file, "namespace", "name", &err), LIMIT_LENGTH_NSNAME);
		}

		if (g_key_file_has_key(key_file, "namespace", "chunk_size", &err)) {
			ns_info.chunk_size = g_key_file_get_integer(key_file, "namespace", "chunk_size", &err);
		}

		DEBUG("Setting namespace in shm name(%s) chunk_size(%d)", ns_info.name, ns_info.chunk_size);
		memcpy(data, &ns_info, sizeof(namespace_info_t));

		release_data(NS_IPC_NAME, data, &err);
	}

	return 0;

errorLabel:
	return 1;
}
