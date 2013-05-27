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
# define LOG_DOMAIN "gridcluster.remote"
#endif
#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <metautils.h>

#include "./gridcluster_remote.h"

static void print_volumes(gpointer data, gpointer user_data)
{
	char buff[512];
	(void)user_data;
	memset(buff, '\0', sizeof(buff));
	volume_info_to_string((volume_info_t *)data, buff, sizeof(buff));
	fprintf(stdout, "Volume info : %s\n", buff);
}

static void print_meta2(gpointer data, gpointer user_data)
{
	char buff[512];
	(void)user_data;
	memset(buff, '\0', sizeof(buff));
	meta2_info_to_string((meta2_info_t *)data, buff, sizeof(buff));
	fprintf(stdout, "Meta2 info : %s\n", buff);
}

int main(int argc, char **argv) {
	char *addr_str = NULL;
	char *port_str = NULL;
	int port;
	(void)argc;
	GSList *volumes = NULL, *meta2 = NULL;
	addr_info_t *addr;
	GError *error = NULL;
	volume_stat_t *vstat = NULL;
	meta2_stat_t *mstat = NULL;

	log4c_init();

	addr_str = argv[1];
	port_str = argv[2];

	if (!addr_str || !port_str) {
		fprintf(stderr, "\nUsage : %s <conscience addr> <conscience port>\n\n", argv[0]);
		return(-1);
	}

	port = atoi(port_str);
	addr = build_addr_info(addr_str, port, &error);
	if (addr == NULL) {
		fprintf(stderr, "\nERROR : Failed to build addr_info : %s\n\n", error->message);
		return(-1);
	}

	volumes = gcluster_get_volume_list(addr, 500000, &error);
	if (volumes == NULL && error) {
		fprintf(stderr, "\nERROR : Failed to get volume list : %s\n\n", error->message);
		return(-1);
	}

	g_slist_foreach(volumes, print_volumes, NULL);

	meta2 = gcluster_get_meta2_list(addr, 5000, &error);
	if (meta2 == NULL && error) {
		fprintf(stderr, "\nERROR : Failed to get meta2 list : %s\n\n", error->message);
		return(-1);
	}

	g_slist_foreach(meta2, print_meta2, NULL);

	vstat = g_try_new0(volume_stat_t, 1);
	if (vstat == NULL) {
		fprintf(stderr, "\nERROR : Allocation failure\n\n");
		return(-1);
	}

	memcpy(&(vstat->info), volumes->data, sizeof(volume_info_t));
	vstat->cpu_idle = 90;
	vstat->io_idle = 80;
	vstat->free_chunk = 10;

	if (!gcluster_push_volume_stat(addr, 5000, g_slist_append(NULL, vstat), &error)) {
		fprintf(stderr, "\nERROR : Failed to push volume_stat : %s\n\n", error->message);
		return(-1);
	}

	mstat = g_try_new0(meta2_stat_t, 1);
	if (mstat == NULL) {
		fprintf(stderr, "\nERROR : Allocation failure\n\n");
		return(-1);
	}

	memcpy(&(mstat->info), meta2->data, sizeof(meta2_info_t));
	mstat->req_idle = 12;

	if (!gcluster_push_meta2_stat(addr, 5000, g_slist_append(NULL, mstat), &error)) {
		fprintf(stderr, "\nERROR : Failed to push meta2_stat : %s\n\n", error->message);
		return(-1);
	}

//	char *container = "454E61A0DAB08CF26FC86A9CE002C9F1ADDD82259ABC4191BD0DEBDCE5AFB163:/path/to/content:GET";
	char *container = "454E61A0DAB08CF26FC86A9CE002C9F1ADDD82259ABC4191BD0DEBDCE5AFB163";

	if (!gcluster_push_broken_container(addr, 5000, g_slist_append(NULL, container), &error)) {
		fprintf(stderr, "\nERROR : Failed to push broken container : %s\n\n", error->message);
		return(-1);
	}

	GSList *containers = NULL;
	containers = gcluster_get_broken_container(addr, 5000, &error);
	if (!containers) {
		fprintf(stderr, "\nERROR : Failed to retreive broken containers : %s\n\n", error->message);
		return(-1);
	} else if (0 != strcmp(container, (char*)containers->data)) {
		fprintf(stderr, "\nERROR : Failed to retreive sent broken container : %s/%s\n\n", container, (char*)containers->data);
		return(-1);
	}

	g_free(addr);

	return(0);
}
