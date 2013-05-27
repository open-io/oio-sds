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
# define LOG_DOMAIN "gridcluster.tools"
#endif
#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <metautils.h>

#include "gridcluster.h"

extern void meta2_info_gclean (gpointer d, gpointer u);
extern void volume_info_gclean (gpointer d, gpointer u);

int main(int argc, char **argv) {
	GError *error = NULL;
	namespace_info_t *ns = NULL;
	meta2_info_t *m2 = NULL;
	volume_info_t *vol = NULL;
	char *ns_name = NULL;
	GSList *volumes = NULL;
	GSList *meta2 = NULL;
	GList *le = NULL;

	ns_name = argv[1];
	if (ns_name == NULL) {
		g_printerr("Missing namespace name\n");
		g_printerr("Usage : %s <ns_name>\n", argv[0]);
		return(-1);
	}

	ns = get_namespace_info(ns_name, &error);
	if (ns == NULL) {
		g_printerr("Failed to get namespace info :\n");
		g_printerr("%s\n", error->message);
		return(-1);
	}

	volumes = list_volumes(ns_name, &error);
	if (volumes == NULL && error) {
		g_printerr("Failed to get volume list :\n");
		g_printerr("%s\n", error->message);
		return(-1);
	}

	meta2 = list_meta2(ns_name, &error);
	if (meta2 == NULL && error) {
		g_printerr("Failed to get meta2 list");
		g_printerr("%s\n", error->message);
		return(-1);
	}

	g_print("\n\n");
	g_print("NAMESPACE INFORMATION for [%s]\n", ns_name);
	g_print("\n");
	g_print("%20s : %s\n", "Name", ns->name);
	g_print("%20s : %d bytes\n", "Chunk size", ns->chunk_size);
	g_print("\n");

	if (meta2) {
		g_print("-- META2 --\n");
		g_print("%20s\t%4s\n", "Addr", "Score");
		for (le = (GList*)meta2; le && le->data; le = le->next) {
			char str[255];
			memset(str, '\0', sizeof(str));
			m2 = (meta2_info_t*)le->data;
			addr_info_to_string (&(m2->addr), str, sizeof(str));
			g_print("%20s\t%4li\n", str, m2->score.value);
		}
		g_print("\n");
	}

	if (volumes) {
		g_print("-- VOLUMES --\n");
		g_print("%16s\t%20s\t%4s\n", "Name", "Addr", "Score");
		for (le = (GList*)volumes; le && le->data; le = le->next) {
			char str[255];
			memset(str, '\0', sizeof(str));
			vol = (volume_info_t*)le->data;
			addr_info_to_string (&(vol->addr), str, sizeof(str));
			g_print("%16s\t%20s\t%4li\n", vol->name, str, vol->score.value);
		}
	}
	g_print("\n\n");

	namespace_info_free(ns);
	g_slist_foreach(meta2, meta2_info_gclean, NULL);
	g_slist_free(meta2);
	g_slist_foreach(volumes, volume_info_gclean, NULL);
	g_slist_free(volumes);

	return 0;
}
