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
	GSList *srv_list = NULL, *le = NULL;

	log4c_init();

	srv_list = list_services(&error);
	if (srv_list == NULL && error) {
		g_printerr("Failed to get service list");
		g_printerr("%s\n", error->message);
		return(-1);
	}

	for (le = srv_list; le && le->data; le = le->next) {
		g_print("%s\n", le->data);
		g_free(le->data);
	}

	g_slist_free(srv_list);

	return 0;
}
