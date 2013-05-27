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

#include <stdlib.h>
#include <metautils.h>
#include <glib.h>

#include "../conscience/grid_definition.h"

static void
dump_ns_info(struct namespace_info_s *ns_info)
{
	gchar str_addr[STRLEN_ADDRINFO];
	GHashTableIter iter;
	gpointer k, v;

	addr_info_to_string(&(ns_info->addr), str_addr, sizeof(str_addr));
	g_print("NS=[%s] CHUNKSIZE=%"G_GINT64_FORMAT" ADDR=[%s]\n", ns_info->name, ns_info->chunk_size, str_addr);
	g_hash_table_iter_init(&iter, ns_info->options);
	while (g_hash_table_iter_next(&iter, &k, &v)) {
		GByteArray *gba = v;
		g_print(" \\ NS_OPT [%s]:[%.*s]\n", (gchar*)k, gba->len, gba->data);
	}
}

static void
dump_services(GSList *services)
{
	GSList *l;
	struct service_info_s *si;
	gchar str_addr[STRLEN_ADDRINFO];
	guint i;
	
	g_print("Got %u services\n", g_slist_length(services));
	for (l=services; l ;l=l->next) {
		si = l->data;
		addr_info_to_string(&(si->addr), str_addr, sizeof(str_addr));
		g_print(" \\ [%s/%s/%s]\n", si->ns_name, si->type, str_addr);
		for (i=0; i < si->tags->len ;i++) {
			struct service_tag_s *tag;
			gchar str_tag[1024];

			tag = si->tags->pdata[i];
			service_tag_to_string(tag, str_tag, sizeof(str_tag));
			g_print("   \\ [%s]:[%s]\n", tag->name, str_tag);
		}
	}
}

int
main(int argc, char **args)
{
	GSList *services = NULL;
	GSList *list_nsnames = NULL, *list_nsinfo=NULL;
	GError *err = NULL;
	struct griddef_cnx_s cnx;
	conscience_db_t *cdb;

	log4c_init();
	if (argc != 5) {
		g_printerr("Invalid args count != 6\n");
		return -1;
	}
	
	cnx.url = args[1];
	cnx.user = args[2];
	cnx.passwd = args[3];
	cnx.db_name = args[4];

	/* try to connect */
	cdb = griddef_init_db_handle(&cnx, &err);
	if (!cdb) {
		g_printerr("DB connection failure : %s\n", err->message);
		goto error_cdb;
	}

	list_nsnames = g_slist_prepend(list_nsnames, "TEST");
	list_nsnames = g_slist_prepend(list_nsnames, "TEST0");

	/* Try to get a namespace */
	if (!griddef_get_nsinfo(cdb, list_nsnames, &list_nsinfo, &err)) {
		g_printerr("Failed to get the namespace_info : %s\n", err->message);
		goto error;
	}
	g_slist_foreach(list_nsinfo, (GFunc)dump_ns_info, NULL);
	g_slist_foreach(list_nsinfo, namespace_info_gclean, NULL);
	g_slist_free(list_nsinfo);
	
	if (!griddef_get_extended_nsinfo(cdb, list_nsnames, &list_nsinfo, &err)) {
		g_printerr("Failed to extend the namespace_info with its options : %s\n", err->message);
		goto error;
	}
	g_slist_foreach(list_nsinfo, (GFunc)dump_ns_info, NULL);
	g_slist_foreach(list_nsinfo, namespace_info_gclean, NULL);
	g_slist_free(list_nsinfo);

	/* Try to get services */
	if (!griddef_load_services_by_address(cdb, "10.26.95.15", &services, &err)) {
		g_printerr("Failed to get services for IP=10.26.95.15 : %s\n", err->message);
		return -1;
	}
	dump_services(services);
	g_slist_foreach(services, service_info_gclean, NULL);
	g_slist_free(services);

	/* alright... */
	griddef_close_db_handle(cdb);
	log4c_fini();
	return 0;
	
error:
	griddef_close_db_handle(cdb);
error_cdb:
	log4c_fini();
	return -1;
}

