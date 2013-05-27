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

#include <glib.h>
#include <metautils.h>
#include "./gridcluster_eventhandler.h"

gboolean address_forward (gridcluster_event_t *event, gpointer udata, gpointer edata, GError **err, const addr_info_t *a )
{
	(void)event;
	(void)udata;
	(void)edata;
	(void)err;
	(void)a;
	g_printerr("address forwarding\n");
	return TRUE;
}

gboolean service_forward (gridcluster_event_t *event, gpointer udata, gpointer edata, GError **err, const gchar *s )
{
	(void)event;
	(void)udata;
	(void)edata;
	(void)err;
	(void)s;
	g_printerr("service forwarding\n");
	return TRUE;
}

int main( int argc, char ** args )
{
	GError *localError=NULL;
	gridcluster_event_handler_t *event_handler;
	GSList *patterns=NULL, *p;


	gchar *data=NULL;
	gsize data_size=0;
	
	if (argc<2) {
		g_printerr("Usage: %s PATH\n", args[0]);
		return -1;
	}

	event_handler = gridcluster_eventhandler_create( "TEST", &localError, NULL, NULL);
	if (!event_handler) {
		g_printerr("Failed to init an EventHandler : %s\n",
			localError->message );
		return -1;
	}

	if (!g_file_get_contents(args[1], &data, &data_size, &localError)) {
		g_printerr("Failed to load the content of [%s] : %s\n", args[1],
			localError->message );
		return -1;
	}

	if (!gridcluster_eventhandler_configure( event_handler, data,
			data_size, &localError ))
	{
		g_printerr("Failed to configure the EventHandler with the content"
			" of [%s] : %s\n", args[1], localError->message );
		return -1;
	}

	patterns = gridcluster_eventhandler_get_patterns( event_handler, &localError );
	if (!patterns && localError) {
		g_printerr("Failed to get the patterns managed by this event_handler : %s",
			localError->message);
		return -1;
	}

	for (p=patterns; p ;p=p->next)
		g_print("Pattern: %s\n", (char*)p->data);

	return 0;
}

