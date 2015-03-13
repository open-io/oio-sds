/*
OpenIO SDS cluster
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "gridcluster.lib"
#endif

#include <metautils/lib/metautils.h>

#include "./gridcluster.h"

int main(int argc, char **argv) {
	char *ns_name = NULL;
	GSList *service_types, *st;
	GError *err = NULL;

	HC_PROC_INIT(argv,GRID_LOGLVL_DEBUG);
	(void)argc;

	ns_name = argv[1];
	if (ns_name == NULL) {
		g_printerr("No namespace specified\n");
		g_printerr("Usage : %s <ns_name>\n", argv[0]);
		return(-1);
	}

	if (get_namespace_info(ns_name, &err) == NULL) {
		FATAL("Failed : %s", err->message);
		return(-1);
	}

	if (!(service_types = list_namespace_service_types(ns_name, &err))) {
		FATAL("Failed : %s", err->message);
		return(-1);
	}

	for (st=service_types; st ;st=st->next) {
		if (list_namespace_services(ns_name, st->data, &err) == NULL) {
			FATAL("Failed : %s", err->message);
			return(-1);
		}
	}

	return(0);
}
