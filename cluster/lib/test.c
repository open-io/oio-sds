#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "gridcluster.lib"
#endif

#include <metautils/lib/metautils.h>

#include "./gridcluster.h"

int main(int argc, char **argv) {
	char *ns_name = NULL;
	GSList *service_types, *st;
	GError *err = NULL;

	(void)argc;
	if (log4c_init())
		g_error("Cannot init log4c");

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
