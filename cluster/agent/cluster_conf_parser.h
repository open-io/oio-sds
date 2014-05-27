#ifndef _CLUSTER_CONF_PARSER_H
#define _CLUSTER_CONF_PARSER_H

#include <glib.h>

#include <cluster/agent/agent.h>

int parse_cluster_conf(const char *file_path, namespace_data_t *ns_data, GError **error);

#endif	/* _CLUSTER_CONF_PARSER_H */
