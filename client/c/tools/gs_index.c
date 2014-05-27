#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.tools.index"
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../lib/grid_client.h"
#include "./gs_tools.h"

#define GS_CAT "gs_cat"
#define GS_GET "gs_get"

enum action_e
{ A_NOTSET, A_LISTSRV, A_LISTCONTENT, A_CONTAINER_LIST, A_CONTAINER_GET };

char *optarg;
int optind, opterr, optopt;

char *meta0_url = NULL;
char *container_name = NULL;
int flag_verbose = 0;
int flag_quiet = 0;

static char *remote_path = NULL;
static int flag_help = 0;
static enum action_e action = A_NOTSET;

static gint debug_level = 0;

static void
debug(const gchar *fmt, ...)
{
	va_list va;
	gchar *msg;

	if (debug_level < 1)
		return;

	va_start(va, fmt);
	msg = g_strdup_vprintf(fmt, va);
	va_end(va);

	if (msg) {
		g_print("%s", msg);
		g_free(msg);
	}
}

static void
help(void)
{
	g_printerr("Description:\n");
	g_printerr("\tGridStorage Indexes management utility\n");
	g_printerr("\tGet indexes on contents\n");
	g_printerr("Miscellaneous options:\n");
	g_printerr("\t -h : displays this help section;\n");
	g_printerr("\t -q : quiet mode, reduces the verbosity to its minimum;\n");
	g_printerr("\t -v : verbose mode, increases debug output;\n");
	g_printerr("Mandatory options:\n");
	g_printerr("\t -m <URL> : provides the URL to the namespace META0;\n");
	g_printerr("\t -d <TOKEN> : the name of the container;\n");
	g_printerr("Action options (if more than one, only the last on command line will be taken into account):\n");
	g_printerr("\t -l : list all the index services used for the given service type;\n");
	g_printerr("\t -c <TOKEN> : get the service used for the given content path;\n");
	g_printerr("\t -L : List all the services used, container-widely\n");
	g_printerr("\t -G : Get an available service for the whole container\n");
}

static int
conf_check(void)
{
	if (flag_quiet)
		flag_verbose = 0;
	if (!meta0_url) {
		PRINT_ERROR("no namespace URL configured (use -m option of " ENV_META0URL " environment variable)\n");
		return 0;
	}
	if (!container_name) {
		PRINT_ERROR("no container name configured (use -d option or "
			ENV_CONTAINER " environment variable)\n");
		return 0;
	}
	if (action==A_LISTCONTENT && !remote_path) {
		PRINT_ERROR("no remote path configured (use -f option)\n");
		return 0;
	}

	PRINT_DEBUG("remote_path=%s container=%s namespace=%s\n", remote_path, container_name, meta0_url);

	return 1;
}

static int
parse_opt(int argc, char **args)
{
	int opt;

	while ((opt = getopt(argc, args, "hvqlLGm:c:d:")) != -1) {
		switch (opt) {

		case 'h':
			flag_help = ~0;
			break;

		case 'v':
			flag_verbose++;
			break;

		case 'q':
			flag_quiet = ~0;
			break;

		case 'G':
			action = A_CONTAINER_GET;
			break;
		case 'L':
			action = A_CONTAINER_LIST;
			break;
		case 'l':
			action = A_LISTSRV;
			break;

		case 'm':
			/*meta0 url */
			IGNORE_ARG('m');
			if (meta0_url)
				free(meta0_url);
			meta0_url = strdup(optarg);
			break;
		case 'd':
			/*container info */
			IGNORE_ARG('d');
			if (container_name)
				free(container_name);
			container_name = strdup(optarg);
			break;

		case 'c':
			/*remote source path */
			IGNORE_ARG('c');
			if (remote_path)
				free(remote_path);
			remote_path = strdup(optarg);
			action = A_LISTCONTENT;
			break;

		case '?':
		default:
			PRINT_ERROR("unexpected %c (%s)\n", optopt, strerror(opterr));
			return 0;
		}
	}

	return 1;
}

#include <signal.h>

static void
sig_pipe(int s)
{
	(void)s;
	signal(SIGPIPE, sig_pipe);
}

static int
list_services_for_path(gs_container_t *container, gs_error_t **err, char *path)
{
	int i;
	size_t str_url_len;
	char str_url[256];
	gs_service_t **all_services, **current_service;
	char **paths;

	paths = calloc(2,sizeof(char*));
	paths[0] = path;
	all_services = gs_index_get_services_for_paths(container, paths, err);
	free(paths);

	if (!all_services)
		return -1;

	debug("# services for [%s]: %d\n", remote_path, g_strv_length((gchar**)all_services));
	for (current_service=all_services; *current_service ;current_service++) {
		str_url_len = gs_service_get_url(*current_service,str_url,sizeof(str_url));
		i = str_url_len;
		g_print("%.*s\n", i, str_url);
	}
	debug("# end of services\n");
	gs_service_free_array(all_services);

	return 0;
}

static int
list_services_used(gs_container_t *container, gs_error_t **err)
{
	int i;
	size_t str_url_len;
	char str_url[256];
	gs_service_t **all_services, **current_service;

	all_services = gs_index_get_all_services_used(container, err);
	if (!all_services)
		return -1;

	debug("# services used by [%s] : %d\n", container_name, g_strv_length((gchar**)all_services));
	for (current_service=all_services; *current_service ;current_service++) {
		str_url_len = gs_service_get_url(*current_service,str_url,sizeof(str_url));
		i = str_url_len;
		g_print("%.*s\n", i, str_url);
	}
	debug("# end of services\n");
	gs_service_free_array(all_services);

	return 0;
}

static int
get_service_for_container(gs_container_t *container, gs_error_t **err)
{
	int i;
	size_t str_url_len;
	char str_url[256];
	gs_service_t **all_services, **current_service;

	all_services = gs_container_service_get_available(container, "solr", err);
	if (!all_services)
		return -1;

	debug("# services available for container [%s] : %u\n", container_name, g_strv_length((gchar**)all_services));
	for (current_service=all_services; *current_service ;current_service++) {
		str_url_len = gs_service_get_url(*current_service,str_url,sizeof(str_url));
		i = str_url_len;
		g_print("%.*s\n", i, str_url);
	}
	debug("# end of services\n");
	gs_service_free_array(all_services);

	return 0;
}

static int
list_services_used_by_container(gs_container_t *container, gs_error_t **err)
{
	int i;
	size_t str_url_len;
	char str_url[256];
	gs_service_t **all_services, **current_service;

	all_services = gs_container_service_get_all(container, "solr", err);
	if (!all_services)
		return -1;

	debug("# services currently used by container [%s] : %u\n", container_name, g_strv_length((gchar**)all_services));
	for (current_service=all_services; *current_service ;current_service++) {
		str_url_len = gs_service_get_url(*current_service,str_url,sizeof(str_url));
		i = str_url_len;
		g_print("%.*s\n", i, str_url);
	}
	debug("# end of services\n");
	gs_service_free_array(all_services);

	return 0;
}

int
main(int argc, char **args)
{
	int rc;
	gs_error_t *err = NULL;
	gs_grid_storage_t *gs = NULL;
	gs_container_t *container = NULL;

	signal(SIGPIPE, sig_pipe);

	if (argc <= 1) {
		help();
		return 1;
	}

	if (!parse_opt(argc, args)) {
		PRINT_ERROR("Cannot parse the arguments\n");
		help();
		return 1;
	}

	if (!conf_check()) {
		PRINT_ERROR("Missing parameters\n");
		help();
		return 1;
	}

	/*open the connection to the META0 */
	gs = gs_grid_storage_init(meta0_url, &err);
	if (!gs) {
		PRINT_ERROR("grid storage error : cannot init the namespace configuration from %s\n", meta0_url);
		return -1;
	}
	PRINT_DEBUG("Connected to the GridStorage namespace %s\n", meta0_url);

	/*find the container */
	container = gs_get_container(gs, container_name, 0, &err);
	if (!container) {
		PRINT_ERROR("grid storage error : cannot find the container %s : %s\n",
			container_name, err->msg);
		gs_grid_storage_free(gs);
		return -1;
	}
	PRINT_DEBUG("container %s found\n", container_name);

	switch (action) {
	case A_CONTAINER_GET:
		rc = get_service_for_container(container,&err);
		if (rc != 0)
			PRINT_ERROR("Failed to list the index services used in container [%s] : %s\n",
				container_name, gs_error_get_message(err));
		break;
	case A_CONTAINER_LIST:
		rc = list_services_used_by_container(container,&err);
		if (rc != 0)
			PRINT_ERROR("Failed to list the index services used in container [%s] : %s\n",
				container_name, gs_error_get_message(err));
		break;
	case A_LISTSRV:
		rc = list_services_used(container,&err);
		if (rc != 0)
			PRINT_ERROR("Failed to list the index services used in container [%s] : %s\n",
				container_name, gs_error_get_message(err));
		break;
		
	case A_LISTCONTENT:
		rc = list_services_for_path(container,&err, remote_path);
		if (rc != 0)
			PRINT_ERROR("Failed to list the index services used in container [%s] for path [%s] : %s\n",
				container_name, remote_path, gs_error_get_message(err));
		break;

	default:
		PRINT_ERROR("Action not set, please provide at least '-l' or '-c'\n");
		rc = -1;
		break;
	}

	gs_container_free(container);
	gs_grid_storage_free(gs);
	return 0;
}

