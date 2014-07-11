#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.tools.event.set"
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <search.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <meta2/remote/meta2_services_remote.h>

#include "../lib/grid_client.h"
#include "../lib/gs_internals.h"
#include "./gs_tools.h"

char *optarg;
int optind, opterr, optopt;

char *meta0_url = NULL;
char *container_name = NULL;
char *event_message = NULL;

static int flag_help = 0;
int flag_verbose = 0;
int flag_quiet = 0;


static void
help(void)
{
	g_printerr("usage: %s [OPTIONS...] [VALUE]\n", g_get_prgname());
	g_printerr("Description:\n");
	g_printerr("\tComing soon...\n");
	g_printerr("Options:\n");
	g_printerr("\t -h : displays this help section\n");
	g_printerr("\t -q : quiet mode, no output\n");
	g_printerr("\t -v : increase the verbosity\n");
	g_printerr("\t -m <URL> : provides the URL to the namespace META0\n");
	g_printerr("\t -d <TOKEN> : the name of the container\n");
}


static int
parse_opt(int argc, char **args)
{
	int opt;

	while ((opt = getopt(argc, args, "hqvm:d:")) != -1) {
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

		case '?':
		default:
			break;
		}
	}

	if (optind < argc)
		event_message = g_strdup(args[optind]);

	return 1;
}

static int
add_event(gs_grid_storage_t * gs, const char *cName, const char *msg)
{
	int rc = -1;
	gs_error_t **gserr = NULL;
	gs_error_t *locerr = NULL;
	struct gs_container_location_s *location = NULL;
	container_id_t cid;
	struct metacnx_ctx_s cnx;
	gchar *hexid = NULL;
	gchar * meta2_url = NULL;
	GError *gerr = NULL;

	metacnx_clear(&cnx);
	if (!gs || !cName || !msg) {
		PRINT_ERROR("Invalid parameter (%p %p %p)\n", gs, cName, msg);
		return rc;
	}

	location = gs_locate_container_by_name(gs, cName, &locerr);
	if (!location) {
		PRINT_ERROR("cannot find %s\n", cName);
		goto exit_label;
	}
	if (!location->m0_url || !location->m1_url || !location->m2_url || !location->m2_url[0]) {
		PRINT_ERROR("cannot find %s\n", cName);
		goto exit_label;
	}
	PRINT_DEBUG("%s found\n", cName);
	hexid = location->container_hexid;
	meta2_url = location->m2_url[0];
	if (!container_id_hex2bin(hexid, strlen(hexid), &cid, &gerr)) {
		GSERRORCAUSE(gserr, gerr, "Invalid container id");
		goto exit_label;
	}

	if (!metacnx_init_with_url(&cnx, meta2_url, &gerr)) {
		GSERRORCAUSE(gserr, gerr, "Invalid META2 address");
		goto exit_label; 
	}

	container_event_t event;
	bzero(&event, sizeof(event));
	event.timestamp = time(0);
	g_strlcpy(event.type, "test", sizeof(event.type));
	g_strlcpy(event.ref, "test", sizeof(event.type));
	event.message = metautils_gba_from_string(msg);

	PRINT_DEBUG("Adding event [%s]", msg);
	rc = meta2_remote_add_container_event(&cnx, cid, &event, &gerr);

	g_byte_array_free(event.message, TRUE);
	event.message = NULL;

	metacnx_close(&cnx);
	metacnx_clear(&cnx);

	if (!rc) {
		PRINT_ERROR("Failed to add event : %s\n", gerror_get_message(gerr));
		g_clear_error(&gerr);
	}

exit_label:
	return rc;
}
	
int
main(int argc, char **args)
{
	int rc = ~0;
	gs_error_t *err = NULL;
	gs_grid_storage_t *gs = NULL;

	g_set_prgname(args[0]);
	log4c_init();

	if (!parse_opt(argc, args)) {
		PRINT_ERROR("cannot parse the options\n");
		return 1;
	}

	if (flag_help || argc == 1) {
		help();
		return 0;
	}

	if (!meta0_url || !container_name) {
		meta0_url = strtok(args[1], "/");
		container_name = strtok(NULL, "/");
		event_message = args[2];		

		if (!meta0_url || !container_name) {
                	PRINT_ERROR("Missing argument, please check help (-h) for more informations\n");
                	return 1;
        	}
	}

	if (!event_message) {
		PRINT_ERROR("Missing argument, please check help (-h) for more informations\n");
                return 1;
	}

	gs = gs_grid_storage_init(meta0_url, &err);
	if (!gs)
		PRINT_ERROR("cannot init the GridStorage client\n");
	else
		rc = add_event(gs, container_name, event_message) ? 0 : 1;

	return rc;
}

