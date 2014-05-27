#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.tools.touch"
#endif

#include <assert.h>
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

#include <signal.h>

#include <glib.h>

#include <metautils/lib/metatypes.h>
#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include "../lib/grid_client.h"
#include "../lib/gs_internals.h"
#include "./gs_tools.h"

char *optarg;
int optind, opterr, optopt;

int flag_verbose = 0;
int flag_quiet = 0;
int flag_help = 0;
int flag_update_csize = 0;

static gchar ns_name[LIMIT_LENGTH_NSNAME];
static gchar container_name[LIMIT_LENGTH_CONTAINERNAME];
static gchar content_path[LIMIT_LENGTH_CONTENTPATH];

/* ------------------------------------------------------------------------- */

static void
help(int argc, char **args)
{
	(void) argc;
	g_printerr("Usage: %s [OPTION]... GRIDURL\n", args[0]);
	g_printerr("OPTION::\n");
	g_printerr("\t -h : displays this help section;\n");
	g_printerr("\t -v : verbose mode, increases debug output;\n");
	g_printerr("\t -u : force an update container size --> meta1(s)\n");
	g_printerr("GRIDURL:\n");
	g_printerr("\t NS/CONTAINER/CONTENT\n");
}

static int
parse_opt(int argc, char **args)
{
	gchar **tokens;
	char *grid_url;
	int opt;

	while ((opt = getopt(argc, args, "hvqu")) != -1) {
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
		case 'u':
			flag_update_csize = ~0;
			break;			
		case '?':
		default:
			PRINT_ERROR("unexpected %c (%s)\n", optopt, strerror(opterr));
			return 0;
		}
	}

	if (optind >= argc) {
		PRINT_ERROR("Expected GridUrl as last argument\n");
		return 0;
	}
	
	grid_url = args[optind];
	tokens = g_strsplit(grid_url, G_DIR_SEPARATOR_S, 0);
	g_assert(tokens != NULL);

	guint len;
	switch (len = g_strv_length(tokens)) {
		case 0:
		case 1:
			PRINT_ERROR("Expected GridUrl as last argument\n");
			g_strfreev(tokens);
			return 0;
		case 2:
			PRINT_DEBUG("Grid URL has %u tokens\n", len);
			g_strlcpy(ns_name, tokens[0], sizeof(ns_name)-1);
			g_strlcpy(container_name, tokens[len-1], sizeof(container_name)-1);
			break;
		default:
			PRINT_DEBUG("Grid URL has %u tokens\n", len);
			g_strlcpy(ns_name, tokens[0], sizeof(ns_name)-1);
			do { /* Join the tokens between the forst and the last */
				gchar *s, *tmp;
				s = tokens[len-1];
				tokens[len-1] = NULL;
				tmp = g_strjoinv(G_DIR_SEPARATOR_S, tokens+1);
				g_assert(tmp != NULL);
				tokens[len-1] = s;
				g_strlcpy(container_name, tmp, sizeof(container_name)-1);
				g_free(tmp);
			} while (0);
			g_strlcpy(content_path, tokens[len-1], sizeof(content_path)-1);
			break;
	}
	
	g_strfreev(tokens);
	return 1;
}

static void
main_sighandler_quit(int s)
{
	signal(s, main_sighandler_quit);
}

static void
main_sighandler_noop(int s)
{
	signal(s, main_sighandler_noop);
}

static void
main_sighandler_sigpipe(int s)
{
	signal(s, main_sighandler_sigpipe);
}

static void
main_install_sighandlers(void)
{
	signal(SIGUSR1, main_sighandler_noop);
	signal(SIGUSR2, main_sighandler_noop);
	signal(SIGINT, main_sighandler_quit);
	signal(SIGQUIT, main_sighandler_quit);
	signal(SIGKILL, main_sighandler_quit);
	signal(SIGSTOP, main_sighandler_quit);
	signal(SIGPIPE, main_sighandler_sigpipe);
}

static void
main_set_defaults(void)
{
	flag_verbose = 0;
	flag_quiet = 0;
	flag_help = 0;
	flag_update_csize = 0;
	bzero(ns_name, sizeof(ns_name));
	bzero(container_name, sizeof(container_name));
	bzero(content_path, sizeof(content_path));
}

static status_t
gs_get_autocontainer(gs_grid_storage_t *gs,
	const gchar *cpath, gsize cpath_size,
	gchar *cname, gsize cname_size,
	gs_error_t **gserr)
{
	(void) gs;
	(void) cpath;
	(void) cpath_size;
	(void) cname;
	(void) cname_size;
	GSERRORSET(gserr, "Not yet implemented");
	return GS_ERROR;
}

static gboolean
str_is_hexid(const gchar *str)
{
	const gchar *s;
	if (!str || !*str)
		return FALSE;
	for (s=str; *s ;s++) {
		if (!g_ascii_isxdigit(*s)) {
			PRINT_DEBUG("non-xdigit character found : %c", *s);
			return FALSE;
		}
	}
	if ((s-str) == 64)
		return TRUE;

	PRINT_DEBUG("Invalid string length : %"G_GSIZE_FORMAT, (s-str));
	return FALSE;
}

int
main(int argc, char **args)
{
	int rc = -1;
	gs_error_t *gserr = NULL;
	gs_grid_storage_t *gs = NULL;
	struct gs_container_location_s *location = NULL;
	struct metacnx_ctx_s m2_ctx;
	GError *gerr = NULL;
	container_id_t cid;
	guint32 flags = 0;

	main_install_sighandlers();
	main_set_defaults();

	if (argc <= 1) {
		help(argc, args);
		return 1;
	}
	if (!parse_opt(argc, args)) {
		help(argc, args);
		return 1;
	}
	if (flag_help) {
		help(argc, args);
		return 0;
	}

	if (flag_update_csize) {
		flags = META2TOUCH_FLAGS_UPDATECSIZE;
	}

	gs = gs_grid_storage_init2(ns_name, 5000, 60000, &gserr);
	if (!gs) {
		PRINT_ERROR("Failed to init the GridStorage client : %s\n", gs_error_get_message(gserr));
		goto label_exit;
	}
	gs_grid_storage_set_timeout(gs, GS_TO_RAWX_CNX, 30000, NULL);
	gs_grid_storage_set_timeout(gs, GS_TO_RAWX_OP,  60000, NULL);
	gs_grid_storage_set_timeout(gs, GS_TO_M0_CNX,   30000, NULL);
	gs_grid_storage_set_timeout(gs, GS_TO_M0_OP,    60000, NULL);
	gs_grid_storage_set_timeout(gs, GS_TO_M1_CNX,   30000, NULL);
	gs_grid_storage_set_timeout(gs, GS_TO_M1_OP,    60000, NULL);
	gs_grid_storage_set_timeout(gs, GS_TO_M2_CNX,   30000, NULL);
	gs_grid_storage_set_timeout(gs, GS_TO_M2_OP,    60000, NULL);
	gs_grid_storage_set_timeout(gs, GS_TO_MCD_CNX,  30000, NULL);
	gs_grid_storage_set_timeout(gs, GS_TO_MCD_OP,   60000, NULL);

	/* Ensure the container's name is set */
	if (!*container_name) {
		gs_status_t status;

		if (!*content_path) {
			PRINT_ERROR("Container cannot automatically determined : %s\n", "no content path");
			goto label_exit_client;
		}
		
		status = gs_get_autocontainer(gs, content_path, strlen(content_path),
				container_name, sizeof(container_name), &gserr);
		if (status != GS_OK) {
			PRINT_ERROR("Container cannot automatically determined : %s\n", gs_error_get_message(gserr));
			goto label_exit_client;
		}
	}

	/* Locate the container */
	if (str_is_hexid(container_name)) {
		PRINT_DEBUG("Considering %s is a hexidecimal container id\n", container_name);
		location = gs_locate_container_by_hexid(gs, container_name, &gserr);
	}
	else {
		PRINT_DEBUG("Considering %s is a regular container id\n", container_name);
		location = gs_locate_container_by_name(gs, container_name, &gserr);
	}

	if (!location) {
		PRINT_ERROR("Container reference not resolvable : %s\n", gs_error_get_message(gserr));
		goto label_exit_client;
	}
	if (!location->m0_url || !location->m1_url || !location->m2_url || !location->m2_url[0]) {
		PRINT_ERROR("Container reference partially missing (%p %p %p): %s\n",
			location->m0_url, location->m1_url, location->m2_url, gs_error_get_message(gserr));
		goto label_exit_location;
	}

	gchar **p;

	g_print("META0   : tcp://%s\n", location->m0_url);
	g_print("META1   :");
	for (p=location->m1_url; p && *p ;p++)
		g_print(" tcp://%s", *p);
	g_print("\n");
	g_print("META2   :");
	for (p=location->m2_url; p && *p ;p++)
		g_print(" tcp://%s", *p);
	g_print("\n");
	g_print("CNAME   : [%s]\n", location->container_name);
	g_print("CID     : [%s]\n", location->container_hexid);
	
	/* Now Dump the content and its chunks */
	container_id_hex2bin(location->container_hexid, strlen(location->container_hexid), &cid, &gerr);
	metacnx_clear(&m2_ctx);
	if (!metacnx_init_with_url(&m2_ctx, location->m2_url[0], &gerr)) {
		g_print("Invalid meta2 address : %s\n", gerror_get_message(gerr));
	}
	else {
		m2_ctx.timeout.cnx = 60000;
		m2_ctx.timeout.req = 60000;
		rc = *content_path != '\0'
			? meta2_remote_touch_content(&m2_ctx, cid, content_path, &gerr)
			: meta2_remote_touch_container_ex(&m2_ctx, cid, flags, &gerr) ;
		metacnx_close(&m2_ctx);
		metacnx_clear(&m2_ctx);

		if (rc)
			g_print("TOUCH DONE  for [%s/%s] : %s\n", location->container_hexid,
					content_path, gerror_get_message(gerr));
		else
			g_print("TOUCH ERROR for [%s/%s] : %s\n", location->container_hexid,
					content_path, gerror_get_message(gerr));
	}
	if (gerr)
		g_clear_error(&gerr);
	rc = rc ? 0 : 1;

label_exit_location:
	gs_container_location_free(location);
label_exit_client:
	gs_grid_storage_free(gs);
label_exit:
	if (gserr)
		gs_error_free(gserr);
	return rc;
}

