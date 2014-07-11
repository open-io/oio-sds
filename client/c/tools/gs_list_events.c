#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.tools.event.list"
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "../lib/gs_internals.h"
#include "./gs_tools.h"

char *optarg;
int optind, opterr, optopt;

int flag_verbose = 0;
int flag_quiet = 0;
int flag_help = 0;

static gchar ns_name[LIMIT_LENGTH_NSNAME];
static gchar container_name[LIMIT_LENGTH_CONTAINERNAME];

/* ------------------------------------------------------------------------- */

static void
help(int argc, char **args)
{
	(void) argc;
	g_printerr("Usage: %s [OPTION]... NAMESPACE/CONTAINER_NAME\n", args[0]);
	g_printerr("OPTIONS::\n");
	g_printerr("\t -h : displays this help section;\n");
	g_printerr("\t -v : verbose mode, increases debug output;\n");
}

static int
parse_opt(int argc, char **args)
{
	gchar **tokens;
	char *grid_url;
	int opt;

	while ((opt = getopt(argc, args, "hvq")) != -1) {
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
	tokens = g_strsplit(grid_url, "/", 0);
	if (!tokens)
		abort();
	if (g_strv_length(tokens) < 2) {
		PRINT_ERROR("Expected GridUrl as last argument\n");
		return 0;
	}

	g_strlcpy(ns_name, tokens[0], sizeof(ns_name)-1);
	g_strlcpy(container_name, tokens[1], sizeof(ns_name)-1);
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
	bzero(ns_name, sizeof(ns_name));
	bzero(container_name, sizeof(container_name));
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

static gboolean
gba_is_printable(GByteArray *gba)
{
	gsize i;

	g_assert(gba != NULL);
	g_assert(!gba->len || gba->data != NULL);

	for (i=0; i<gba->len ;i++) {
		gchar c = (gchar) gba->data[i];
		if (c && !g_ascii_isspace(c) && !g_ascii_isprint(c))
			return FALSE;
	}
	return TRUE;
}

static void
event_print(container_event_t *ce)
{
	guint i;
	GByteArray *gba;

	g_print("%"G_GINT64_FORMAT" 	| %"G_GINT64_FORMAT" 	| %s 	| %s 	| ", ce->rowid, ce->timestamp, ce->type, ce->ref);
	
	gba = ce->message;
	if (gba_is_printable(gba)) {
		for (i=0; i < gba->len ;i++) {
			gchar c = (gchar) gba->data[i];
			switch (c) {
				case '\0': g_print("\\0"); break;
				case '\t': g_print("\\t"); break;
				case '\n': g_print("\\n"); break;
				case '\r': g_print("\\r"); break;
				default: g_print("%c", c); break;
			}
		}
	}
	else {
		g_print("0x");
		for (i=0; i < gba->len ;i++)
			g_print("%02X", gba->data[i]);
	}

	g_print("\n");
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

	main_install_sighandlers();
	main_set_defaults();
	log4c_init();

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

	gs = gs_grid_storage_init2(ns_name, 5000, 60000, &gserr);
	if (!gs) {
		PRINT_ERROR("Failed to init the GridStorage client : %s\n", gs_error_get_message(gserr));
		goto label_exit;
	}
	gs_grid_storage_set_timeout(gs, GS_TO_RAWX_CNX,  5000, NULL);
	gs_grid_storage_set_timeout(gs, GS_TO_RAWX_OP,  60000, NULL);
	gs_grid_storage_set_timeout(gs, GS_TO_M0_CNX,    5000, NULL);
	gs_grid_storage_set_timeout(gs, GS_TO_M0_OP,    60000, NULL);
	gs_grid_storage_set_timeout(gs, GS_TO_M1_CNX,    5000, NULL);
	gs_grid_storage_set_timeout(gs, GS_TO_M1_OP,    60000, NULL);
	gs_grid_storage_set_timeout(gs, GS_TO_M2_CNX,    5000, NULL);
	gs_grid_storage_set_timeout(gs, GS_TO_M2_OP,    60000, NULL);
	gs_grid_storage_set_timeout(gs, GS_TO_MCD_CNX,   5000, NULL);
	gs_grid_storage_set_timeout(gs, GS_TO_MCD_OP,   60000, NULL);

	/* Ensure the container's name is set */
	if (!*container_name) {
		PRINT_ERROR("Container canot automatically determined : not managed\n");
		goto label_exit_client;
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
	PRINT_DEBUG("META0   : tcp://%s\n", location->m0_url);
	g_print("META1   :");
	for (p=location->m1_url; p && *p ;p++)
		g_print(" tcp://%s", *p);
	g_print("META2   :");
	for (p=location->m2_url; p && *p ;p++)
		g_print(" tcp://%s", *p);
	PRINT_DEBUG("CNAME   : [%s]\n", location->container_name);
	PRINT_DEBUG("CID     : [%s]\n", location->container_hexid);
	
	/* Now Dump the content and its chunks */
	container_id_hex2bin(location->container_hexid, strlen(location->container_hexid), &cid, &gerr);
	metacnx_clear(&m2_ctx);
	if (!metacnx_init_with_url(&m2_ctx, location->m2_url[0], &gerr)) {
		g_print("Invalid meta2 address : %s\n", gerror_get_message(gerr));
	}
	else {
		GSList *last_events = NULL, *l;

		m2_ctx.timeout.cnx = 60000;
		m2_ctx.timeout.req = 60000;
		rc = meta2_remote_list_last_container_events(&m2_ctx, cid, 20, "ALL", "", &last_events, &gerr);
		metacnx_close(&m2_ctx);
		metacnx_clear(&m2_ctx);

		if (last_events) {
			g_print("#Rowid 	| Timestamp 	| Type 	| Ref 	| Message\n");
			g_print("-------------------------------------------------------\n");
			for (l=last_events; l ;l=l->next)
				event_print(l->data);
			g_slist_foreach(last_events, container_event_gclean, NULL);
			g_slist_free(last_events);
		}

		if (!rc)
			PRINT_ERROR("List error : %s\n", gerror_get_message(gerr));
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

