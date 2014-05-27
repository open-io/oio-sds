#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.meta2-mover"
#endif

#include <stdio.h>

#include <grid_client.h>

#include <metautils/lib/metautils.h>
#include <meta1v2/meta1_remote.h>
#include <meta2/remote/meta2_remote.h>
#include <meta2/remote/meta2_services_remote.h>

#include "lib/meta2_mover.h"
#include "lib/meta2_mover_internals.h"

// FIXME: this constant is defined in gs_internals.h
#ifndef ENV_LOG4C_ENABLE
# define ENV_LOG4C_ENABLE "GS_DEBUG_ENABLE"
#endif

/* Global variables */
time_t interval_update_services;

/* Static variables */
static gs_grid_storage_t *ns_client;
static gchar ns_name[LIMIT_LENGTH_NSNAME+1];
static GString* console_tag;

static gboolean error_raised;
/* ------------------------------------------------------------------------- */

static GError*
gs_init_client(const gchar *ns, gs_grid_storage_t **result)
{
	gs_error_t *gserr = NULL;
	gs_grid_storage_t *cli;

	cli = gs_grid_storage_init2(ns, 90000, 90000, &gserr);
	if (!cli) {
		GError *err = GS_ERROR_NEW(gs_error_get_code(gserr), "Grid ERROR : %s", gs_error_get_message(gserr));
		gs_error_free(gserr);
		GS_ERROR_STACK(&err);
		return err;
	}

	g_assert(gserr == NULL);
	gs_grid_storage_set_timeout(cli, GS_TO_RAWX_CNX, 90000, NULL);
	gs_grid_storage_set_timeout(cli, GS_TO_RAWX_OP, 90000, NULL);
	gs_grid_storage_set_timeout(cli, GS_TO_M0_CNX, 90000, NULL);
	gs_grid_storage_set_timeout(cli, GS_TO_M0_OP, 90000, NULL);
	gs_grid_storage_set_timeout(cli, GS_TO_M1_CNX, 90000, NULL);
	gs_grid_storage_set_timeout(cli, GS_TO_M1_OP, 90000, NULL);
	gs_grid_storage_set_timeout(cli, GS_TO_M2_CNX, 90000, NULL);
	gs_grid_storage_set_timeout(cli, GS_TO_M2_OP, 90000, NULL);
	gs_grid_storage_set_timeout(cli, GS_TO_MCD_CNX, 90000, NULL);
	gs_grid_storage_set_timeout(cli, GS_TO_MCD_OP, 90000, NULL);
	*result = cli;
	return NULL;
}

/* ------------------------------------------------------------------------- */

static void
main_specific_stop(void)
{
}

static void
main_specific_fini(void)
{
        GRID_DEBUG("Cleaning specific data");
        if (ns_client) {
                gs_grid_storage_free(ns_client);
                ns_client = NULL;
        }
        meta2_mover_clean_services();

        if (console_tag) {
                g_string_free(console_tag, TRUE);
        }
}

static void
main_action(void)
{
	gchar line[1024];
	GError *err;

	GRID_DEBUG("Job starting...");

        if (NULL != (err = gs_init_client(ns_name, &ns_client))) {
                GRID_ERROR("Failed to init a GridStorage client : %s", err->message);
                g_clear_error(&err);
                return;
        }

	while (!feof(stdin) && !ferror(stdin)) {
		memset(line, 0x00, sizeof(line));
		if (!fgets(line, sizeof(line)-1, stdin)) 
			break;

		gchar* meta2_addr = NULL;
		if (console_tag != NULL) {
			meta2_addr = g_strdup(console_tag->str);
		}

		err = meta2_mover_migrate(ns_client, line, meta2_addr);
		if (err != NULL) {
			error_raised = TRUE;
			GRID_ERROR("Migration error for [%s]: %s",
					line, gerror_get_message(err));
			g_clear_error(&err);
		}
		if (NULL != meta2_addr) {
			g_free(meta2_addr);
		}
	}

	if (ferror(stdin)) {
		GRID_ERROR("Input error: errno=%d %s", errno, strerror(errno));
		return;
	}

	GRID_DEBUG("End of input, job done!");

	if (error_raised) {
		main_specific_fini();
		main_specific_stop();

		exit(EXIT_FAILURE);
	}
}

static gboolean
main_configure(int argc, char **args)
{
	if (argc != 1) {
		GRID_ERROR("Please specidy one and only one argument, a namespace name");
		return FALSE;
	}

	if (sizeof(ns_name) <= g_strlcpy(ns_name, args[0], sizeof(ns_name)-1)) {
		GRID_ERROR("Namespace name too long, maximum %d bytes", LIMIT_LENGTH_NSNAME);
		return FALSE;
	}

	return TRUE;
}

static struct grid_main_option_s*
main_get_options(void)
{
	static struct grid_main_option_s options[] = {
		{ "Tag", OT_STRING, {.str = &console_tag},
                        "The targeted meta2 tag (-OTag=tag.key=value) or meta2 IP (-OTag=url=IP:port)" },
		{NULL, 0, {.i=0}, NULL}
	};

	return options;
}

static void
main_set_defaults(void)
{
	GRID_DEBUG("Setting defaults\n");
	ns_client = NULL;
	memset(ns_name, 0x00, sizeof(ns_name));
	interval_update_services = 60L;

	console_tag = NULL;

	error_raised = FALSE;
}

static const gchar*
main_get_usage(void)
{
	static gchar xtra_usage[] = "\tExpected argument: a namespace name\n\tExpected input (stdin): list of container IDs\n";
	return xtra_usage;
}

static struct grid_main_callbacks cb =
{
	.options = main_get_options,
	.action = main_action,
	.set_defaults = main_set_defaults,
	.specific_fini = main_specific_fini,
	.configure = main_configure,
	.usage = main_get_usage,
	.specific_stop = main_specific_stop
};

int
main(int argc, char **argv)
{
	setenv(ENV_LOG4C_ENABLE, "0", TRUE);
	return grid_main_cli(argc, argv, &cb);
}

