#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "hc.tools"
#endif

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

#include "../lib/gs_internals.h"

#ifndef FREEP
# define FREEP(F,P) do { if (!(P)) return; F(P); (P) = NULL; } while (0)
#endif

static gboolean flag_xml = FALSE;

static gchar *action = NULL;
static gchar *namespace = NULL;
static gchar *reference = NULL;
static gchar **action_args = NULL;
static container_id_t cid;

static void
dump_properties(gchar **s)
{
	if (!flag_xml) {
		for (; s && *s ; s++)
			g_print("   [%s]\n", *s);
	}
	else {
		g_print("<properties>\n");
		for (; s && *s ; s++) {
			gchar **ssplit = g_strsplit(*s, "=", 2);
			if (!ssplit)
				g_print("<!-- Invalid %s -->\n", *s);
 			else {
				if (!*ssplit)
					g_print("<!-- Invalid %s -->\n", *s);
				else {
					g_print(" <property>\n");
					g_print("  <k>%s</k>\n", ssplit[0]);
					g_print("  <v>%s</v>\n", ssplit[1]);
					g_print(" </property>\n");
				}
				g_strfreev(ssplit);
			}
		}
		g_print("</properties>\n");
	}
}

static void
help_get(void)
{
	g_printerr("usage: %s get <NS>/<REF>\n\n", g_get_prgname());
	g_printerr("    NS: Honeycomb namespace, if you don't know this, please contact your Honeycomb namespace administrator\n");
	g_printerr("    REF: The reference you want to create. A reference if mandatory to work with services in Honeycomb.\n");
}

static gboolean
func_get(gs_grid_storage_t *hc)
{
	gs_error_t *e;
	gchar *keys[] = {"meta2.quota", NULL};
	gchar **values = NULL;

	if (!(e = hc_get_reference_property(hc, reference, keys, &values))) {
		if (!*values)
			g_printerr("No property [%s] associated to the reference [%s]\n", keys[0], reference);
		dump_properties(values);
		g_strfreev(values);
		values = NULL;
		return TRUE;
	}

	g_printerr("%s", e->msg);
	gs_error_free(e);
	return FALSE;
}


static void
help_set(void)
{
	g_printerr("usage: %s set <NS>/<REF> SIZE\n\n", g_get_prgname());
	g_printerr("    NS: Honeycomb namespace, if you don't know this, please contact your Honeycomb namespace administrator\n");
	g_printerr("    REF: The reference you want to create. A reference if mandatory to work with services in Honeycomb.\n");
	g_printerr("    SIZE: The sequence number for the given (service,container) association\n");
}

static gboolean
func_set(gs_grid_storage_t *hc)
{
	container_info_t cinfo;
	GSList list = {.data = &cinfo, .next = NULL};
	addr_info_t *m1a = NULL;
	gchar strm1a[64];
	gboolean rc;
	GError *e = NULL;

	if (g_strv_length(action_args) != 1) {
		help_set();
		return FALSE;
	}

	cinfo.size = g_ascii_strtoll(action_args[0], NULL, 10);
	memcpy(cinfo.id, cid, sizeof(container_id_t));
	
	if (!(m1a = gs_resolve_meta1v2(hc, cid, NULL, 0, NULL, &e))) {
		g_printerr("%s\n", e->message);
		g_clear_error(&e);
		return FALSE;
	}

	addr_info_to_string(m1a, strm1a, sizeof(strm1a));
	rc = meta1_remote_update_containers(strm1a, &list, 60001, &e);
	addr_info_clean(m1a);
	m1a = NULL;

	if (rc) {
		g_printerr("Quota updated for reference [%s]\n", reference);
		return TRUE;
	}

	g_printerr("%s", e->message);
	g_clear_error(&e);
	return FALSE;
}

/* ------------------------------------------------------------------------- */

struct action_s {
	const gchar *name;
	gboolean (*job) (gs_grid_storage_t *hc);
};

struct help_s {
	const gchar *name;
	void (*help) (void);
};

static struct action_s actions[] = {
	{"set", func_set},
	{"get", func_get},
	{NULL,  NULL},
};

static struct help_s helps[] = {
	{"set", help_set},
	{"get", help_get},
	{NULL,  NULL},
};

static void
_call_action(gs_grid_storage_t *hc)
{
	struct action_s *paction;

	for (paction=actions; paction->name ;paction++) {
		if (0 != g_ascii_strcasecmp(paction->name, action))
			continue;
		if (!paction->job(hc))
			GRID_DEBUG("Action error");
		grid_main_stop();
		return;
	}

	g_printerr("Unknown action [%s]\n", action);
}

static gboolean
_call_help(const gchar *a)
{
	struct help_s *phelp;

	for (phelp=helps; phelp->name ;phelp++) {
		if (!g_ascii_strcasecmp(phelp->name, a)) {
		 	phelp->help();
			return TRUE;
		}
	}

	g_printerr("Help section not found for [%s]\n", a);
	return FALSE;
}

static void
gsquota_action(void)
{
	gs_error_t *hc_error = NULL;
	gs_grid_storage_t *hc;

	hc = gs_grid_storage_init(namespace, &hc_error);

	if (!hc) {
		g_printerr("Failed to load namespace [%s]. Please ensure /etc/gridstorage.conf.d/%s file exists.\n"
				"If not, please contact your Honeycomb namespace administrator.\n", namespace, namespace);
		return;
	}

	_call_action(hc);

	gs_grid_storage_free(hc);
}

static struct grid_main_option_s *
gsquota_get_options(void)
{
	static struct grid_main_option_s gsquota_options[] = {
		{ "OutputXML", OT_BOOL, {.b = &flag_xml},
			"Write XML instead of the default key=value output"},
		{NULL, 0, {.i=0}, NULL}
	};

	return gsquota_options;
}

static void
gsquota_set_defaults(void)
{
	GRID_DEBUG("Setting defaults");
	action = NULL;
	namespace = NULL;
	reference = NULL;
	action_args = NULL;
	memset(cid, 0, sizeof(container_id_t));
}

static void
gsquota_specific_fini(void)
{
	GRID_DEBUG("Exiting");
	FREEP(g_free, action);
	FREEP(g_free, namespace);
	FREEP(g_free, reference);
	FREEP(g_strfreev, action_args);
}

static void
gsquota_specific_stop(void)
{
	/* no op */
}

static const gchar *
gsquota_usage(void)
{
	return "<command> [<args>]\n"
		"\nThe available hcdir commands are:\n"
		"   set    Force the quota of the container\n"
		"   get    Gets and dumps the quota of a container\n"
		"\n";
}

static gboolean
gsquota_configure(int argc, char **argv)
{
	gchar **tmp;

	GRID_DEBUG("Configuration");

	if (argc < 1) {
		g_printerr("Invalid arguments number");
		return FALSE;
	}

	action = g_strdup(argv[0]);

	if (!g_ascii_strcasecmp(action, "help")) {
		grid_main_stop();
		if (argc >= 2)
			return _call_help(argv[1]);
		g_print("usage: %s %s", g_get_prgname(), gsquota_usage());
		return TRUE;
	}
	
	if (argc < 2) {
		g_printerr("Invalid arguments number");
		return FALSE;
	}

	tmp = g_strsplit(argv[1], "/", 2);

	if (2 != g_strv_length(tmp)) {
		g_printerr("Invalid reference name, expected VNS/REFNAME");
		g_strfreev(tmp);
		return FALSE;
	}

	meta1_name2hash(cid, tmp[0], tmp[1]);

	namespace = tmp[0];
	reference = tmp[1];
	g_free(tmp);
	tmp = NULL;
	
	action_args = g_strdupv(argv+2);
	return TRUE;
}

struct grid_main_callbacks gsquota_callbacks =
{
	.options =       gsquota_get_options,
	.action =        gsquota_action,
	.set_defaults =  gsquota_set_defaults,
	.specific_fini = gsquota_specific_fini,
	.configure =     gsquota_configure,
	.usage =         gsquota_usage,
	.specific_stop = gsquota_specific_stop,
};

int
main(int argc, char **args)
{
	g_setenv("GS_DEBUG_GLIB2", "1", TRUE);
	return grid_main_cli(argc, args, &gsquota_callbacks);
}

