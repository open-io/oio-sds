#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "hc.tools"
#endif

#include <assert.h>
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

typedef gboolean (*action_func)(gs_grid_storage_t *hc);
typedef void (*help_func)(void);

static gboolean flag_xml = FALSE;

static struct hc_url_s *url = NULL;

static gchar *action = NULL;
static gchar **action_args = NULL;
static container_id_t cid;

static void
freev(char **v)
{
	char **p;
	if (!v)
		return;
	for (p=v; *p ;p++)
		free(*p);
	free(v);
}

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
dump_services(gchar **s)
{
	if (!flag_xml) {
		for (; s && *s ; s++)
			g_print("   [%s]\n", *s);
	}
	else {
		g_print("<services>\n");
		for (; s && *s ; s++) {
			struct meta1_service_url_s *m1url;
			if (!(m1url = meta1_unpack_url(*s)))
				g_print("<!-- Invalid %s -->\n", *s);
			else {
				g_print(" <service>\n");
				g_print("  <seq>%"G_GINT64_FORMAT"</seq>\n", m1url->seq);
				g_print("  <type>%s</type>\n", m1url->srvtype);
				g_print("  <host>%s</host>\n", m1url->host);
				g_print("  <args>%s</args>\n", m1url->args);
				g_print(" </service>\n");
				g_free(m1url);
			}
		}
		g_print("</services>\n");
	}
}

/* ------------------------------------------------------------------------- */

static void
help_list(void)
{
	g_printerr("usage: hcdir list <NS>/<REF> <SRV_TYPE>\n\n");
	g_printerr("    NS: Honeycomb namespace, if you don't know this, "
			"please contact your Honeycomb namespace administrator\n");
	g_printerr("    REF: The reference on which you want to list the services."
			" A reference if mandatory to work with services in Honeycomb.\n");
	g_printerr("    SRV_TYPE: The type of service you want to list "
			"(set ALL if you want to get all service types linked).\n");
}

static gboolean
func_list(gs_grid_storage_t *hc)
{
	gs_error_t *e = NULL;
	gchar **services = NULL;

	e = hc_list_reference_services(hc, hc_url_get(url, HCURL_REFERENCE),
			action_args[0], &services);
	if (NULL != e) {
		g_printerr("%s", e->msg);
		gs_error_free(e);
		return FALSE;
	}

	if (!services) {
		gchar *tab[] = {NULL};

		if (action_args[0])
			g_printerr("No service [%s] linked to reference [%s].\n",
					action_args[0], hc_url_get(url, HCURL_REFERENCE));
		else
			g_printerr("No service linked to reference [%s].\n",
					hc_url_get(url, HCURL_REFERENCE));
		dump_services(tab);
	}
	else {
		if (action_args[0])
			g_printerr("Reference [%s], services [%s] linked:\n",
					hc_url_get(url, HCURL_REFERENCE), action_args[0]);
		else
			g_printerr("Reference [%s], all services linked:\n",
					hc_url_get(url, HCURL_REFERENCE));

		dump_services(services);
	}

	freev(services);
	return TRUE;
}


static void
help_link(void)
{
	g_printerr("usage: hcdir link <NS>/<REF> <SRV_TYPE>\n\n");
	g_printerr("    NS: Honeycomb namespace, if you don't know this,"
			" please contact your Honeycomb namespace administrator\n");
	g_printerr("    REF: The reference on which you want to link a service.");
	g_printerr("    SRV_TYPE: The type of service you want to link.\n");
}

static gboolean
func_link(gs_grid_storage_t *hc)
{
	gs_error_t *e;
	char **urlv = NULL;

	if (g_strv_length(action_args) != 1) {
		help_link();
		return FALSE;
	}

	e = hc_link_service_to_reference(hc,
			hc_url_get(url, HCURL_REFERENCE),
			action_args[0],
			&urlv);
	if (NULL != e) {
		g_printerr("Link error : %s", e->msg);
		gs_error_free(e);
		return FALSE;
	}

	g_printerr("Service [%s] linked to reference [%s]\n", urlv[0],
			hc_url_get(url, HCURL_REFERENCE));
	freev(urlv);
	return TRUE;
}


static void
help_unlink(void)
{
	g_printerr("usage: hcdir unlink <NS>/<REF> <SRV_TYPE>\n\n");
	g_printerr("    NS: Honeycomb namespace, if you don't know this,"
			" please contact your Honeycomb namespace administrator\n");
	g_printerr("    REF: The reference on which you want to unlink services");
	g_printerr("    SRV_TYPE: The type of service you want to unlink.\n");
	g_printerr("    (This functionally will be improved later.)\n");
}

static gboolean
func_unlink(gs_grid_storage_t *hc)
{
	gs_error_t *e = NULL;

	if (g_strv_length(action_args) != 1) {
		help_unlink();
		return FALSE;
	}

	if (!(e = hc_unlink_reference_service(hc,
					hc_url_get(url, HCURL_REFERENCE),
					action_args[0]))) {
		g_printerr("Services [%s] unlinked from reference [%s]\n",
				action_args[0], hc_url_get(url, HCURL_REFERENCE));
		return TRUE;
	}

	g_printerr("%s", e->msg);
	gs_error_free(e);
	return FALSE;
}


static void
help_has(void)
{
	g_printerr("usage: hcdir has <NS>/<REF>\n\n");
	g_printerr("    NS: Honeycomb namespace, if you don't know this,"
			" please contact your Honeycomb namespace administrator\n");
	g_printerr("    REF: The reference you want to check.\n");
}

static gboolean
func_has(gs_grid_storage_t *hc)
{
	gs_error_t *e;

	if (g_strv_length(action_args) != 0) {
		help_has();
		return FALSE;
	}

	if (!(e = hc_has_reference(hc, hc_url_get(url, HCURL_REFERENCE)))) {
		g_printerr("Reference %s exists\n", hc_url_get(url, HCURL_REFERENCE));
		return TRUE;
	}

	if(e->code != 431)
		g_printerr("%s", e->msg);
	else
		g_print("Reference %s does not exist\n",
				hc_url_get(url, HCURL_REFERENCE));

	gs_error_free(e);
	return FALSE;
}


static void
help_delete(void)
{
	g_printerr("usage: hcdir delete <NS>/<REF>\n\n");
	g_printerr("    NS: Honeycomb namespace, if you don't know this,"
			" please contact your Honeycomb namespace administrator\n");
	g_printerr("    REF: The reference you want to delete.\n");
}

static gboolean
func_delete(gs_grid_storage_t *hc)
{
	gs_error_t *e;

	if (!(e = hc_delete_reference(hc, hc_url_get(url, HCURL_REFERENCE)))) {
		g_print("Reference [%s] deleted\n", hc_url_get(url, HCURL_REFERENCE));
		return TRUE;
	}

	g_printerr("%s", e->msg);
	gs_error_free(e);
	return FALSE;
}


static void
help_create(void)
{
	g_printerr("usage: hcdir create <NS>/<REF>\n\n");
	g_printerr("    NS: Honeycomb namespace, if you don't know this,"
			"please contact your Honeycomb namespace administrator\n");
	g_printerr("    REF: The reference you want to create."
			"A reference if mandatory to work with services in Honeycomb.\n");
}

static gboolean
func_create(gs_grid_storage_t *hc)
{
	gs_error_t *e;

	if (!(e = hc_create_reference(hc, hc_url_get(url, HCURL_REFERENCE)))) {
		g_print("Reference [%s] created\n", hc_url_get(url, HCURL_REFERENCE));
		return TRUE;
	}

	g_printerr("%s", e->msg);
	gs_error_free(e);
	return FALSE;
}


static void
help_poll(void)
{
	g_printerr("usage: hcdir poll <NS>/<REF> <TYPE>\n\n");
	g_printerr("    NS: Honeycomb namespace, if you don't know this,"
			"please contact your Honeycomb namespace administrator\n");
	g_printerr("    REF: The targeted reference");
	g_printerr("    TYPE: A type of service managed in the given namespace\n");
}

static gboolean
func_poll(gs_grid_storage_t *hc)
{
	char *u = NULL;
	gs_error_t *e;

	if (g_strv_length(action_args) != 1) {
		help_poll();
		return FALSE;
	}

	if (!(e = hc_poll_service(hc,
					hc_url_get(url, HCURL_REFERENCE),
					action_args[0],
					&u))) {
		char *urlv[2] = {NULL,NULL};
		urlv[0] = u;
		dump_services(urlv);
		free(u);
		return TRUE;
	}

	g_printerr("Poll error : (%d) %s", e->code, e->msg);
	gs_error_free(e);
	return FALSE;
}


static void
help_force(void)
{
	g_printerr("usage: hcdir force <NS>/<REF> '<SEQ>|<TYPE>|<URL>|<ARGS>'\n\n");
	g_printerr("    NS: Honeycomb namespace, if you don't know this,"
			" please contact your Honeycomb namespace administrator\n");
	g_printerr("    REF: The targeted reference");
	g_printerr("    SEQ: The sequence number for the given "
			"(service,container) association\n");
	g_printerr("    TYPE: A type of service managed in the given namespace\n");
	g_printerr("    URL: the network address of the given service\n");
	g_printerr("    ARGS: some service-dependant arguments attached to this "
			"(service,container) association\n");
}

static gboolean
func_force(gs_grid_storage_t *hc)
{
	gs_error_t *e;

	if (g_strv_length(action_args) != 1) {
		help_force();
		return FALSE;
	}

	if (NULL != (e = hc_force_service(hc,
					hc_url_get(url, HCURL_REFERENCE),
					action_args[0]))) {
		g_printerr("%s", e->msg);
		gs_error_free(e);
		return FALSE;
	}

	g_print("Service [%s] forced for reference [%s]\n",
			action_args[0], hc_url_get(url, HCURL_REFERENCE));
	return TRUE;
}


static void
help_srvconfig(void)
{
	g_printerr("usage: hcdir srvconfig <NS>/<REF> "
			"'<SEQ>|<TYPE>|<URL>|<ARGS>'\n\n");
	g_printerr("    NS: Honeycomb namespace, if you don't know this,"
			" please contact your Honeycomb namespace administrator\n");
	g_printerr("    REF: The targeted reference");
	g_printerr("    SEQ: The sequence number for the given (service,container)"
			" association\n");
	g_printerr("    TYPE: A type of service managed in the given namespace\n");
	g_printerr("    URL: the network address of the given service\n");
	g_printerr("    ARGS: the new service-dependant arguments that will "
			"be attached to this (service,container) association\n");
}

static gboolean
func_srvconfig(gs_grid_storage_t *hc)
{
	gs_error_t *e;

	if (g_strv_length(action_args) != 2) {
		help_srvconfig();
		return FALSE;
	}

	if (!(e = hc_configure_service(hc,
					hc_url_get(url, HCURL_REFERENCE),
					action_args[0]))) {
		g_printerr("Service [%s] reconfigured for reference [%s]\n",
				action_args[0], hc_url_get(url, HCURL_REFERENCE));
		return TRUE;
	}

	g_printerr("%s", e->msg);
	gs_error_free(e);
	return FALSE;
}


static void
help_propset(void)
{
	g_printerr("usage: hcdir propset <NS>/<REF> KEY VALUE\n\n");
	g_printerr("    NS: Honeycomb namespace, if you don't know this,"
			" please contact your Honeycomb namespace administrator\n");
	g_printerr("    REF: The targeted reference");
	g_printerr("    SEQ: The sequence number for the given (service,container)"
			" association\n");
	g_printerr("    KEY: \n");
	g_printerr("    VALUE: \n");
}

static gboolean
func_propset(gs_grid_storage_t *hc)
{
	gs_error_t *e = NULL;

	if (g_strv_length(action_args) != 2) {
		help_propset();
		return FALSE;
	}

	if (!(e = hc_set_reference_property(hc, hc_url_get(url, HCURL_REFERENCE),
					action_args[0], action_args[1]))) {
		g_print("Key [%s] updated for reference [%s]\n", action_args[0],
				action_args[1]);
		return TRUE;
	}

	g_printerr("%s", e->msg);
	gs_error_free(e);
	return FALSE;
}


static void
help_propget(void)
{
	g_printerr("usage: hcdir propget <NS>/<REF> [KEY]...\n\n");
	g_printerr("    NS: Honeycomb namespace, if you don't know this,"
			" please contact your Honeycomb namespace administrator\n");
	g_printerr("    REF: The targeted reference");
	g_printerr("    SEQ: The sequence number for the given (service,container)"
			" association\n");
	g_printerr("    KEY: A potentially empty sequence of property names\n");
}

static gboolean
func_propget(gs_grid_storage_t *hc)
{
	gs_error_t *e;
	gchar **values = NULL;

	if (!(e = hc_get_reference_property(hc, hc_url_get(url, HCURL_REFERENCE),
					action_args, &values))) {
		if (!*values)
			g_printerr("No property associated to the reference [%s]\n",
					hc_url_get(url, HCURL_REFERENCE));
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
help_propdel(void)
{
	g_printerr("usage: hcdir propget <NS>/<REF> KEY...\n\n");
	g_printerr("    NS: Honeycomb namespace, if you don't know this,"
			" please contact your Honeycomb namespace administrator\n");
	g_printerr("    REF: The targeted reference");
	g_printerr("    SEQ: The sequence number for the given (service,container)"
			" association\n");
	g_printerr("    KEY: A not-empty sequence of property names\n");
}

static gboolean
func_propdel(gs_grid_storage_t *hc)
{
	gs_error_t *e;

	if (g_strv_length(action_args) < 1) {
		help_propdel();
		return FALSE;
	}

	if (!(e = hc_delete_reference_property(hc, hc_url_get(url, HCURL_REFERENCE),
					action_args))) {
		g_printerr("Properties deleted for reference [%s]\n",
				hc_url_get(url, HCURL_REFERENCE));
		return TRUE;
	}

	g_printerr("%s", e->msg);
	gs_error_free(e);
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
	{"has",       func_has},
	{"create",    func_create},
	{"delete",    func_delete},
	{"list",      func_list},
	{"link",      func_link},
	{"unlink",    func_unlink},
	{"poll",      func_poll},
	{"force",     func_force},
	{"srvconfig", func_srvconfig},
	{"propset",   func_propset},
	{"propget",   func_propget},
	{"propdel",   func_propdel},
	{NULL,        NULL},
};

static struct help_s helps[] = {
	{"has",       help_has},
	{"create",    help_create},
	{"delete",    help_delete},
	{"list",      help_list},
	{"link",      help_link},
	{"unlink",    help_unlink},
	{"poll",      help_poll},
	{"force",     help_force},
	{"srvconfig", help_srvconfig},
	{"propset",   help_propset},
	{"propget",   help_propget},
	{"propdel",   help_propdel},
	{NULL,        NULL},
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
hcdir_action(void)
{
	gs_error_t *hc_error = NULL;
	gs_grid_storage_t *hc;

	hc = gs_grid_storage_init(hc_url_get(url, HCURL_NS), &hc_error);

	if (!hc) {
		g_printerr("Failed to load namespace [%s]. "
				"Please ensure /etc/gridstorage.conf.d/%s file exists.\n"
				"If not, please contact your Honeycomb namespace"
				" administrator.\n",
				hc_url_get(url, HCURL_NS), hc_url_get(url, HCURL_NS));
		return;
	}

	_call_action(hc);

	gs_grid_storage_free(hc);
}

static struct grid_main_option_s *
hcdir_get_options(void)
{
static struct grid_main_option_s hcdir_options[] = {
		{ "OutputXML", OT_BOOL, {.b = &flag_xml},
			"Write XML instead of the default key=value output"},
		{NULL, 0, {.i=0}, NULL}
	};

	return hcdir_options;
}

static void
hcdir_set_defaults(void)
{
	GRID_DEBUG("Setting defaults");
	url = NULL;
	action = NULL;
	action_args = NULL;
	memset(cid, 0, sizeof(container_id_t));
}

static void
hcdir_specific_fini(void)
{
	GRID_DEBUG("Exiting");
	FREEP(g_free, action);
	FREEP(g_strfreev, action_args);
	if (url) {
		hc_url_clean(url);
		url = NULL;
	}
}

static void
hcdir_specific_stop(void)
{
	/* no op */
}

static const gchar *
hcdir_usage(void)
{
	return "<command> [<args>]\n"
		"\nThe available hcdir commands are:\n"
		"   create     Create a reference on a Honeycomb namespace\n"
		"   has        Ensure a reference exists on a Honeycomb namespace\n"
		"   delete     Delete a reference on a Honeycomb namespace\n"
		"   link       Associate a reference to a specified service type\n"
		"   list       List services from a specified type linked to a"
		" reference\n"
		"   unlink     Dissociate a service from a reference\n"
		"   poll       Like 'link' but tells the directory to force the"
		" election of a new service even if a service is still available\n"
		"   force      Links to the reference a service explicitely described,"
		" beyong all load-balancing mechanics\n"
		"   srvconfig  Changes the argument of a service linked to a"
		" reference.\n"
		"   propget    Get the/some properties associated to a given"
		" reference\n"
		"   propset    Associates a property to a reference\n"
		"   propdel    Dissociates (deletes) a property for a given reference\n"
		"\n"
		"See 'hcdir help <command>' for more information on a specific"
		"command. (Not yet implemented)\n";
}

static gboolean
hcdir_configure(int argc, char **argv)
{
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
		g_print("usage: %s %s", g_get_prgname(), hcdir_usage());
		return TRUE;
	}

	if (argc < 2) {
		g_printerr("Invalid arguments number");
		return FALSE;
	}

	if (!(url = hc_url_init(argv[1]))) {
		g_printerr("Invalid reference name, expected VNS/REFNAME");
		return FALSE;
	}

	action_args = g_strdupv(argv+2);
	return TRUE;
}

static struct grid_main_callbacks hcdir_callbacks =
{
	.options = hcdir_get_options,
	.action = hcdir_action,
	.set_defaults = hcdir_set_defaults,
	.specific_fini = hcdir_specific_fini,
	.configure = hcdir_configure,
	.usage = hcdir_usage,
	.specific_stop = hcdir_specific_stop,
};

int
main(int argc, char **args)
{
	g_setenv("GS_DEBUG_GLIB2", "1", TRUE);
	return grid_main_cli(argc, args, &hcdir_callbacks);
}

