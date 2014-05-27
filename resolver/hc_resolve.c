#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.sqlx.resolve"
#endif

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include <resolver/hc_resolver_internals.h>
#include <metautils/lib/metautils.h>
#include "./hc_resolver_internals.h"

static GSList *url_list = NULL;

static void
_action(struct hc_resolver_s *resolver)
{
	for (GSList *l=url_list; l ;l=l->next) {
		struct hc_url_s *url = l->data;
		gchar **u, **urlv = NULL;
		GError *err;

		err = hc_resolve_reference_service(resolver, url, "meta2", &urlv);
		if (err) {
			g_printerr("Resolution error : (%d) %s\n", err->code, err->message);
			g_error_free(err);
			return;
		}

		for (u=urlv; *u ;u++)
			g_print("%s\n", *u);
		g_strfreev(urlv);
	}
}

static void
hcres_action(void)
{
	struct hc_resolver_s *resolver = hc_resolver_create1(0);

	hc_resolver_set_ttl_csm0(resolver, 0);
	hc_resolver_set_ttl_services(resolver, 1);

	hc_resolver_set_now(resolver, 0);
	_action(resolver); // M0 + M1 loaded
	_action(resolver); // everything is cached

	hc_resolver_set_now(resolver, 2);
	_action(resolver); // everything is cached, expire not called, noatime not set
	hc_resolver_expire(resolver); // M0 kept, M1 kept (no noatime)
	_action(resolver); // everything is cached

	hc_resolver_set_now(resolver, 4);
	hc_resolver_expire(resolver); // M0 kept, M1 dropped
	_action(resolver); // M1 reloaded
	_action(resolver); // everything is cached

	// you should notice 1 call to meta0 and 2 calls to meta1

	hc_resolver_destroy(resolver);
}

static struct grid_main_option_s *
hcres_get_options(void)
{
	static struct grid_main_option_s hcres_options[] = {
		{NULL, 0, {.i=0}, NULL}
	};

	return hcres_options;
}

static void
hcres_set_defaults(void)
{
	GRID_DEBUG("Setting defaults");
	url_list = NULL;
}

static void
hcres_specific_fini(void)
{
	GRID_DEBUG("Exiting");
	if (url_list) {
		g_slist_foreach(url_list, hc_url_gclean, NULL);
		g_slist_free(url_list);
	}
}

static void
hcres_specific_stop(void)
{
	/* no op */
}

static const gchar *
hcres_usage(void)
{
	return "HC_URL [HC_URL...]";
}

static gboolean
hcres_configure(int argc, char **argv)
{
	GRID_DEBUG("Configuration");

	if (argc < 1) {
		g_printerr("Invalid arguments number");
		return FALSE;
	}

	for (; argc>0 && *argv ;argv++,argc--) {
		struct hc_url_s *url = hc_url_init(*argv);
		if (!url) {
			g_printerr("Invalid reference name, expected VNS/REFNAME");
			return FALSE;
		}
		url_list = g_slist_prepend(url_list, url);
	}

	return TRUE;
}

static struct grid_main_callbacks hcres_callbacks =
{
	.options = hcres_get_options,
	.action = hcres_action,
	.set_defaults = hcres_set_defaults,
	.specific_fini = hcres_specific_fini,
	.configure = hcres_configure,
	.usage = hcres_usage,
	.specific_stop = hcres_specific_stop,
};

int
main(int argc, char **args)
{
	g_setenv("GS_DEBUG_GLIB2", "1", TRUE);
	return grid_main_cli(argc, args, &hcres_callbacks);
}

