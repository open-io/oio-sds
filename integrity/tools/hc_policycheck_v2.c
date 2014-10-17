#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "hc-policycheck"
#endif

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <neon/ne_uri.h>
#include <neon/ne_basic.h>
#include <neon/ne_request.h>
#include <neon/ne_session.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include <cluster/lib/gridcluster.h>
#include <resolver/hc_resolver.h>
#include <meta2v2/meta2v2_remote.h>
#include <meta2v2/meta2_utils.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>

#include "../lib/content_check.h"
#include "../lib/http_pipe.h"
#include "./policycheck_repair.h"

static struct policy_check_s policy_check;

//------------------------------------------------------------------------------
// Main hooks
//------------------------------------------------------------------------------

static void
polcheck_action(void)
{
	GError *err = NULL;
	struct check_args_s args;

	args.lbpool = policy_check.lbpool;
	args.ns_info = policy_check.nsinfo;
	policy_check.check = m2v2_check_create(policy_check.url, &args);
	policy_check.m2urlv = NULL;

	if (!(err = policy_load_beans(&policy_check))) {
		GRID_DEBUG("Beans loaded");
		err = policy_check_and_repair(&policy_check);
	}

	if (err) {
		GRID_ERROR("Policy check repair error : (%d) %s", err->code, err->message);
		g_clear_error(&err);
		grid_main_set_status(1);
	}

	m2v2_check_destroy(policy_check.check);
	g_strfreev(policy_check.m2urlv);
	policy_check.check = NULL;
	policy_check.m2urlv = NULL;
}

static struct grid_main_option_s *
polcheck_get_options(void)
{
	static struct grid_main_option_s polcheck_options[] = {
		{"CheckOnly", OT_BOOL, {.b = &policy_check.check_only},
			"Only check if content is ok, don't perform any action"},
		{ NULL, 0, {.i=0}, NULL}
	};

	return polcheck_options;
}

static void
polcheck_set_defaults(void)
{
	memset(&policy_check, 0, sizeof(policy_check));
}

static void
polcheck_specific_fini(void)
{
	GRID_DEBUG("Exiting");
	if (policy_check.url)
		hc_url_clean(policy_check.url);
	if (policy_check.resolver)
		hc_resolver_destroy(policy_check.resolver);
	if (policy_check.lbpool)
		grid_lbpool_destroy(policy_check.lbpool);
	if (policy_check.nsinfo)
		namespace_info_free(policy_check.nsinfo);
}

static void
polcheck_specific_stop(void)
{
	/* no op */
}

static const gchar *
polcheck_usage(void)
{
	return	"Expected argument: an Honeycomb url => NAMESPACE/REFERENCE/PATH\n";
}

static gboolean
polcheck_configure(int argc, char **argv)
{
	if (!argc) {
		GRID_ERROR("Missing arguments");
		return FALSE;
	}

	if (!(policy_check.url = hc_url_init(argv[0]))) {
		GRID_ERROR("Invalid URL [%s] : %s", argv[0], "Format error");
		return FALSE;
	}
	if (!hc_url_has(policy_check.url, HCURL_NS)) {
		GRID_ERROR("Invalid URL [%s] : %s", argv[0], "missing NS");
		return FALSE;
	}
	if (!hc_url_has(policy_check.url, HCURL_REFERENCE)) {
		GRID_ERROR("Invalid URL [%s] : %s", argv[0], "missing REFERENCE");
		return FALSE;
	}
	if (!hc_url_has(policy_check.url, HCURL_PATH)) {
		GRID_ERROR("Invalid URL [%s] : %s", argv[0], "missing PATH");
		return FALSE;
	}

	if (!(policy_check.resolver = hc_resolver_create())) {
		GRID_ERROR("HC resolver creation failure");
		return FALSE;
	}

	GError *err = NULL;
	policy_check.nsinfo = get_namespace_info(hc_url_get(
				policy_check.url, HCURL_NSPHYS), &err);
	if (!policy_check.nsinfo) {
		GRID_ERROR("Failed to load NS [%s] : (%d) %s",
				hc_url_get(policy_check.url, HCURL_NSPHYS),
				err->code, err->message);
		g_clear_error(&err);
		return FALSE;
	}

	policy_check.lbpool = grid_lbpool_create(hc_url_get(
				policy_check.url, HCURL_NSPHYS));
	if (!policy_check.lbpool) {
		GRID_ERROR("LB pool init failure : (%d) %s", 0, "memory allocation failure");
		return FALSE;
	}

	grid_lbpool_reconfigure(policy_check.lbpool, policy_check.nsinfo);

	err = gridcluster_reload_lbpool(policy_check.lbpool);
	if (NULL != err) {
		GRID_ERROR("LB pool init failure : (%d) %s", err->code, err->message);
		g_clear_error(&err);
		return FALSE;
	}

	return TRUE;
}

static struct grid_main_callbacks polcheck_callbacks =
{
	.options = polcheck_get_options,
	.action = polcheck_action,
	.set_defaults = polcheck_set_defaults,
	.specific_fini = polcheck_specific_fini,
	.configure = polcheck_configure,
	.usage = polcheck_usage,
	.specific_stop = polcheck_specific_stop,
};

int
main(int argc, char **args)
{
	g_setenv("GS_DEBUG_GLIB2", "1", TRUE);
	return grid_main_cli(argc, args, &polcheck_callbacks);
}
