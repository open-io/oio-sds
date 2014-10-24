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
#include "../lib/policycheck_repair.h"

static struct hc_url_s *url;
static gboolean check_only;

//------------------------------------------------------------------------------
// Main hooks
//------------------------------------------------------------------------------

static void
polcheck_action(void)
{
	GError *err = NULL;
	check_and_repair_content(url, check_only, &err);

	if (err) {
		GRID_ERROR("Policy check repair error: (%d) %s", err->code, err->message);
		g_clear_error(&err);
		grid_main_set_status(1);
	}
}

static struct grid_main_option_s *
polcheck_get_options(void)
{
	static struct grid_main_option_s polcheck_options[] = {
		{"CheckOnly", OT_BOOL, {.b = &check_only},
			"Only check if content is ok, don't perform any action"},
		{ NULL, 0, {.i=0}, NULL}
	};

	return polcheck_options;
}

static void
polcheck_set_defaults(void)
{
	check_only = FALSE;
	url = NULL;
}

static void
polcheck_specific_fini(void)
{
	GRID_DEBUG("Exiting");
	if (url)
		hc_url_clean(url);
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

	if (!(url = hc_url_init(argv[0]))) {
		GRID_ERROR("Invalid URL [%s]: %s", argv[0], "Format error");
		return FALSE;
	}
	if (!hc_url_has(url, HCURL_NS)) {
		GRID_ERROR("Invalid URL [%s]: %s", argv[0], "missing NS");
		return FALSE;
	}
	if (!hc_url_has(url, HCURL_REFERENCE)) {
		GRID_ERROR("Invalid URL [%s]: %s", argv[0], "missing REFERENCE");
		return FALSE;
	}
	if (!hc_url_has(url, HCURL_PATH)) {
		GRID_ERROR("Invalid URL [%s]: %s", argv[0], "missing PATH");
		return FALSE;
	}

	if (metautils_str_ishexa(hc_url_get(url, HCURL_REFERENCE),
			STRLEN_CONTAINERID - 1)) {
		gchar cid[STRLEN_CONTAINERID] = {0};
		g_strlcpy(cid, hc_url_get(url, HCURL_REFERENCE), STRLEN_CONTAINERID);
		hc_url_set(url, HCURL_HEXID, cid);
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
