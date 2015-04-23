/*
OpenIO SDS integrity
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "hc-policycheck"
#endif

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <attr/xattr.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>
#include <rawx-lib/src/rawx.h>

#include "../lib/content_check.h"

static gboolean check_only = FALSE;

struct hc_url_s *url = NULL;

/* ------------------------------------------------------------------------- */
static void
polcheck_action(void)
{
	if(url) {
		GError *local_error = NULL;
		if(!check_content_storage_policy(hc_url_get(url, HCURL_NS), hc_url_get(url, HCURL_HEXID),
					hc_url_get(url, HCURL_PATH), check_only, &local_error)) {
			GRID_ERROR("Storage policy check failure : %s", local_error ? local_error->message : NULL);
		} else {
			GRID_DEBUG("Check done");
		}

		if(local_error)
			g_clear_error(&local_error);
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
	/* Nothin to do */
}

static void
polcheck_specific_fini(void)
{
	GRID_DEBUG("Exiting");
	if(url)
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
	return "Expected argument: NAMESPACE/REFERENCE/PATH\n";
}

static gboolean
polcheck_configure(int argc, char **argv)
{
	if (!argc) {
		GRID_ERROR("Missing arguments");
		return FALSE;
	}

	url = hc_url_oldinit(argv[0]);
	if(!hc_url_has(url, HCURL_NS) || !hc_url_has(url, HCURL_REFERENCE) 
			|| !hc_url_has(url, HCURL_PATH)) { 
		GRID_ERROR("Invalid url : [%s]", argv[0]);
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
	return grid_main_cli(argc, args, &polcheck_callbacks);
}
