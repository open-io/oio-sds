/*
OpenIO SDS meta0v2
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

#include <stddef.h>
#include <string.h>
#include <errno.h>

#include <metautils/lib/metautils.h>

#include "meta0_remote.h"
#include "meta0_utils.h"

static gint nbreplicas = 1;
static gchar **urls;
static addr_info_t addr;
static gchar *namespace=NULL;
static gboolean flag_fill_v1 =FALSE;
static gboolean nodist = FALSE;

static gboolean
urlv_check (gchar **urlv)
{
	if (!urlv)
		return FALSE;
	for (gchar **u=urlv; *u ;u++) {
		if (!metautils_url_valid_for_connect(*u)) {
			GRID_WARN("Bad address [%s]", *u);
			return FALSE;
		}
	}
	return TRUE;
}

static addr_info_t *
_getMeta0addr(GSList **m0_lst, GSList *exclude ) {
	if ( namespace ) {
		return  meta0_utils_getMeta0addr(namespace,m0_lst,exclude);
	} else {
		if ( !exclude )
			return &addr;
	}
	return NULL;
}

static void
meta0_action(void)
{
	GError *err = NULL;
	GSList *m0_lst = NULL;
	GSList *exclude = NULL;
	addr_info_t *m0addr;

	m0addr = _getMeta0addr(&m0_lst,exclude);
	while (m0addr) {
		gchar url[STRLEN_ADDRINFO];
		grid_addrinfo_to_string(m0addr, url , sizeof(url));
		if ( flag_fill_v1 )
			err = meta0_remote_fill(url, urls, nbreplicas);
		else
			err = meta0_remote_fill_v2(url, nbreplicas, nodist);

		if (err) {
			GRID_WARN("META0 error (%d): %s", err->code, err->message);
			if (CODE_IS_NETWORK_ERROR(err->code)) {
				exclude=g_slist_prepend(exclude,m0addr);
				m0addr = _getMeta0addr(&m0_lst,exclude);
			} else {
				g_clear_error(&err);
				m0addr = NULL;
			}
		} else {
			GRID_INFO("META0 filled!");
			return;
		}	
	}

	grid_main_set_status(0);
}

static const char *
meta0_usage(void)
{
	return "META0_URL [META1_URL...]";
}

static struct grid_main_option_s *
meta0_get_options(void)
{
	static struct grid_main_option_s meta0_options[] = {
		{"NbReplicas", OT_INT, {.i=&nbreplicas},
			"Specificy a number of replicas (strictly greater than 0)"},
		{"IgnoreDistance", OT_BOOL, {.b=&nodist},
			"Allow replication on meta1 services with the same IP"},
		{NULL, 0, {.i=0}, NULL}
	};
	return meta0_options;
}

static void
meta0_specific_fini(void)
{
	if (urls) {
		g_strfreev(urls);
		urls = NULL;
	}
}

static void
meta0_set_defaults(void)
{
	urls = NULL;
	memset(&addr, 0, sizeof(addr));
}

static gboolean
meta0_configure(int argc, char **argv)
{
	if (argc < 1 ) {
		GRID_WARN("Not enough options, see usage.");
		return FALSE;
	}

	if (nbreplicas < 1 || nbreplicas > 1024) {
		GRID_WARN("Invalid number of replicas");
		return FALSE;
	}

	if (!grid_string_to_addrinfo(argv[0], &addr)) {
		namespace = strdup(argv[0]);
		GRID_INFO("[%s] considered as a namespace name", argv[0]);
	} else {
		GRID_INFO("[%s] considered as an explicit META0 address", argv[0]);
	}

	if (argc < 2) {
		GRID_NOTICE("META1 located from the conscience");
	} else {
		// meta1 addr 
		if (!urlv_check(argv+1)) {
			GRID_WARN("Invalid META1 address");
			return FALSE;
		}

		urls = g_strdupv(argv+1);
		flag_fill_v1 = TRUE;
		GRID_INFO("Ready to configure [%u] explicit META1", g_strv_length(urls));
	}
	return TRUE;
}

static void
meta0_specific_stop(void)
{
	GRID_TRACE("STOP!");
}

static struct grid_main_callbacks meta0_callbacks =
{
	.options = meta0_get_options,
	.action = meta0_action,
	.set_defaults = meta0_set_defaults,
	.specific_fini = meta0_specific_fini,
	.configure = meta0_configure,
	.usage = meta0_usage,
	.specific_stop = meta0_specific_stop,
};

int
main(int argc, char ** argv)
{
	return grid_main(argc, argv, &meta0_callbacks);
}

