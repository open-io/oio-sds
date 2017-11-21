/*
OpenIO SDS meta1v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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
#include <metautils/lib/metacomm.h>

#include "./meta1_remote.h"

static addr_info_t addr;
static gboolean flag_list = FALSE;

static const char *
meta1_usage(void)
{
	return "IP:PORT list";
}

static void
meta1_client_list(void)
{
	gchar url[64];
	grid_addrinfo_to_string(&addr, url, sizeof(url));

	GRID_INFO("List of prefixes managed by this meta1 %s",url);
	GError *err = NULL;
	gchar **result;
	guint len =0;

	err = meta1v2_remote_get_prefixes(url, &result, oio_ext_get_deadline());

	if (err != NULL) {
		GRID_WARN("META1 request error (%d) : %s", err->code, err->message);
		g_clear_error(&err);
	} else {
		if ( result == NULL || g_strv_length(result) == 0) {
			GRID_WARN("NO prefix managed by this meta1 %s.",url);
			return;
		}
		len = g_strv_length(result);
		guint i=0,done=0;
		for (i=len; i >0 ; i--,done++) {
			g_print("%s ",result[i-1]);
			if ( (done+1) % 15 == 0 && done!= 0 )
				g_print("\n");
		}
		g_print("\n");
		GRID_INFO("This meta1 %s managed %d prefixes",url,len);

	}
	GRID_INFO("End of list");
}

static void
meta1_action(void)
{
	if (flag_list) {
		meta1_client_list();
	}
}

static struct grid_main_option_s *
meta1_get_options(void)
{
	static struct grid_main_option_s meta1_options[] = {
		{NULL, 0, {.i=NULL}, NULL}
	};
	return meta1_options;
}

static void
meta1_specific_fini(void)
{
}

static void
meta1_set_defaults(void)
{
	memset(&addr, 0, sizeof(addr));
}

static gboolean
meta1_configure(int argc, char **argv)
{
	const gchar *command;

	if (argc < 2) {
		GRID_WARN("Not enough options, see usage.");
		return FALSE;
	}

	if (!grid_string_to_addrinfo(argv[0], &addr)) {
		GRID_WARN("Invalid address : (%d) %s", errno, strerror(errno));
		return FALSE;
	}

	command = argv[1];
	if (!g_ascii_strcasecmp(command, "list")) {
		flag_list = TRUE;
		return TRUE;
	}

	GRID_WARN("Invalid command, see usage.");
	return FALSE;
}

static void
meta1_specific_stop(void)
{
	GRID_TRACE("STOP!");
}

static struct grid_main_callbacks meta1_callbacks =
{
	.options = meta1_get_options,
	.action = meta1_action,
	.set_defaults = meta1_set_defaults,
	.specific_fini = meta1_specific_fini,
	.configure = meta1_configure,
	.usage = meta1_usage,
	.specific_stop = meta1_specific_stop,
};

int
main(int argc, char ** argv)
{
	return grid_main_cli (argc, argv, &meta1_callbacks);
}

