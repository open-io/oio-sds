/*
OpenIO SDS client
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <glib.h>

#include <metautils/lib/metautils.h>

#include "../lib/grid_client.h"
#include "../lib/gs_internals.h"
#include "../lib/hcadmin.h"

static gchar *g_url = NULL;
static gchar *action = NULL;
static gchar **action_args = NULL;
static gboolean flag_checkonly = FALSE;

typedef gboolean (*action_func)();
typedef void (*help_func)(void);

static void
_display_err(gchar *msg, gs_error_t *err)
{
	if(!err->msg) {
		g_printerr("Action '%s %s' failed, but no error specified.\n", g_get_prgname(), action);
		return;
	}

	if ( msg ) {
		g_printerr("%s (%d) : %s \n", msg, err->code, err->msg);
	} else {
		g_printerr("Failed to excecute action %s (%d) : %s\n", action, err->code, err->msg);
	}
}

static void
_dump_arrays(gchar **arrays)
{
	guint i;
	if (!arrays)
		return;
	for (i = 0; i < g_strv_length(arrays); i++) {
		g_print("   [%s]\n", arrays[i]);
	}
}

static void
help_touch(void)
{
	g_printerr("\n");
	g_printerr("usage: %s touch <NS>/<CONTAINER_NAME> [UPDATE_CSIZE|RECALC_CSIZE]\n", g_get_prgname());
	g_printerr("or     %s touch <NS>/<CONTAINER_NAME>/<CONTENT_NAME>\n\n", g_get_prgname());
	g_printerr("\tExecute a touch command on a container or on a simgle content\n\n");
	g_printerr("\t             NS : The namespace name\n");
	g_printerr("\t CONTAINER_NAME : The container to restore snapshot of\n");
	g_printerr("\t   CONTENT_NAME : The content to restore from the snapshot\n");
	g_printerr("\t   UPDATE_CSIZE : Option for update container_size data on meta1 by container_size from meta2 \n");
	g_printerr("\t                 (without recalculation)\n");
	g_printerr("\t   RECALC_CSIZE : Option for recalculation container_size form content_header(meta2) and update data on meta1\n");
	g_printerr("\n");
}

/* ---------------------------------------- */


static gboolean
_func_touch(void)
{
	gs_error_t *err=NULL;
	gchar **result=NULL;
	gchar *globalresult= NULL;
	err =  hcadmin_touch(g_url,action,flag_checkonly,&globalresult,&result,action_args);

	if ( err != NULL )
	{
		_display_err("Failed to apply touch cmd ",err);			
	} else {
		if ( globalresult)
			g_print("%s\n",globalresult);
		_dump_arrays(result);
	}

	return TRUE;
}

/* ---------------------------------------- */

struct action_s {
	const gchar *name;
	gboolean (*job) (void);
};

struct help_s {
	const gchar *name;
	void (*help) (void);
};

static struct action_s actions[] = {
	{"touch", _func_touch},
	{NULL,          NULL},
};

static struct help_s helps[] =
{
	{"touch", help_touch},
	{NULL,		NULL},
};

static void
_call_action()
{
	struct action_s *paction;
	for (paction=actions; paction->name ;paction++) {
		if (0 != g_ascii_strcasecmp(paction->name, action))
			continue;
		if (!paction->job())
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
hcadmin_action(void)
{
	if ( action && action[0] && g_url && g_url[0] )
		_call_action();
}

static struct grid_main_option_s *
hcadmin_get_options(void)
{
	static struct grid_main_option_s hcdir_options[] = {
		{ "Checkonly", OT_BOOL, {.b = &flag_checkonly}, "Not commit modification on data base"},
		{ NULL, 0, {.i=0}, NULL}
	};
	return hcdir_options;
}

static void
hcadmin_set_defaults(void)
{
	GRID_DEBUG("Setting defaults");
	g_url=NULL;
	action = NULL;
	action_args = NULL;
}

static void
hcadmin_specific_fini(void)
{
	g_free(g_url);
	g_free(action);
	g_strfreev(action_args);
}

static void
hcadmin_specific_stop(void)
{
}

static const gchar *
hcadmin_usage(void)
{
	return "<command> NS[/Container/Content] [<args>]\n\n"
		"The available commands are:\n"
		"\tmeta1_policy_apply\tapply the meta1 policy of replication\n"
		"\tmeta1_policy_exclude\texclude service on mechanism of meta1 replication\n"
		"\ttouch             \texecute a touch command on a container or a content on a meta2\n"
		"\n"
		"See 'help <command>' for more information on a specific command.\n\n";
}

static gboolean
hcadmin_configure(int argc, char **argv)
{
	GRID_DEBUG("Configuration");

	oio_ext_set_random_reqid();

	if (argc < 1) {
		g_printerr("Invalid arguments number\n");
		return FALSE;
	}

	action = g_strdup(argv[0]);

	// check case of help
	if (!g_ascii_strcasecmp(action, "help")) {
		if (argc >= 2) {
			return _call_help(argv[1]);
		}
	}

	if ( argc < 2 ) {
		g_print("usage: %s %s", g_get_prgname(), hcadmin_usage());
		return TRUE;
	}

	g_url = g_strdup(argv[1]);
	if (argc > 2 )
		action_args = g_strdupv(argv+2);

	return TRUE;
}

static struct grid_main_callbacks hcadmin_callbacks =
{
	.options = hcadmin_get_options,
	.action = hcadmin_action,
	.set_defaults = hcadmin_set_defaults,
	.specific_fini = hcadmin_specific_fini,
	.configure = hcadmin_configure,
	.usage = hcadmin_usage,
	.specific_stop = hcadmin_specific_stop,
};

int
main(int argc, char **args)
{
	return grid_main_cli(argc, args, &hcadmin_callbacks);
}
