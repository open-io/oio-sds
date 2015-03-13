/*
OpenIO SDS cluster
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

#ifndef OIO_SDS__cluster__events__eventhandler_internals_h
# define OIO_SDS__cluster__events__eventhandler_internals_h 1

# include <stdlib.h>
# include <string.h>
# include <stdio.h>

# include <metautils/lib/metautils.h>
# include <metautils/lib/metacomm.h>

# include <cluster/events/gridcluster_events.h>
# include <cluster/events/gridcluster_eventhandler.h>

enum gridcluster_event_actiontype_e {
	GCEAT_EXIT=1,
	GCEAT_DROP=2,
	GCEAT_SERVICE=3,
	GCEAT_ADDRESS=4,
};

struct gridcluster_eventaction_s {
	enum gridcluster_event_actiontype_e type;
	union {
		gchar service[LIMIT_LENGTH_SRVTYPE];
		addr_info_t address;
	} parameter;
};

struct gridcluster_eventrule_s {
	gchar *pattern;
	struct gridcluster_eventaction_s **actions;
};

struct gridcluster_event_handler_s {
	gchar ns_name[LIMIT_LENGTH_NSNAME];
	struct gridcluster_event_hooks_s hooks;
	gpointer user_data;
	struct gridcluster_eventrule_s **ruleset;
};

/**
 * Handy structure passed along subsequent event rules executions
 */
struct gridcluster_execution_context_s {
	gridcluster_event_t *event;
	struct gridcluster_event_handler_s *handler;
	gboolean running;
	gpointer edata;
	struct gridcluster_event_hooks_s *hooks;
};

/* ------------------------------------------------------------------------- */

static inline void
gridlcuster_eventactionset_destroy(struct gridcluster_eventaction_s **as)
{
	struct gridcluster_eventaction_s **pAction, *action;
	for (pAction=as; (action=*pAction) ;pAction++) {
		memset(action,0x00,sizeof(struct gridcluster_eventaction_s));
		g_free(action);
		*pAction = NULL;
	}
	g_free(as);
}

static inline void
gridcluster_eventruleset_destroy(struct gridcluster_eventrule_s **rs)
{
	struct gridcluster_eventrule_s **pRule, *rule;
	if (!rs)
		return;
	for (pRule=rs; *pRule ;pRule++) {
		rule=*pRule;
		if (rule->pattern)
			g_free( rule->pattern );
		if (rule->actions)
			gridlcuster_eventactionset_destroy(rule->actions);
		memset( rule, 0x00, sizeof(struct gridcluster_eventrule_s) );
		g_free( rule );
		*pRule = NULL;
	}
	g_free( rs );
}

#endif /*OIO_SDS__cluster__events__eventhandler_internals_h*/