#ifndef __GC_EVENTHANDLER_INTERNALS_H__
# define __GC_EVENTHANDLER_INTERNALS_H__

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

#endif /*__GC_EVENTHANDLER_INTERNALS_H__*/
