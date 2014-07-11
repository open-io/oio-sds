#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.events.test"
#endif

#include <assert.h>
#include <stdlib.h>
#include <metautils/lib/metautils.h>
#include "./eventhandler_internals.h"
#define NS_NAME "ns_test"

static gchar cfg1[] = "\n" ;
static gchar cfg2[] = "\n" ;
static gchar cfg3[] = "\n" ;

static gchar *all_cfg[] = { cfg1, cfg2, cfg3, NULL };

int main( int argc, char ** args )
{
	(void) argc;
	(void) args;

	gridcluster_event_t *evt1, *evt2;
	gboolean status;
	GError *error = NULL;
	gridcluster_event_handler_t *eh = NULL;
	gchar **cfg;
	
	/* prepare two events */
	evt1 = g_hash_table_new_full( g_str_hash, g_str_equal, g_free, g_free );
	evt2 = g_hash_table_new_full( g_str_hash, g_str_equal, g_free, g_free );

	/* CREATE the EventHandler */
	eh = gridcluster_eventhandler_create( NS_NAME, &error, NULL, NULL);
	g_printerr("# gridcluster_eventhandler_create(...) %d %s\n",
		gerror_get_code(error), gerror_get_message(error));
	assert( eh );

	for (cfg=all_cfg; *cfg ;cfg++) {

		/* CONFIGURE it */
		status = gridcluster_eventhandler_configure( eh, *cfg, strlen(*cfg),
				&error);
		g_printerr("# gridcluster_eventhandler_configure(...) %d %s\n",
			gerror_get_code(error), gerror_get_message(error));
		assert( status );

		/* try to manage two events */
		status = gridcluster_manage_event( eh, evt1, NULL, &error );
		g_printerr("# gridcluster_manage_event(event1) %d %s",
			gerror_get_code(error), gerror_get_message(error));
		assert( status );

		status = gridcluster_manage_event( eh, evt2, NULL, &error );
		g_printerr("# gridcluster_manage_event(event2) %d %s",
			gerror_get_code(error), gerror_get_message(error));
		assert( status );

		/* CLEAN */
		gridcluster_eventhandler_destroy( eh, FALSE );
	}
	
	return 0;
}

