#ifndef __GRIDCLUSTER_EVENTHANDLER_H__
# define __GRIDCLUSTER_EVENTHANDLER_H__

# include <glib.h>
# include <metautils/lib/metatypes.h>
# include <cluster/events/gridcluster_events.h>

/**
 * We choosed to hide the guts of an EventHandler
 */
typedef struct gridcluster_event_handler_s gridcluster_event_handler_t;

/**
 * Causes a direct forwarding to 
 */
typedef gboolean (*gridcluster_address_forwarder_f) (gridcluster_event_t *event,
	gpointer udata, gpointer edata, GError **err, const addr_info_t *a );

/**
 * Causes a dispatching on an available service in the current namespac
 */
typedef gboolean (*gridcluster_service_forwarder_f) (gridcluster_event_t *event,
	gpointer udata, gpointer edata, GError **err, const gchar *s );

/**
 * Called on explicit drop
 */
typedef gboolean (*gridcluster_on_drop_f) (gridcluster_event_t *event,
	gpointer udata, gpointer edata, GError **err);

/**
 * Called on explicit exit or when no rule matched
 */
typedef gboolean (*gridcluster_on_exit_f) (gridcluster_event_t *event,
	gpointer udata, gpointer edata, GError **err);

struct gridcluster_event_hooks_s {
	gridcluster_address_forwarder_f on_address;
	gridcluster_service_forwarder_f on_service;
	gridcluster_on_drop_f on_drop;
	gridcluster_on_exit_f on_exit;
};

/* ------------------------------------------------------------------------- */

/**
 * Allocates an empty event handler (dropping all the event managed)
 *
 * The hooks holder will be copied in the event_handler, the caller is free
 * to pass a stacked or static structure.
 *
 * @param ns_name
 * @param err
 * @param hooks
 * @return
 */
gridcluster_event_handler_t* gridcluster_eventhandler_create(
	  const gchar *ns_name , GError **err, gpointer udata,
	  struct gridcluster_event_hooks_s *hooks);

/**
 * Destroy the given event handler. Of the content_only argument is
 * true, the pointed structure is only cleaned and reset.
 * @param h
 * @return
 */
void gridcluster_eventhandler_destroy(gridcluster_event_handler_t *h, gboolean content_only );

/**
 * Populates the ruleset with the parsed configuration
 * @param h
 * @param cfg
 * @param cfg_size
 * @param err
 * @return
 */
gboolean gridcluster_eventhandler_configure( gridcluster_event_handler_t *h, const gchar *cfg,
	gsize cfg_size, GError **err );

/**
 *
 * @param handler
 * @param err
 * @return
 */
GByteArray* gridcluster_eventhandler_get_configuration(gridcluster_event_handler_t *handler, GError **err);

/**
 * Calls gridcluster_manage_event_no_defaults() with the hooks set registered at
 * the event_handler creation.
 *
 * @param handler
 * @param event
 * @param edata
 * @param err
 * @return
 */
gboolean gridcluster_manage_event( gridcluster_event_handler_t *handler, gridcluster_event_t *event,
	gpointer edata, GError **err );

/**
 * Run the ruleset, and execute the actions of the rule whose pattern has been matched
 * by the current event 'TYPE' field.
 *
 * @param handler
 * @param event
 * @param edata
 * @param err
 * @param hooks
 * @return
 */
gboolean gridcluster_manage_event_no_defaults( gridcluster_event_handler_t *handler, gridcluster_event_t *event,
	gpointer edata, GError **err, struct gridcluster_event_hooks_s *hooks);

/**
 * Returns a GSList* of newly allocated (gchar*), representing all the
 * patterns of the managed event types.
 *
 * If a rule has a DROP as its first action, the event wont appear in the
 * list.
 *
 * @param h
 * @param err
 * @return
 */
GSList* gridcluster_eventhandler_get_patterns( gridcluster_event_handler_t *h,
	GError **err );

/**
 *
 * @param patterns
 * @param word
 * @return
 */
gboolean gridcluster_eventhandler_match_word(GSList *patterns,
	const gchar *word);

/**
 *
 * @param patterns
 * @param list_of_words
 * @return
 */
gboolean gridcluster_eventhandler_match_wordlist(GSList *patterns,
	GSList *list_of_words);

/**
 *
 * @param patterns
 * @param array_of_words
 * @return
 */
gboolean gridcluster_eventhandler_match_wordarray(GSList *patterns,
	gchar **array_of_words);

/**
 * @param patterns
 * @param list_of_words
 * @return
 */
gboolean gridcluster_eventhandler_match_wordslist(GSList *patterns,
		GSList *list_of_words);

#endif /*__GRIDCLUSTER_EVENTHANDLER_H__*/
