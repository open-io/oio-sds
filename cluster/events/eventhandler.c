#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.event.handler"
#endif /*G_LOG_DOMAIN*/

#include <fnmatch.h>

#include "./eventhandler_internals.h"

gridcluster_event_handler_t *
gridcluster_eventhandler_create(const gchar * ns_name, GError ** err, gpointer udata,
    struct gridcluster_event_hooks_s *hooks)
{
	gridcluster_event_handler_t *result;

	(void) udata;
	if (!ns_name) {
		GSETERROR(err, "Invalid namespace name");
		return NULL;
	}

	if (!hooks)
		DEBUG("No default hooks for namespace=%s", ns_name);
	else if (DEBUG_ENABLED()) {
		if (!hooks->on_service)
			DEBUG("Default on-address hook disabled (namepsace=%s)", ns_name);
		if (!hooks->on_address)
			DEBUG("Default on-service hook disabled (namepsace=%s)", ns_name);
		if (!hooks->on_drop)
			DEBUG("Default on-drop hook disabled (namepsace=%s)", ns_name);
		if (!hooks->on_exit)
			DEBUG("Default on-exit hook disabled (namepsace=%s)", ns_name);
	}

	result = g_try_malloc0(sizeof(struct gridcluster_event_handler_s));
	if (!result) {
		GSETERROR(err, "Memory allocation failure");
		return NULL;
	}

	g_strlcpy(result->ns_name, ns_name, LIMIT_LENGTH_NSNAME);
	if (hooks)
		memcpy(&(result->hooks), hooks, sizeof(struct gridcluster_event_hooks_s));

	return result;
}

void
gridcluster_eventhandler_destroy(gridcluster_event_handler_t * h, gboolean content_only)
{
	if (!h)
		return;
	if (h->ruleset) {
		gridcluster_eventruleset_destroy(h->ruleset);
		h->ruleset = NULL;
	}
	memset(h, 0x00, sizeof(gridcluster_event_handler_t));
	if (!content_only)
		g_free(h);
}

static inline gboolean
gridcluster_event_execute_DROP(struct gridcluster_execution_context_s *ctx, GError ** err)
{
	ctx->running = FALSE;
	if (!ctx->hooks->on_exit)
		DEBUG("No 'on_drop' hook configured");
	else if (!ctx->hooks->on_drop(ctx->event, ctx->handler->user_data, ctx->edata, err)) {
		GSETERROR(err,"'on_drop' hook failed");
		return FALSE;
	}
	return TRUE;
}

static inline gboolean
gridcluster_event_execute_EXIT(struct gridcluster_execution_context_s *ctx, GError **err)
{
	ctx->running = FALSE;
	if (!ctx->hooks->on_exit)
		DEBUG("No 'on_exit' hook configured");
	else if (!ctx->hooks->on_exit(ctx->event, ctx->handler->user_data, ctx->edata, err)) {
		GSETERROR(err,"'on_exit' hook failed");
		return FALSE;
	}
	return TRUE;
}

static inline gboolean
gridcluster_event_execute_ADDRESS(const addr_info_t *addr, struct gridcluster_execution_context_s *ctx, GError ** err)
{
	if (!ctx->hooks->on_address)
		INFO("Event dropped (no forward_to_address handler)");
	else if (!ctx->hooks->on_address(ctx->event, ctx->handler->user_data, ctx->edata, err, addr)) {
		gsize str_size;
		gchar str[STRLEN_ADDRINFO];

		str_size = addr_info_to_string(addr, str, sizeof(str));
		GSETERROR(err, "Failed to forward the event to the address [%.*s]", str_size, str);
		return FALSE;
	}
	return TRUE;
}

static inline gboolean
gridcluster_event_execute_SERVICE(const gchar *srv_name, struct gridcluster_execution_context_s *ctx, GError **err)
{
	if (!ctx->hooks->on_service)
		INFO("Event dropped (no forward_to_service handler)");
	else if (!ctx->hooks->on_service(ctx->event, ctx->handler->user_data, ctx->edata, err, srv_name)) {
		GSETERROR(err, "Failed to forward the event to the service [%s]", srv_name);
		return FALSE;
	}
	return TRUE;
}

gboolean
gridcluster_manage_event_no_defaults(gridcluster_event_handler_t *handler, gridcluster_event_t *event,
	gpointer edata, GError **err, struct gridcluster_event_hooks_s *hooks)
{
	GByteArray *gba_type;
	gchar *event_type;
	struct gridcluster_execution_context_s ctx;
	struct gridcluster_eventrule_s **pRule, *rule;

	/*sanity checks*/
	if (!handler || !event) {
		GSETERROR(err,"Invalid parameter");
		return FALSE;
	}
	gba_type = g_hash_table_lookup( event, "TYPE" );
	if (!gba_type) {
		GSETERROR(err,"Event field [type] undefined (mandatory!!!)");
		return FALSE;
	}
	if (!handler->ruleset) {
		DEBUG("Empty RuleSet, no match possible");
		return TRUE;
	}
	
	event_type = g_alloca(gba_type->len+1);
	memcpy(event_type, gba_type->data, gba_type->len);
	event_type[gba_type->len] = '\0';

	/*prepare the execution context*/
	memset( &ctx, 0x00, sizeof(struct gridcluster_execution_context_s) );
	ctx.event = event;
	ctx.handler = handler;
	ctx.running = TRUE;
	ctx.edata = edata;
	ctx.hooks = hooks;

	/*evaluate the expression list for explicit actions*/
	for (pRule=handler->ruleset; ctx.running && (rule=*pRule); pRule++) {
		if (!rule->pattern)
			WARN("NULL rule pattern!");
		else if (!rule->actions)
			DEBUG("Empty ActionSet for this Rule, no nedd to match");
		else {
			struct gridcluster_eventaction_s **pAction, *action;
			if (DEBUG_ENABLED()) {
				GByteArray *gba_message = g_byte_array_new();
				for (pAction=rule->actions; ctx.running && (action=*pAction) ;pAction++) {
					switch (action->type) {
						case GCEAT_DROP:
							g_byte_array_append(gba_message, (guint8*)",drop", (guint) sizeof(",drop")-1);
							break;
						case GCEAT_EXIT:
							g_byte_array_append(gba_message, (guint8*)",exit", (guint) sizeof(",exit")-1);
							break;
						case GCEAT_ADDRESS:
							g_byte_array_append(gba_message, (guint8*)",address", (guint) sizeof(",address")-1);
							break;
						case GCEAT_SERVICE:
							g_byte_array_append(gba_message, (guint8*)",service", (guint) sizeof(",service")-1);
							break;
						default:
							break;
					}
				}
				DEBUG("Rule: %s = %.*s", rule->pattern, gba_message->len, gba_message->data);
				g_byte_array_free(gba_message, TRUE);
			}
			
			if (0 != fnmatch( rule->pattern, event_type, FNM_CASEFOLD))
				TRACE("Event type '%s' does not match pattern '%s'", event_type, rule->pattern);
			else {
				TRACE("Event type '%s' matches pattern '%s'", event_type, rule->pattern);

				for (pAction=rule->actions; ctx.running && (action=*pAction) ;pAction++) {
					switch (action->type) {
						case GCEAT_DROP:
							return gridcluster_event_execute_DROP(&ctx, err);
						case GCEAT_EXIT:
							return gridcluster_event_execute_EXIT(&ctx, err);
						case GCEAT_SERVICE:
							if (!gridcluster_event_execute_SERVICE(action->parameter.service, &ctx, err)) {
								GSETERROR(err,"'address' action execution failure");
								return FALSE;
							}
							break;
						case GCEAT_ADDRESS:
							if (!gridcluster_event_execute_ADDRESS(&(action->parameter.address), &ctx, err)) {
								GSETERROR(err,"'service' action execution failure");
								return FALSE;
							}
							break;
						default:
							GSETERROR(err, "EventAction with type [%d] not implemented", action->type);
							return FALSE;
					}
				}
			}
		}
	}

	/*no explicit action found, executing an implicit exit*/
	if (!gridcluster_event_execute_EXIT(&ctx, err)) {
		GSETERROR(err,"Implicit 'on_exit' hook failed");
		return FALSE;
	}

	return TRUE;
}

gboolean
gridcluster_manage_event( gridcluster_event_handler_t *h, gridcluster_event_t *e, gpointer edata, GError **err)
{
	if (!h || !e) {
		GSETERROR(err,"Invalid parameter (%p,%p)", h, e);
		return FALSE;
	}
	return gridcluster_manage_event_no_defaults(h, e, edata, err, &(h->hooks));
}

GByteArray*
gridcluster_eventhandler_get_configuration(gridcluster_event_handler_t *h, GError **err)
{
	GByteArray *gba_config;
	gchar buffer[1024];
	gsize buffer_size;

	if (!h) {
		GSETERROR(err,"Invalid parameter (NULL eventhandler)");
		return NULL;
	}
	
	/* Writes a header */
	gba_config = g_byte_array_new();
	
	/* write each rule on one line */
	if (h->ruleset) {
		struct gridcluster_eventrule_s **rule_pointer;
		for (rule_pointer=h->ruleset; *rule_pointer ;rule_pointer++) {
			gboolean first_action_met = FALSE;
			struct gridcluster_eventrule_s *rule;
			struct gridcluster_eventaction_s **action_pointer;
			
			rule = *rule_pointer;
			g_byte_array_append(gba_config, (guint8*) rule->pattern, strlen(rule->pattern));
			g_byte_array_append(gba_config, (guint8*) "=", 1);
			for (action_pointer=rule->actions; action_pointer && *action_pointer ; action_pointer++) {
				struct gridcluster_eventaction_s *action;
				action = *action_pointer;
				
				if (first_action_met)
					g_byte_array_append(gba_config, (guint8*) ",", 1);
				else
					first_action_met = TRUE;

				switch (action->type) {
				case GCEAT_EXIT:
					g_byte_array_append(gba_config, (guint8*)"exit", sizeof("exit")-1);
					break;
				case GCEAT_DROP:
					g_byte_array_append(gba_config, (guint8*)"drop", sizeof("drop")-1);
					break;
				case GCEAT_SERVICE:
					g_byte_array_append(gba_config, (guint8*)"service ", sizeof("service ")-1);
					g_byte_array_append(gba_config, (guint8*)action->parameter.service, strlen(action->parameter.service));
					break;
				case GCEAT_ADDRESS:
					g_byte_array_append(gba_config, (guint8*)"address ", sizeof("address ")-1);
					buffer_size = addr_info_to_string(&(action->parameter.address), buffer, sizeof(buffer));
					g_byte_array_append(gba_config, (guint8*)buffer, buffer_size);
					break;
				}
			}
	
			if (*(rule_pointer+1))
				g_byte_array_append(gba_config, (guint8*)";\n", 2);
			else
				g_byte_array_append(gba_config, (guint8*)"\n", 1);
		}
	}

	return gba_config;
}

/* ------------------------------------------------------------------------- */

GSList*
gridcluster_eventhandler_get_patterns(gridcluster_event_handler_t *h, GError **err)
{
	struct gridcluster_eventrule_s **pRule;
	GSList *result = NULL;
	
	if (!h) {
		GSETERROR(err,"Invalid parameter");
		return NULL;
	}

	if (!h->ruleset)
		return NULL;

	for (pRule=h->ruleset; *pRule ;pRule++) {
		gchar *pattern;
		pattern = (*pRule)->pattern;
		if (pattern)
			result = g_slist_prepend( result, g_strdup(pattern) );
	}

	return result;
}

gboolean
gridcluster_eventhandler_match_word(GSList *patterns, const gchar *word)
{
	GSList *l;
	if (!patterns || !word || !*word)
		return FALSE;
	for (l=patterns; l ;l=l->next) {
		if (!l->data)
			continue;
		if (!fnmatch(l->data, word, 0))
			return TRUE;
	}
	return FALSE;
}

gboolean
gridcluster_eventhandler_match_wordslist(GSList *patterns, GSList *list_of_words)
{
	GSList *l;
	if (!patterns || !list_of_words)
		return FALSE;
	for (l=list_of_words; l ;l=l->next) {
		if (gridcluster_eventhandler_match_word(patterns,l->data))
			return TRUE;
	}
	return FALSE;
}

gboolean
gridcluster_eventhandler_match_wordarray(GSList *patterns, gchar **array_of_words)
{
	gchar **p_word;
	if (!patterns || !array_of_words)
		return FALSE;
	for (p_word=array_of_words; *p_word ;p_word++) {
		if (gridcluster_eventhandler_match_word(patterns,*p_word))
			return TRUE;
	}
	return FALSE;
}

