%{
#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.event.config"
#endif
#include <glib.h>
#include <cluster/events/eventhandler_internals.h>
#include <cluster/lib/gridcluster.h>
#define YYLVAL event_yylval
#define YYTEXT event_yytext

#define YYERROR_VERBOSE 1
#define YY_EXTRA_TYPE   parse_parm*
#if 0
#define PARM parm
#endif
#define YYSTYPE  union parse_type_u

typedef struct parse_parm_s {
	const char *buf;
	int pos;
	int length;
	GSList *rules;
	GError *error;
} parse_parm;

union parse_type_u {
	gchar* s;
	GSList *rule_set;
	struct gridcluster_eventrule_s *rule;
	struct gridcluster_eventaction_s *action;
	GSList *action_set;
} ;

#define YYARG_DECL YY_EXTRA_TYPE parm
#define YYARG_CALL parm

static int event_yylex(YYSTYPE *, YYARG_DECL);
static void event_yyerror(YYARG_DECL, char const *m);

#if 0
static int yylex_init(void **);
static int yylex_destroy(void *);
#endif

static struct gridcluster_eventrule_s* __make_rule( YYARG_DECL, const gchar *pattern, GSList *actions);

static struct gridcluster_eventaction_s* __make_action_stop( YYARG_DECL );

static struct gridcluster_eventaction_s* __make_action_drop( YYARG_DECL );

static struct gridcluster_eventaction_s* __make_action_forward_to_address(YYARG_DECL, const gchar *word);

static struct gridcluster_eventaction_s* __make_action_forward_to_service(YYARG_DECL, const gchar *word);

%}
%pure_parser
%parse-param {YY_EXTRA_TYPE parm}
%lex-param {YY_EXTRA_TYPE parm}
%token SEMICOLON_TK EQUAL_TK COMA_TK
%token ADDRESS_TK SERVICE_TK EXIT_TK DROP_TK
%token <s> WORD_TK
%type  <rule> rule
%type  <rule_set> rule_set
%type  <action> action
%type  <action_set> action_set
%start input
%%
input: rule_set { TRACE("'input' rule parsed, %d rules\n", g_slist_length($1)); parm->rules = g_slist_reverse($1); }

rule: WORD_TK EQUAL_TK action_set {
		TRACE("'rule' rule parsed ()\n");
		$$ = __make_rule(YYARG_CALL,$1,g_slist_reverse($3));
		g_free($1);
		if (!$$) {
			event_yyerror(YYARG_CALL,"Failed to build a set of EventRule");
			YYABORT;
		}
	}
	
rule_set: { TRACE("'rule_set' rule parsed (empty rule)\n"); $$ = NULL; }
	| rule { TRACE("'rule_set' rule parsed (single rule)\n"); $$ = g_slist_prepend(NULL,$1); }
	| rule_set SEMICOLON_TK rule { TRACE("'rule_set' rule parsed ()\n"); $$ = g_slist_prepend($1,$3); }
	
action:   EXIT_TK            { TRACE("'action' rule parsed (exit)\n"); $$ = __make_action_stop(YYARG_CALL); }
	| DROP_TK            { TRACE("'action' rule parsed (drop)\n"); $$ = __make_action_drop(YYARG_CALL); }
	| ADDRESS_TK WORD_TK { TRACE("'action' rule parsed (addr)\n"); $$ = __make_action_forward_to_address(YYARG_CALL,$2); g_free($2); }
	| SERVICE_TK WORD_TK { TRACE("'action' rule parsed (serv)\n"); $$ = __make_action_forward_to_service(YYARG_CALL,$2); g_free($2); }

action_set: action { TRACE("'action_set' rule parsed (single action)\n"); $$ = g_slist_prepend(NULL,$1); } 
	|   action_set COMA_TK action { TRACE("'action_set' rule parsed (action sequence)\n"); $$ = g_slist_prepend($1,$3); }

%%

/* ------------------------------------------------------------------------- */

struct gridcluster_eventrule_s*
__make_rule( YYARG_DECL, const gchar *pattern, GSList *actions)
{
	GSList *le;
	int i;
	gchar error_buffer[1024];
	struct gridcluster_eventrule_s *rule;
	
	TRACE("Building a rule of %u actions\n", g_slist_length(actions));
	
	rule = g_try_malloc0( sizeof(struct gridcluster_eventrule_s) );
	if (!rule) {
		g_snprintf(error_buffer,sizeof(error_buffer),
			"Memory allocation failure at (%s,%d)", __FILE__, __LINE__);
		goto errorLabel;
	}

	rule->pattern = g_strdup(pattern);
	rule->actions = g_try_malloc0( sizeof(void*) * (1+g_slist_length(actions)) );
	if (!rule->actions) {
		g_snprintf(error_buffer,sizeof(error_buffer),
			"Memory allocation failure at (%s,%d)", __FILE__, __LINE__);
		goto errorLabel;
	}
	
	for (i=0,le=actions; le ; le=g_slist_next(le)) {
		if (le->data)
			rule->actions[ i++ ] = (struct gridcluster_eventaction_s*) le->data;
		le->data = NULL;
	}

	g_slist_free(actions);
	return rule;

errorLabel:	
	if (rule->pattern)
		g_free( rule->pattern );
	if (rule->actions)
		g_free( rule->actions );
	event_yyerror(YYARG_CALL,error_buffer);
	return NULL;
}

struct gridcluster_eventaction_s*
__make_action_drop( YYARG_DECL )
{
	gchar error_buffer[1024];
	struct gridcluster_eventaction_s *action;

	action = g_try_malloc0( sizeof(struct gridcluster_eventaction_s) );
	if (!action) {
		g_snprintf(error_buffer,sizeof(error_buffer),
			"Memory allocation failure at (%s,%d)", __FILE__, __LINE__);
		goto errorLabel;
	}
	action->type = GCEAT_DROP;
	return action;
errorLabel:
	event_yyerror(YYARG_CALL,error_buffer);
	if (action)
		g_free(action);
	return NULL;
}

struct gridcluster_eventaction_s*
__make_action_stop( YYARG_DECL )
{
	gchar error_buffer[1024];
	struct gridcluster_eventaction_s *action;

	action = g_try_malloc0( sizeof(struct gridcluster_eventaction_s) );
	if (!action) {
		g_snprintf(error_buffer,sizeof(error_buffer),
			"Memory allocation failure at (%s,%d)", __FILE__, __LINE__);
		goto errorLabel;
	}
	action->type = GCEAT_EXIT;
	return action;
errorLabel:
	event_yyerror(YYARG_CALL,error_buffer);
	if (action)
		g_free(action);
	return NULL;
}

struct gridcluster_eventaction_s*
__make_action_forward_to_address( YYARG_DECL, const gchar *word)
{
	GError *error_local = NULL;
	gchar error_buffer[1024];
	struct gridcluster_eventaction_s *action;

	action = g_try_malloc0( sizeof(struct gridcluster_eventaction_s) );
	if (!action) {
		g_snprintf(error_buffer,sizeof(error_buffer),
			"Memory allocation failure at (%s,%d)", __FILE__, __LINE__);
		goto errorLabel;
	}

	action->type = GCEAT_ADDRESS;
	if (!l4_address_init_with_url(&(action->parameter.address), word, NULL)) {
		g_snprintf(error_buffer,sizeof(error_buffer), "Invalid address format");
		goto errorLabel;
	}
	if (error_local)
		g_error_free(error_local);
	return action;
errorLabel:
	event_yyerror(YYARG_CALL,error_buffer);
	if (action)
		g_free(action);
	if (error_local)
		g_error_free(error_local);
	return NULL;
}

struct gridcluster_eventaction_s*
__make_action_forward_to_service( YYARG_DECL, const gchar *word)
{
	gchar error_buffer[1024];
	struct gridcluster_eventaction_s *action;

	action = g_try_malloc0( sizeof(struct gridcluster_eventaction_s) );
	if (!action) {
		g_snprintf(error_buffer,sizeof(error_buffer),
			"Memory allocation failure at (%s,%d)", __FILE__, __LINE__);
		goto errorLabel;
	}

	action->type = GCEAT_SERVICE;
	g_strlcpy( action->parameter.service, word, sizeof(action->parameter.service) ); 
	return action;
errorLabel:
	event_yyerror(YYARG_CALL,error_buffer);
	if (action)
		g_free(action);
	return NULL;
}

void
event_yyerror(YYARG_DECL, char const *m)
{
	(void) parm;
	fprintf(stderr,"%s\n", m);
}

int
event_yylex(YYSTYPE *arg1, YYARG_DECL)
{
	gboolean comment=FALSE;

	while (parm->pos<parm->length) {
		char c = parm->buf[parm->pos++];
		if (c=='\n') {
			comment = FALSE;
		}
		if (comment) {
			comment = TRUE;
		}
		else if (!g_ascii_isspace(c)) { /*skip white space*/
			switch (c) {
				case '#':
					comment = TRUE;
					break;
				case ',':
					return COMA_TK;
				case ';':
					return SEMICOLON_TK;
				case '=':
					return EQUAL_TK;
				default: 
					{
						char *word;
						int start_position, word_length;

						start_position = parm->pos-1;
						for ( ; parm->pos<parm->length ; parm->pos++) {
							char _c = parm->buf[parm->pos];
							if (g_ascii_isspace(_c))
								break;
							if (_c=='#' || _c==',' || _c==';' || _c=='=')
								break;
						}
						word_length = parm->pos - start_position;
						word = g_alloca(word_length+1);
						memcpy(word, parm->buf+start_position, word_length);
						word[word_length]='\0';
						if (0==g_ascii_strcasecmp(word,"exit"))
							return EXIT_TK;
						if (0==g_ascii_strcasecmp(word,"drop"))
							return DROP_TK;
						if (0==g_ascii_strcasecmp(word,"service"))
							return SERVICE_TK;
						if (0==g_ascii_strcasecmp(word,"address"))
							return ADDRESS_TK;
						arg1->s = g_strdup(word);
						return WORD_TK;
					}
			}
		}
	}
	
	TRACE("END_OF_INPUT\n");
	return 0;
}

gboolean
gridcluster_eventhandler_configure(
	gridcluster_event_handler_t *h, const gchar *cfg, gsize cfg_size,
	GError **err )
{
	int ret=1, i;
	parse_parm  pp;
	GSList *le=NULL;

	if (!h || !cfg) {
		GSETERROR(err,"Invalid parameter (%p %p)", h, cfg);
		return FALSE;
	}

	memset(&pp, 0x00, sizeof(pp));
	pp.buf = cfg;
	pp.length = cfg_size;

	ret = event_yyparse(&pp);

	if (ret) {
		GSETERROR(err, "Failed to parse the configuration string");
		return FALSE;
	}

	if (h->ruleset) {
		gridcluster_eventruleset_destroy( h->ruleset );
		h->ruleset = NULL;
	}

	h->ruleset = g_try_malloc0( sizeof(struct gridcluster_eventrule_s*) * (1+g_slist_length(pp.rules)));
	for (i=0,le=pp.rules; le ;le=le->next) {
		if (le->data) {
			h->ruleset[ i++ ] = (struct gridcluster_eventrule_s*) le->data;
			le->data = NULL;
		}
	}

	DEBUG("[NS=%s] Configured the event_handler with [%d] rules", h->ns_name, i);
	g_slist_free(pp.rules);

	return TRUE;
}

