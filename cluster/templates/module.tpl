{{UNLESS module_name}}
#error "Invalid configuration, no module_name defined"
{{STOP}}
{{END}}
{{UNLESS module_functions}}
#error "Invalid configuration, no module_functions defined"
{{STOP}}
{{END}}
#ifndef LOG_DOMAIN
# define LOG_DOMAIN "{{module_name}}.module"
#endif

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <glib.h>

#include <metatypes.h>
#include <metautils.h>
#include <metacomm.h>

#include <plugin.h>
#include <message_handler.h>
#include <srvstats.h>
#include <srvtimer.h>

#define LOCK_STATS()   g_static_rec_mutex_lock(&mutex_stats)
#define UNLOCK_STATS() g_static_rec_mutex_unlock(&mutex_stats)
#define STAT_INCFAILURES() do { LOCK_STATS(); m2stats.failures ++; UNLOCK_STATS(); } while (0)


/* ------------------------------------------------------------------------- */

/**
 * This functions must be defined in an annex file and linked with the
 * current.
 */
extern int {{module_name}}_custom_init(GHashTable *params, GError **err);

/**
 * This functions must be defined in an annex file and linked with the
 * current.
 */
extern void {{module_name}}_custom_close(void);

/* Back-end forward declarations */
{{FOREACH f IN module_functions}}
extern {{f.return.type}} {{f.prefix}}_{{f.name}}({{FOREACH arg IN f.args}}{{arg.type}}{{IF arg.is_out}}*{{END}}, {{END}}GError **err);
{{END}}

/* ------------------------------------------------------------------------- */

struct stat_s {
	gint64 total;
	gint64 failures;
	{{FOREACH f IN module_functions}}gint64 {{f.name}};
	{{END}}
};

typedef gboolean (*_cmd_handler_f) (struct request_context_s*);

struct cmd_s {
	char *c;
	_cmd_handler_f h;
	gint64 *pCounter;
	gint64 *pTimeStat;
};

/* Message handler forward declarations*/
{{FOREACH f IN module_functions}}
static gboolean handler_{{f.name}} (struct request_context_s *req_ctx);
{{END}}

/* ------------------------------------------------------------------------- */

static GStaticRecMutex mutex_stats;
static struct stat_s counters;
static struct stat_s times;

static struct cmd_s CMD[] =
{
	{{FOREACH f IN module_functions}}{ "{{f.request_name}}", handler_{{f.name}}, &(counters.{{f.name}}), &(times.{{f.name}})},
	{{END}}
	{NULL,NULL,NULL,NULL}
};

/* ------------------------------------------------------------------------- */

{{BLOCK clean_variable-}}
	{{IF what.serializer}}{{SWITCH what.serializer}}
		{{CASE constants.SERIALIZE_STRUCT}}
		{{CASE constants.SERIALIZE_ARRAY}}
		{{CASE constants.SERIALIZE_POINTER}}if ({{what.local_name}}) {
			g_free({{what.local_name}});
			{{what.local_name}} = NULL;
		}
		{{CASE constants.SERIALIZE_STRING}}if ({{what.local_name}}) {
			g_free({{what.local_name}});
			{{what.local_name}} = NULL;
		}
		{{CASE}}{{IF what.singleton}}if ({{what.local_name}}) {
			{{what.cleaner}}({{what.local_name}},NULL);
			{{what.local_name}} = NULL;
		}{{ELSE}}if ({{what.local_name}}) {
			g_slist_foreach({{what.local_name}},{{what.cleaner}},NULL);
			g_slist_free({{what.local_name}});
			{{what.local_name}} = NULL;
		}{{END}}
	{{END}}{{END}}
{{-END}}

{{BLOCK clean_arg_variables}}
do {
	{{FOREACH arg IN function.args}}{{PROCESS clean_variable what = arg}}
	{{END}}
	{{PROCESS clean_variable what = function.return}}
} while (0);
{{END}}

{{BLOCK send_arg_to_reply}}
do {
	GByteArray *gba;
	{{IF what.singleton}}
	GSList *list;
	list = g_slist_prepend(NULL,{{what.local_name}});
	gba = {{what.marshaller}}(list,&(ctx.warning));
	g_slist_free(list);
	{{ELSE}}gba = {{what.marshaller}}({{what.local_name}},&(ctx.warning));
	{{END}}
	{{SWITCH what.message_location}}
	{{CASE 'body'}}reply_context_set_body(&ctx,gba->data,gba->len,REPLYCTX_COPY|REPLYCTX_DESTROY_ON_CLEAN);
	{{CASE 'header'}}reply_context_add_header_in_reply(&ctx,"{{what.message_name}}",gba);
	{{END}}
	g_byte_array_free(gba,TRUE);
} while (0);
{{END}}

{{FOREACH f IN module_functions}}
gboolean
handler_{{f.name}} (struct request_context_s *req_ctx)
{
	/*Declare the woking structures*/
	GTimer *timer;
	struct reply_context_s ctx;
	{{f.return.type}} result;
	{{FOREACH arg IN f.args}}{{arg.type}} {{arg.local_name}};{{END}}

	/*Initialize all the variables according to their type*/
	memset(&ctx,0x00,sizeof(ctx));
	timer = g_timer_new();
	ctx.req_ctx = req_ctx;
	
	{{-FOREACH arg IN f.args}}{{SWITCH arg.serializer}}
	{{CASE constants.SERIALIZE_STRUCT}}memset(&{{arg.local_name}},0x00,sizeof({{arg.local_name}}));
	{{CASE constants.SERIALIZE_ARRAY}}memset({{arg.local_name}},0x00,sizeof({{arg.local_name}}));
	{{CASE}}{{arg.local_name}} = 0;
	{{END}}{{END-}}
	
	{{-IF f.return.serializer}}{{SWITCH f.return.serializer}}
	{{CASE constants.SERIALIZE_STRUCT}}memset(&{{f.return.local_name}},0x00,sizeof({{f.return.local_name}}));
	{{CASE constants.SERIALIZE_ARRAY}}memset({{f.return.local_name}},0x00,sizeof({{f.return.local_name}}));
	{{CASE}}{{f.return.local_name}} = NULL;
	{{END}}{{END-}}
	
	/*Unpack the request*/
	{{FOREACH arg IN f.in_args}}
	{{SWITCH arg.message_location}}
	{{CASE 'header'}}{{PROCESS get_arg_from_header where=arg.local_name err='&(ctx.warning)' msg='req_ctx->request' arg=arg}}
	{{CASE 'body'}}{{PROCESS get_arg_from_body where=arg.local_name err='&(ctx.warning)' msg='req_ctx->request' arg=arg}}
	{{CASE}}{{STOP}}{{END}}
	{{END}}

	/*Execute the back-end function*/
	result = {{f.prefix}}_{{f.name}}({{FOREACH arg IN f.args}}{{IF arg.is_out}}&{{END}}{{arg.local_name}},{{END}}&(ctx.warning));

	/*Prepare the reply*/
	{{FOREACH arg IN f.out_args}}
		{{IF arg.on_error}}if (ctx.warning){{ELSE}}if (!ctx.warning){{END}} { {{PROCESS send_arg_to_reply what=arg}} }
	{{END}}
	{{IF f.return.serializer}}
		{{IF arg.on_error}}if (ctx.warning){{ELSE}}if (!ctx.warning){{END}} { {{PROCESS send_arg_to_reply what=f.return}} }
	{{END}}

	if (ctx.warning) {
		GSETERROR(&(ctx.warning),"Back-end function [%s] failed", "{{f.prefix}}_{{f.name}}");
		goto error_label;
	}

	/*Forward the reply*/
	reply_context_set_message(&ctx, 200, "OK");
	if (!reply_context_reply(&ctx,&(ctx.warning))) {
		GSETERROR(&(ctx.warning),"Operation successful but unable to reply to the client");
		goto error_label;
	}
	reply_context_log_access(&ctx,"");
	STOP_TIMER(timer,__FUNCTION__);

	/*Clean the working structures*/
	{{PROCESS clean_arg_variables function=f}}
	reply_context_clear (&ctx, TRUE);
	g_timer_destroy(timer);
	return TRUE;

error_label:
	reply_context_set_message(&ctx, gerror_get_code(ctx.warning), gerror_get_message(ctx.warning));
	if (!reply_context_reply(&ctx,NULL))
		GSETERROR(&(ctx.warning),"In addition, failed to reply to the client");
	ERROR("Operation '{{f.name}}' failed : %s", gerror_get_message(ctx.warning));
	reply_context_log_access(&ctx,"coming soon");
	STOP_TIMER(timer,__FUNCTION__);

        LOCK_STATS();
	counters.failures ++;
	UNLOCK_STATS();

	/*Clean the working structures*/
	{{PROCESS clean_arg_variables function=f}}
	g_timer_destroy(timer);
	reply_context_clear (&ctx, TRUE);
	return FALSE;
}
{{END}}

/* ------------------------------------------------------------------------- */

static void
plugin_update_stats (gpointer d)
{
	gdouble val;
	struct stat_s workingStats, workingTimes;

	(void)d;
	LOCK_STATS();
	memcpy (&workingStats,  &counters,  sizeof(struct stat_s));
	memcpy (&workingTimes,  &times,  sizeof(struct stat_s));
	UNLOCK_STATS();

	val = workingStats.total;
	srvstat_set ("{{module_name}}.req_counter.total", val);
	
	{{ FOREACH f IN module_functions }}
	val = workingStats.{{f.name}};
	srvstat_set ("{{module_name}}.req_counter.{{f.name}}", val);
	
	val = workingTimes.{{f.name}};
	srvstat_set ("{{module_name}}.req_time.{{f.name}}", val);
	{{END}}
}

static inline struct cmd_s*
__find_handler (gchar *n, gsize l)
{
	struct cmd_s *c;
	(void)l;
	if (!g_str_has_prefix(n,"{{FILTER uc()}}{{module_name}}{{END}}"))
		return NULL;
	for (c=CMD ; c->c && c->h ; c++) {
		if (0 == g_ascii_strcasecmp(c->c, n))
			return c;
	}
	return NULL;
}

static gint
plugin_matcher (MESSAGE m, void *param, GError **err)
{
	gchar *name;
	gsize nameLen;

	(void)param;	
	if (!m || !message_has_NAME(m, err)) {
		GSETERROR(err, "Invalid parameter (%p)", m);
		return 0;
	}

	message_get_NAME(m, (void*)&name, &nameLen, err);
	if (!name || nameLen<=0) {
		INFO("The message contains an invalid NAME parameter");
		return 0;
	}

	return (__find_handler (name, nameLen)!=NULL ? 1 : 0);
}

static gint
plugin_handler (MESSAGE m, gint cnx, void *param, GError **err)
{
	struct request_context_s ctx;
	gchar *name;
	gsize nameLen;
	struct cmd_s *cmd=NULL;
	gint rc;
	GTimer *timer;

	(void)param;
	timer = g_timer_new();
	memset(&ctx,0x00,sizeof(ctx));
	ctx.fd = cnx;
	ctx.request = m;

	LOCK_STATS();
	counters.total ++;
	UNLOCK_STATS();
	
	if (!m) {
		GSETERROR(err, "Invalid parameter");
		return 0;
	}

	message_get_NAME(m, (void*)&name, &nameLen, err);
	if (!name) {
		GSETERROR(err, "The message contains an invalid NAME parameter");
		return 0;
	}
	if (!(cmd = __find_handler (name, nameLen))) {
		GSETERROR(err, "This message does not concern this plugin.");
		return 0;
	}

	g_timer_start(timer);
	rc = cmd->h(&ctx);
	g_timer_stop(timer);

	LOCK_STATS();
	*(cmd->pCounter) = *(cmd->pCounter) + 1;
	*(cmd->pTimeStat) += g_timer_elapsed(timer, NULL) * 1000000;
	UNLOCK_STATS();

	g_timer_destroy(timer);
	return(rc);
}

static gint
plugin_init (GHashTable *params, GError **err)
{
	if (!params) {
		GSETERROR(err, "parameter param cannot be NULL");
		return 0;
	}

	g_static_rec_mutex_init(&mutex_stats);
	memset (&counters, 0x00, sizeof(counters));
	srvtimer_register_regular("{{module_name}} request counters", plugin_update_stats, NULL, NULL, 2LLU);

	if (!message_handler_add ("{{module_name}}", plugin_matcher, plugin_handler, err)) {
		GSETERROR(err,"Failed to register the plugin");
		return 0;
	}

	if (!{{module_name}}_custom_init(params,err)) {
		GSETERROR(err, "Failed to finish with the plugin custom initiation");
		return 0;
	}
	
	INFO("{{module_name}} plugin init done");
	return 1;
}

static gint
plugin_close (GError **err)
{
	(void)err;
	DEBUG("Closing the {{module_name}} plugin");
	memset (&counters, 0x00, sizeof(counters));
	{{module_name}}_custom_close();
	INFO("{{module_name}} plugin closed");
	return 1;
}

struct exported_api_s exported_symbol = 
{
	"{{module_name}}",
	plugin_init,
	plugin_close,
	NULL
};


