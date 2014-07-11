{{UNLESS module_name}}
#error "Invalid configuration, no module_name defined"
{{STOP}}
{{END}}
{{UNLESS module_functions}}
#error "Invalid configuration, no module_functions defined"
{{STOP}}
{{END}}
#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "{{module_name}}.remote"
#endif

/**
 * AUTO-GENERATED!
 * DO NOT EDIT THIS DIRECTLY, IT WILL BE OVERWRITTEN
 */

#include <stdlib.h>
#include <string.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <meta2/remote/{{module_name}}_remote.h>

static MESSAGE
_build_request(GError **err, GByteArray *id, char *name)
{
	MESSAGE msg=NULL;
	message_create(&msg, err);
	if (id)
		if (!message_set_ID (msg, id->data, id->len, err)) {
			GSETERROR(err, "Failed to set message ID");
			message_destroy(msg, NULL);
			return NULL;
		}
	if (name)
		if (!message_set_NAME (msg, name, strlen(name), err)) {
			GSETERROR(err, "Failed to set message NAME");
			message_destroy(msg, NULL);
			return NULL;
		}
	return msg;
}

{{FOREACH f IN module_functions}}

{{IF f.has_out}}
struct arg_{{f.name}}_s {
	{{FOREACH arg IN f.out_args}}
		{{IF arg.is_list}}
			{{IF arg.singleton}}
				{{arg.type}} {{arg.local_name}};
			{{ELSE}}
				GSList* {{arg.local_name}};
			{{END}}
		{{ELSE}}
			{{arg.type}} {{arg.local_name}};
		{{END}}
	{{END}}

	{{IF f.return.serializer}}
		{{IF arg.is_list}}
			{{IF f.return.singleton}}
				{{f.return.type}} result;
			{{ELSE}}
				GSList *result;
			{{END}}
		{{ELSE}}
			{{f.return.type}} result;
		{{END}}
	{{END}}
};

static gboolean
msg_manager_{{f.name}}(GError ** err, gpointer udata, gint code, MESSAGE rep)
{
	struct arg_{{f.name}}_s *args;
	if (!udata || !rep) {
		GSETERROR(err,"Invalid parameter udata=%p rep=%p", (void*)udata, (void*)rep);
		return FALSE;
	}
	args = udata;
	
	{{FOREACH arg IN f.out_args}}
	{{IF arg.on_error}}if (code<200 || code>=400){{ELSE}}if (code==200 || code==206){{END}}
	{
	{{SWITCH arg.message_location}}
	{{CASE 'header'}}/* Get args->{{arg.local_name}} from the header {{arg.message_name}} */
	{{PROCESS get_arg_from_header msg='rep' where="(args -> $arg.local_name )" err='err' arg=arg}}
	{{CASE 'body'}}/* Get args->{{arg.local_name}} from the body */
	gint has_body = message_has_BODY(rep,NULL);
	if (code == 206 && 0 > has_body) {
		GSETERROR(err,"No body found in the reply");
		goto error_label;
	} else if (has_body > 0) { /*a body has been found in the message*/
		{{PROCESS get_arg_from_body msg='rep' where="(args-> $arg.local_name )" err='err' arg=arg}}
	}
	{{END}}
	}
	{{END}}

	{{IF f.return.serializer}}
	{{IF arg.on_error}}if (code<200 || code>=400){{ELSE}}if (code==200 || code==206){{END}}
	{
	{{SWITCH f.return.message_location}}
	{{CASE 'header'}}/* Get args->result from the header {{f.return.message_name}} */
	{{PROCESS get_arg_from_header msg='rep' where="(args->result )" err='err' arg=f.return}}
	{{CASE 'body'}}/* Get args->result from the body */
	{{PROCESS get_arg_from_body msg='rep' where="(args->result)" err='err' arg=f.return}}
	{{END}}
	}
	{{END}}

	return TRUE;
error_label:
	GSETERROR(err,"Reply management failure (code=%d)", code);
	return FALSE;
}
{{END}}



{{f.return.type}}
{{f.prefix}}_remote_{{f.name}}(struct metacnx_ctx_s *ctx, {{FOREACH arg IN f.args}}{{IF arg.is_out}}{{arg.type}} *{{ELSE}}{{arg.type_decl}} {{END}}{{arg.local_name}}, {{END}}GError **err)
{
	MESSAGE request;

	{{UNLESS f.return.serializer}}{{f.return.type}} status = 0;{{END}}
	{{IF f.has_out -}}
	struct arg_{{f.name}}_s args;
	struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL,         NULL, msg_manager_{{f.name}} },
		{ 206, REPSEQ_BODYMANDATORY, NULL, msg_manager_{{f.name}} },
		{ -1,  REPSEQ_ERROR,         NULL, msg_manager_{{f.name}} },
		{ 0,0,NULL,NULL}
	};
	struct reply_sequence_data_s data = { &args , 0 , codes };
	{{ELSE -}}
	struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL,         NULL, NULL },
		{ 0,0,NULL,NULL}
	};
	struct reply_sequence_data_s data = { NULL , 0 , codes };
	{{END-}}

	{{FOREACH arg IN f.out_args}}args.{{arg.local_name}} = 0;
	{{END-}}
	{{IF f.return.serializer}}args.result = NULL;{{END-}}
	
	if (!ctx{{FOREACH arg IN f.in_args}}{{SWITCH arg.serializer}}
		{{CASE constants.SERIALIZE_INTEGER}}
		{{CASE}} || !{{arg.local_name}}
		{{END}}{{END}}) {
		GSETERROR(err,"Invalid parameter");
		goto error_check;
	}

	request = _build_request( err, ctx->id, "{{f.request_name}}");
	if (!request) {
		GSETERROR(err,"Memory allocation failure");
		goto error_check;
	}

	/*prepare the request, fill all the fields*/
	{{FOREACH arg IN f.in_args}}
		{{IF arg.serializer}}
			do {
				int rc;
				GByteArray *gba;

				{{PROCESS serialize_data gba="gba" arg=arg err="err"}}
				if (!gba) {
					GSETERROR(err,"Serialization error");
					goto error_label;
				}
				{{SWITCH arg.message_location}}
				{{CASE 'body'}}
				rc = message_set_BODY(request, gba->data, gba->len, err);
				{{CASE 'header'}}
				/* empty gba not necessary an error, don't try to serialize it */
				if (gba->len > 0) {
					rc = message_add_field(request, "{{arg.message_name}}",
							sizeof("{{arg.message_name}}")-1, gba->data, gba->len, err);
				} else {
					rc = 1;
				}
				{{END}}
				g_byte_array_free(gba, TRUE);
				if (!rc) {
					GSETERROR(err,"Request configuration failure");
					goto error_label;
				}
			} while (0);
		{{END}}
	{{END}}

	/*Now send the request*/
	if (!metacnx_open(ctx, err)) {
		GSETERROR(err,"Failed to open the connexion");
		goto error_label;
	}
	if (!metaXClient_reply_sequence_run_context (err, ctx, request, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto error_label;
	}
	
	{{UNLESS f.return.serializer}}status = 1;{{END}}
error_label:
	message_destroy(request,NULL);
error_check:
	
	{{FOREACH arg IN f.out_args}}if ({{arg.local_name}})
		*{{arg.local_name}} = args.{{arg.local_name}};
	{{END}}
	
	{{IF f.return.serializer-}}
		return args.result;
	{{ELSE}}
		return status;
	{{END}}
}

{{END+}}


