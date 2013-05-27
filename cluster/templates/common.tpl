{{BLOCK copy_data}}{{SWITCH arg.serializer}}
{{CASE constants.SERIALIZE_STRUCT}}memcpy(&{{where}}, data, sizeof({{arg.type}}));
{{CASE constants.SERIALIZE_ARRAY}}memcpy({{where}}, data, sizeof({{arg.type}}));
{{CASE constants.SERIALIZE_POINTER}}{{where}} = g_memdup(data, sizeof(*{{where}}));
{{CASE constants.SERIALIZE_STRING}}{{where}} = g_strndup(data, data_size);
{{CASE}}{{arg.unmarshaller}}(&{{where}}, data, &data_size, {{err}});
{{END}}{{END}}

{{BLOCK get_arg_from_header}}
do {
	void *data;
	gsize data_size;
	data = NULL;
	data_size = 0;
	switch (message_get_field({{msg}}, "{{arg.message_name}}", sizeof("{{arg.message_name}}")-1, &data, &data_size, {{err}})) {
	case -1:
		GSETCODE({{err}}, 400, "Invalid message, missing field [%s]", "{{arg.message_name}}");
		goto error_label;
	case 0:
		{{IF arg.mandatory}}GSETCODE({{err}}, 400, "Invalid ASN.1 message, missing field [%s]", "{{arg.message_name}}");
		goto error_label;
		{{ELSE}}DEBUG("Optional field [%s] not found", "{{arg.message_name}}");
		break;{{END}}
	default:
		{
			GError *error_local;

			error_local = NULL;
			DEBUG("Found header=[%s] [%u/%p]", "{{arg.message_name}}", data_size, data);
			{{PROCESS copy_data where=where arg=arg err="&error_local"}}
			if (error_local) {
				GSETERROR({{err}}, "Cause: %s", gerror_get_message(error_local));
				GSETERROR({{err}}, "Invalid ASN.1 message : ");
				g_error_free(error_local);
				goto error_label;
			}
		}
		break;
	}
} while (0);
{{END}}

{{BLOCK get_arg_from_body}}
do {
	void *data;
	gsize data_size;
	data = NULL;
	data_size = 0;
	switch (message_get_BODY({{msg}}, &data, &data_size, {{err}})) {
	case -1:
		GSETCODE({{err}}, 400, "Invalid ASN.1 message, failed to extract the body");
		goto error_label;
	case 0:
		{{IF arg.mandatory-}}
		GSETCODE({{err}}, 400, "Invalid ASN.1 message, missing body");
		goto error_label;
		{{ELSE-}}
		DEBUG("Optional body not found");
		break;
		{{END}}
	default:
		{
			GError *error_local;

			error_local = NULL;
			DEBUG("Found body [%u/%p]", data_size, data);
			{{PROCESS copy_data where=where arg=arg err="&error_local"}}
			if (error_local) {
				GSETERROR({{err}}, "Cause: %s", gerror_get_message(error_local));
				GSETERROR({{err}}, "Invalid ASN.1 message : ");
				g_error_free(error_local);
				goto error_label;
			}
		}
		break;
	}
} while (0);
{{END}}

