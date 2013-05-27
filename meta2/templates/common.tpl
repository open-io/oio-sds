{{BLOCK serialize_data}}
do { /* BLOCK serialize_data */
	{{SWITCH arg.serializer}}
	{{CASE constants.SERIALIZE_STRUCT}}
		{{gba}} = g_byte_array_append(g_byte_array_new(), (guint8*)&{{arg.local_name}}, sizeof({{arg.type}}));
	{{CASE constants.SERIALIZE_ARRAY}}
		{{gba}} = g_byte_array_append(g_byte_array_new(), (guint8*){{arg.local_name}}, sizeof({{arg.type}}));
	{{CASE constants.SERIALIZE_POINTER}}
		{{gba}} = g_byte_array_append(g_byte_array_new(), (guint8*){{arg.local_name}}, sizeof(*{{arg.local_name}}));
	{{CASE constants.SERIALIZE_STRING}}
		{{gba}} = g_byte_array_append(g_byte_array_new(), (guint8*){{arg.local_name}}, strlen({{arg.local_name}}));
	{{CASE constants.SERIALIZE_INTEGER}}
		{{gba}} = simple_integer_marshall_gba({{arg.local_name}}, {{err}});
	{{CASE}}
		{{IF arg.is_list}}
			{{IF arg.singleton}}
				GSList *l = g_slist_prepend(NULL, {{arg.local_name}});
				{{gba}} = {{arg.marshaller}}(l, {{err}});
				g_slist_free(l);
			{{ELSE}}
				{{gba}} = {{arg.marshaller}}({{arg.local_name}}, {{err}});
			{{END}}
		{{ELSE}}
			{{gba}} = {{arg.marshaller}}({{arg.local_name}}, {{err}});
		{{END}}
	{{END}}
} while (0);
{{END}}

{{BLOCK unserialize_data}}
do { /* BLOCK unserialize_data */
	{{SWITCH arg.serializer}}
	{{CASE constants.SERIALIZE_STRUCT}}
		memcpy(&{{where}}, data, sizeof({{arg.type}}));
	{{CASE constants.SERIALIZE_ARRAY}}
		memcpy({{where}}, data, sizeof({{arg.type}}));
	{{CASE constants.SERIALIZE_POINTER}}
		{{where}} = g_memdup(data, sizeof(*{{where}}));
	{{CASE constants.SERIALIZE_STRING}}
		{{where}} = g_strndup(data, data_size);
	{{CASE constants.SERIALIZE_INTEGER}}
		gint64 my_int = 0;
		simple_integer_unmarshall((guint8*)data, data_size, &my_int);
		{{where}} = my_int;
	{{CASE}}
		{{IF arg.is_list}}
			{{IF arg.singleton}}
				GSList *l = NULL, *l_next = NULL;
				{{arg.unmarshaller}}(&l, data, &data_size, {{err}});
				if (l) {
					{{where}} = l->data;
					l->data = NULL;
					l_next = l->next;
					l->next = NULL;
					g_slist_free1(l);
					if (l_next) {
						g_slist_foreach(l_next, {{arg.cleaner}}, NULL);
						g_slist_free(l_next);
					}
				}
			{{ELSE}}
				{{arg.unmarshaller}}(&{{where}}, data, &data_size, {{err}});
			{{END}}
		{{ELSE}}
			{{arg.unmarshaller}}(&{{where}}, data, &data_size, {{err}});
		{{END}}
	{{END}}
} while (0);
{{END}}

{{BLOCK get_arg_from_header}}
do { /* BLOCK get_arg_from_header */
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
			DEBUG("Found header=[%s] [%"G_GSIZE_FORMAT"/%p]", "{{arg.message_name}}", data_size, data);
			{{PROCESS unserialize_data where=where arg=arg err="&error_local"}}
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
do { /* BLOCK get_arg_from_body */
	void *data = NULL;
	gsize data_size = 0;
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
			DEBUG("Found body [%"G_GSIZE_FORMAT"/%p]", data_size, data);
			{{PROCESS unserialize_data where=where arg=arg err="&error_local"}}
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

