#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "meta1.remote"
#endif

#include <metautils/lib/metautils.h>

#include "./internals.h"
#include "./meta1_remote.h"

#define GBA_POOL_CLEAN(P) do { \
	if (P) { \
		g_slist_foreach((P), metautils_gba_gunref, NULL); \
		g_slist_free((P)); \
		(P) = NULL; \
	} \
} while (0)

static GByteArray *
gba_poolify(GSList **pool, GByteArray *gba)
{
	if (!gba)
		return NULL;
	*pool = g_slist_prepend(*pool, gba);
	return gba;
}

static gboolean
cid_handler_list (GError **err, gpointer udata, gint code,
		guint8 *body, gsize bodySize)
{
	(void) code;
	GSList **ppResL, *pResL, *list, *pL;

	if (!udata || !body || bodySize<=0) {
		GSETERROR(err,"Invalid parameter (%p %p %u)", udata, body, bodySize);
		return FALSE;
	}

	ppResL = (GSList**) udata;
	if (!ppResL) {
		GSETERROR(err,"invalid parameter");
		return FALSE;
	}

	list = meta2_maintenance_sized_arrays_unmarshall_buffer (body, bodySize, sizeof(container_id_t), err);

	if (!list) {
		GSETERROR (err, "Cannot unserialize the content of the reply");
		return FALSE;
	}

	TRACE("Arrays sequence unserialized, %d elements!", g_slist_length(list));
	pResL = *ppResL;
	for (pL=list; pL ;pL=g_slist_next(pL)) {
		if (pL->data)
			pResL = g_slist_prepend( pResL, pL->data );
	}

	*ppResL = pResL;
	g_slist_free( list );
	return TRUE;
}

static gboolean
extract_raw_container(GError **err, gpointer udata, gint code, guint8 *body, gsize bodySize)
{
	(void) code;
	struct meta1_raw_container_s *raw_container = NULL;

	if (!body || bodySize<sizeof(struct meta1_raw_container_s))
		return FALSE;

	raw_container = meta1_raw_container_unmarshall(body, bodySize, err);

	memcpy(udata, raw_container, sizeof(struct meta1_raw_container_s));

	g_free(raw_container);

	return TRUE;
}

static gboolean
arrays_handler_list (GError **err, gpointer udata, gint code,
		guint8 *body, gsize bodySize)
{
	(void) code;
	GSList **ppResL, *pResL, *list, *pL;

	if (!udata || !body || bodySize<=0) {
		GSETERROR(err,"Invalid parameter (%p %p %u)", udata, body, bodySize);
		return FALSE;
	}

	ppResL = (GSList**) udata;
	if (!ppResL) {
		GSETERROR(err,"invalid parameter");
		return FALSE;
	}

	list = meta2_maintenance_arrays_unmarshall_buffer (body, bodySize, err);

	if (!list) {
		GSETERROR (err, "Cannot unserialize the content of the reply");
		return FALSE;
	}

	TRACE("Arrays sequence unserialized, %d elements!", g_slist_length(list));
	pResL = *ppResL;
	for (pL=list; pL ;pL=g_slist_next(pL)) {
		if (pL->data)
			pResL = g_slist_prepend( pResL, pL->data );
	}

	*ppResL = pResL;
	g_slist_free( list );
	return TRUE;
}

static gboolean
kv_handler_list (GError **err, gpointer udata, gint code,
		guint8 *body, gsize bodySize)
{
	(void) code;
	GSList *list = NULL;
	GHashTable **ppResL = NULL;
	GHashTable *table = NULL;
	gboolean status = FALSE;

	if (!udata) {
		GSETERROR(err,"Invalid parameter (%p)", udata);
		return status;
	}

	if(code == 200 && (!body || bodySize <= 0)) {
		GSETERROR(err,"Invalid parameter (%p, %p)", body, bodySize);
		return status;
	}

	ppResL = (GHashTable**) udata;
	if (!ppResL) {
		GSETERROR(err,"invalid parameter");
		return status;
	}

	if(code == 200) {
		DEBUG("Code = 200, unmarshalling");
		if (0 >= key_value_pairs_unmarshall(&list, body, &bodySize, err)) {
			GSETERROR (err, "Cannot unserialize the content of the reply");
			goto errorLabel;
		}

		table = key_value_pairs_convert_to_map(list, TRUE, err);
		if (!table) {
			GSETERROR (err, "Cannot unserialize the content of the reply");
			goto errorLabel;
		}

		DEBUG("Response body parsed, %d elements", g_hash_table_size(table));

		*ppResL = table;
	} else
		DEBUG("Handling code 204, ok nothing to do");

	status = TRUE;

errorLabel:

	if (list) {
		g_slist_foreach(list, key_value_pair_gclean, NULL);
		g_slist_free(list);
	}

	return status;
}

static gboolean
strings_handler_list (GError **err, gpointer udata, gint code,
		guint8 *body, gsize bodySize)
{
	(void) code;
	GSList **ppResL, *list = NULL;

	if (!udata || !body || bodySize<=0) {
		GSETERROR(err,"Invalid parameter (%p %p %u)", udata, body, bodySize);
		return FALSE;
	}

	ppResL = (GSList**) udata;
	if (!ppResL) {
		GSETERROR(err,"invalid parameter");
		return FALSE;
	}

	if (!strings_unmarshall(&list, body, &bodySize, err)) {
		GSETERROR (err, "Cannot unserialize the content of the reply");
		return FALSE;
	}

	if (TRACE_ENABLED()) {
		TRACE("Arrays sequence unserialized, %d elements!", g_slist_length(list));
	}

	do {
		GSList *pResL, *pL;
		pResL = *ppResL;
		for (pL=list; pL ;pL=pL->next)
			pResL = g_slist_prepend(pResL, pL->data);
		*ppResL = pResL;
	} while (0);

	g_slist_free(list);
	return TRUE;
}

typedef enum meta1_operation_e
{
	M1_OP_CREATE,
	M1_OP_DESTROY,
	M1_OP_GET,
	M1_OP_GETFLAGS,
	M1_OP_SETFLAGS,

	M1_OP_RANGE_GET,
	M1_OP_RANGE_DEL,
	M1_OP_RANGE_ADD,
	M1_OP_RANGE_SET,
	M1_OP_RANGE_LIST,

	M1_OP_GETALLONM2,
	M1_OP_FORCECREATE,
	M1_OP_GETCONTBYID,
	M1_OP_GETCONTBYNAME,
	M1_OP_GETCONTMATCHING,
	M1_OP_UPDCONT,
	M1_OP_GETVNSSTATE,
	
	M1V2_OP_CREATE,
	M1V2_OP_DESTROY,
	M1V2_OP_HAS,
	M1V2_OP_SRVAVAIL,
	M1V2_OP_SRVALL,
	M1V2_OP_SRVDEL,
	M1V2_OP_SETPROP,
	M1V2_OP_GETPROP,
	M1V2_OP_DELPROP

} meta1_operation_t;


static gint __get_request_name1 (meta1_operation_t mo, gchar **str, gsize *len)
{
#define SETSTR(S) do { *str=S; *len=sizeof(S)-1; } while (0)
	switch (mo)
	{
		case M1_OP_CREATE:    SETSTR(NAME_MSGNAME_M1_CREATE);    return 1;
		case M1_OP_DESTROY:   SETSTR(NAME_MSGNAME_M1_DESTROY);   return 1;
		case M1_OP_GET:       SETSTR(NAME_MSGNAME_M1_GET);       return 1;
		case M1_OP_GETFLAGS:  SETSTR(NAME_MSGNAME_M1_GETFLAGS);  return 1;
		case M1_OP_SETFLAGS:  SETSTR(NAME_MSGNAME_M1_SETFLAGS);  return 1;

		case M1_OP_RANGE_GET:  SETSTR(NAME_MSGNAME_M1_RANGE_GET);  return 1;
		case M1_OP_RANGE_DEL:  SETSTR(NAME_MSGNAME_M1_RANGE_DEL);  return 1;
		case M1_OP_RANGE_ADD:  SETSTR(NAME_MSGNAME_M1_RANGE_ADD);  return 1;
		case M1_OP_RANGE_SET:  SETSTR(NAME_MSGNAME_M1_RANGE_SET);  return 1;
		case M1_OP_RANGE_LIST: SETSTR(NAME_MSGNAME_M1_RANGE_LIST); return 1;

		case M1_OP_GETALLONM2:  SETSTR(NAME_MSGNAME_M1_GETALLONM2); return 1;
		case M1_OP_FORCECREATE: SETSTR(NAME_MSGNAME_M1_FORCECREATE); return 1;
		case M1_OP_GETCONTBYID: SETSTR(NAME_MSGNAME_M1_CONT_BY_ID); return 1;
		case M1_OP_GETCONTBYNAME: SETSTR(NAME_MSGNAME_M1_CONT_BY_NAME); return 1;
		case M1_OP_GETCONTMATCHING: SETSTR(NAME_MSGNAME_M1_GETMATCHES); return 1;
		case M1_OP_UPDCONT: SETSTR(NAME_MSGNAME_M1_UPDATE_CONTAINERS); return 1;
		case M1_OP_GETVNSSTATE: SETSTR(NAME_MSGNAME_M1_GET_VNS_STATE); return 1;
		
		/* V2 MSG */
		case M1V2_OP_CREATE: 	SETSTR("M1V2_CREATE");    return 1;
		case M1V2_OP_DESTROY: 	SETSTR("M1V2_DESTROY");    return 1;
		case M1V2_OP_HAS: 	SETSTR("M1V2_HAS");    return 1;
		case M1V2_OP_SRVAVAIL: 	SETSTR("M1V2_SRVAVAIL");    return 1;
		case M1V2_OP_SRVALL: 	SETSTR("M1V2_SRVALL");    return 1;
		case M1V2_OP_SRVDEL:	SETSTR("M1V2_SRVDEL");	return 1;
		case M1V2_OP_SETPROP: 	SETSTR("M1V2_CID_PROPSET");    return 1;
		case M1V2_OP_GETPROP: 	SETSTR("M1V2_CID_PROPGET");    return 1;
		case M1V2_OP_DELPROP: 	SETSTR("M1V2_CID_PROPDEL");    return 1;
	}
	return 0;
#undef SETSTR
}


static gint
meta1_range_request_common (MESSAGE m, meta1_operation_t mop, prefix_t *prefix, prefix_data_t *pData, GError **err)
{
	void *body = NULL;
	gsize bodySize = 0;
	gint retCode;
	gsize wrkLen=0;
	gchar *wrkBuf=NULL;

	if (!m)
	{
		GSETERROR(err, "Invalid parameter");
		return 0;
	}

	/*sets the request name*/
	retCode = __get_request_name1 (mop, &wrkBuf, &wrkLen);
	if (!retCode)
	{
		GSETERROR(err, "Invalid request type");
		return 0;
	}

	retCode = message_set_NAME (m, wrkBuf, wrkLen, err);
	if (!retCode)
	{
		GSETERROR(err, "Cannot set the name of the request");
		return 0;
	}

	if (prefix) {
		retCode = message_add_field (m, NAME_MSGKEY_PREFIX,
				sizeof(NAME_MSGKEY_PREFIX)-1, &prefix, sizeof(prefix), err);
		if (!retCode)
		{
			GSETERROR(err, "Cannot set the container id in the request");
			goto errorLabel;
		}

		if (pData)
		{
			retCode = message_add_field (m, NAME_MSGKEY_FLAG,
					sizeof(NAME_MSGKEY_FLAG)-1, &(pData->flags),
					sizeof(pData->flags), err);
			if (!retCode)
			{
				GSETERROR(err, "Cannot set the container name in the request");
				goto errorLabel;
			}

			if (pData->addr)
			{
				retCode = addr_info_marshall (pData->addr, &body, &bodySize, err);
				if (!retCode)
				{
					GSETERROR(err, "Cannot serialize the list of addresses");
					goto errorLabel;
				}

				retCode = message_set_BODY (m, body, bodySize, err);
				if (!retCode)
				{
					GSETERROR(err, "Cannot set the body of the message");
					goto errorLabel;
				}
			}
		}
	}

	return 1;
errorLabel:
	if (body)
		g_free(body);
	return 0;
}

static gint
meta1_container_request_common_v2 (MESSAGE m, meta1_operation_t mop, const container_id_t id,
		const gchar *name, const gchar *virtual_namespace, GError **err)
{
	gsize nameSize;
	gsize virtualNsSize;
	gint retCode;
	gsize wrkLen=0;
	gchar *wrkBuf=NULL;

	if (!m) {
		GSETERROR(err, "Invalid parameter");
		return 0;
	}

	nameSize = name ? strlen(name) : 0;
	virtualNsSize = virtual_namespace ? strlen(virtual_namespace) : 0;

	/*sets the request name*/
	retCode = __get_request_name1 (mop, &wrkBuf, &wrkLen);
	if (!retCode) {
		GSETERROR(err, "Invalid request type");
		return 0;
	}

	retCode = message_set_NAME (m, wrkBuf, wrkLen, err);
	if (!retCode) {
		GSETERROR(err, "Cannot set the name of the request");
		return 0;
	}

	/*Sets the container ID*/
	retCode = 1;
	if (id!=NULL || name!=NULL) {
		container_id_t usedID;
		if (id)
			memcpy(usedID, id, sizeof(container_id_t));
		else
			meta1_name2hash(usedID, virtual_namespace, name);
		retCode = message_add_field (m, NAME_MSGKEY_CONTAINERID, sizeof(NAME_MSGKEY_CONTAINERID)-1,
				usedID, sizeof(container_id_t), err);
	}

	if (!retCode) {
		GSETERROR(err, "Cannot set the container id in the request");
		goto errorLabel;
	}

	if (name && nameSize>0) {
		retCode = message_add_field (m, NAME_MSGKEY_CONTAINERNAME, sizeof(NAME_MSGKEY_CONTAINERNAME)-1,
				name, nameSize, err);
		if (!retCode) {
			GSETERROR(err, "Cannot set the container name in the request");
			goto errorLabel;
		}
	}

	if (virtual_namespace && virtualNsSize>0) {
		retCode = message_add_field (m, NAME_MSGKEY_VIRTUALNAMESPACE, sizeof(NAME_MSGKEY_VIRTUALNAMESPACE)-1,
				virtual_namespace, virtualNsSize, err);
		if (!retCode) {
			GSETERROR(err, "Cannot set the virtual namespace in the request");
			goto errorLabel;
		}
	}

	return 1;
errorLabel:
	return 0;
}

static gint
meta1_container_request_common (MESSAGE m, meta1_operation_t mop, const container_id_t id,
		const gchar *name, GError **err)
{
	return meta1_container_request_common_v2(m, mop, id, name, NULL, err);
}


gboolean 
meta1_remote_create_container_v2 (addr_info_t *meta1, gint ms, GError **err, const char *cName, const char *virtualNs,
		container_id_t cID, gdouble to_step, gdouble to_overall, gchar **master)
{
	(void) ms;
	struct client_s *client = NULL;
	GByteArray *packed = NULL;
	MESSAGE request=NULL;
	gboolean status = FALSE;
	gchar target[64];

	if (!message_create (&request, err)) {
		GSETERROR(err, "Cannot create a message");
		goto end_label;
	}

	if (!meta1_container_request_common_v2 (request, M1_OP_CREATE, cID, cName, virtualNs, err)) {
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto end_label;
	}

	addr_info_to_string(meta1, target, sizeof(target));
	packed = message_marshall_gba(request, NULL);
	client = gridd_client_create(target, packed, NULL, NULL);

	if(to_step > 0 && to_overall > 0)
		gridd_client_set_timeout(client, to_step, to_overall);

	gridd_client_start(client);
	if((*err = gridd_client_loop(client)) != NULL) {
		goto end_label;
	}

	if(g_ascii_strcasecmp(target, gridd_client_url(client)) && NULL != master)
		*master = g_strdup(gridd_client_url(client));

	if((*err = gridd_client_error(client)) != NULL)
		goto end_label;

	status = TRUE;

end_label:
	if (request) {
		message_destroy(request, NULL);
	}
	if (packed) {
		g_byte_array_unref(packed);
	}

	gridd_client_free(client);

	return status;
}

gboolean 
meta1_remote_create_container (addr_info_t *meta1, gint ms, GError **err, const char *cName, container_id_t cID)
{
	return meta1_remote_create_container_v2(meta1, ms, err, cName, NULL, cID, 0, 0, NULL);
}

gint 
meta1_remote_destroy_container_by_name (addr_info_t *meta1, gint ms, GError **err, const char *cName,
			gdouble to_step, gdouble to_overall, char **master)
{
	(void) ms;
	struct client_s *client = NULL;
	GByteArray *packed = NULL;
	MESSAGE request=NULL;
	gboolean status = FALSE;
	gchar target[64];

	if (!message_create (&request, err)) {
		GSETERROR(err, "Cannot create a message");
		goto end_label;
	}

	if (!meta1_container_request_common(request, M1_OP_DESTROY, NULL, cName, err)) {
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto end_label;
	}

	addr_info_to_string(meta1, target, sizeof(target));
	packed = message_marshall_gba(request, NULL);
	client = gridd_client_create(target, packed, NULL, NULL);

	if(to_step > 0 && to_overall > 0)
		gridd_client_set_timeout(client, to_step, to_overall);

	gridd_client_start(client);
	if((*err = gridd_client_loop(client)) != NULL) {
		goto end_label;
	}

	if(g_ascii_strcasecmp(target, gridd_client_url(client)) && NULL != master)
		*master = g_strdup(gridd_client_url(client));

	do{
		struct client_s *clients[2];
		clients[0] = client;
		clients[1] = NULL;
		if((*err = gridd_clients_error(clients)) != NULL)
			goto end_label;
	} while(0);

	status = TRUE;

end_label:
	if (request) {
		message_destroy(request, NULL);
	}
	if (packed) {
		g_byte_array_free(packed, TRUE);
	}

	gridd_client_free(client);

	return status;
}


GSList* 
meta1_remote_get_meta2_by_container_name (addr_info_t *meta1, gint ms, GError **err, const char *cName)
{
	struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL,         &addr_info_concat, NULL },
		{ 206, REPSEQ_BODYMANDATORY, &addr_info_concat, NULL },
		{ 0, 0, NULL, NULL },
	};
	GSList *list=NULL;
	struct reply_sequence_data_s data = { &list , 0 , codes };
	MESSAGE request=NULL;

	if (!message_create (&request, err))
	{
		GSETERROR(err, "Cannot create a message", __FUNCTION__);
		goto errorLabel;
	}

	if (!meta1_container_request_common (request, M1_OP_GET, NULL, cName, err))
	{
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	if (!metaXClient_reply_sequence_run_from_addrinfo (err, request, meta1, ms, &data))
	{
		GSETERROR(err,"An error occured while executing the GET_META2 request");
		goto errorLabel;
	}

errorLabel:
	if (request)
		message_destroy(request, NULL);
	return list;
}


gboolean 
meta1_remote_destroy_container_with_flags (addr_info_t *meta1, gint ms, GError **err,
		const container_id_t cID, guint32 flags, gdouble to_step, gdouble to_overall,
		char **master)
{
	(void) ms;
	struct client_s *client = NULL;
	GByteArray *packed = NULL;
	MESSAGE request=NULL;
	gboolean status = FALSE;
	gchar target[64];

	gboolean add_flag( const gchar *str_flag ) {
		return (0<message_add_field( request,
					str_flag, strlen(str_flag),
					"true", sizeof("true")-1,
					err))
			? TRUE : FALSE;
	}

	if (!message_create (&request, err)) {
		GSETERROR(err, "Cannot create a message");
		goto end_label;
	}

	if (!meta1_container_request_common (request, M1_OP_DESTROY, cID, NULL, err)) {
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto end_label;
	}

	if ((flags & M1FLAG_DESTROY_FORCED) && !add_flag("FORCED")) {
		GSETERROR(err, "Cannot add the [%s] flag to the request", "FORCED");
		goto end_label;
	}

	if ((flags & M1FLAG_DESTROY_NOFOLLOW) && !add_flag("NOFOLLOW")) {
		GSETERROR(err, "Cannot add the [%s] flag to the request", "NOFOLLOW");
		goto end_label;
	}

	addr_info_to_string(meta1, target, sizeof(target));
	packed = message_marshall_gba(request, NULL);
	client = gridd_client_create(target, packed, NULL, NULL);

	if(to_step > 0 && to_overall > 0)
		gridd_client_set_timeout(client, to_step, to_overall);

	gridd_client_start(client);
	if((*err = gridd_client_loop(client)) != NULL) {
		goto end_label;
	}

	if(g_ascii_strcasecmp(target, gridd_client_url(client)) && NULL != master) {
		*master = g_strdup(gridd_client_url(client));
	}

	if((*err = gridd_client_error(client)) != NULL)
		goto end_label;

	status = TRUE;

end_label:
	if (request) {
		message_destroy(request, NULL);
	}
	if (packed) {
		g_byte_array_free(packed, TRUE);
	}

	gridd_client_free(client);

	return status;
}


gint 
meta1_remote_destroy_container_by_id (addr_info_t *meta1, gint ms, GError **err, const container_id_t cID)
{
	return meta1_remote_destroy_container_with_flags( meta1, ms, err, cID, 0x0000000, 0, 0, NULL);
}



GSList* 
meta1_remote_get_meta2_by_container_id (addr_info_t *meta1, gint ms, GError **err, const container_id_t cID,
		gdouble to_step, gdouble to_overall)
{
	(void) ms;
	GSList *list=NULL;
	struct client_s *client = NULL;
	GByteArray *packed = NULL;
	MESSAGE request=NULL;
	gchar target[64];

	gboolean on_reply(gpointer ctx, MESSAGE reply) {
                  void *b = NULL;
                  gsize bsize = 0;
                  (void) ctx;
                  if (0 < message_get_BODY(reply, &b, &bsize, NULL)) {
			addr_info_unmarshall(&list, b, &bsize, err);
                  }
                  return TRUE;
        }

	if (!meta1 || !cID) {
		GSETERROR(err,"Invalid parameter (%p %p)", meta1, cID);
		goto end_label;
	}

	if (!message_create (&request, err)) {
		GSETERROR(err, "Cannot create a message");
		goto end_label;
	}

	if (!meta1_container_request_common (request, M1_OP_GET, cID, NULL, err))
	{
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto end_label;
	}

	addr_info_to_string(meta1, target, sizeof(target));
	packed = message_marshall_gba(request, NULL);
	client = gridd_client_create(target, packed, NULL, on_reply);

	if(to_step > 0 && to_overall > 0)
		gridd_client_set_timeout(client, to_step, to_overall);

	gridd_client_start(client);
	if((*err = gridd_client_loop(client)) != NULL) {
		goto end_label;
	}

	*err = gridd_client_error(client);

end_label:

	if (request) {
		message_destroy(request, NULL);
	}
	if (packed) {
		g_byte_array_free(packed, TRUE);
	}

	gridd_client_free(client);

	return list;
}



gboolean 
meta1_remote_set_container_flag (addr_info_t *meta1, gint ms, GError **err,
		const container_id_t cID, guint32 flags)
{
	struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, NULL },
		{ 0, 0, NULL, NULL },
	};
	struct reply_sequence_data_s data = { NULL , 0 , codes };
	MESSAGE request=NULL;

	if (!message_create (&request, err))
	{
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}

	if (!meta1_container_request_common (request, M1_OP_SETFLAGS, cID, NULL, err))
	{
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	if (!message_set_BODY(request,&flags,sizeof(flags),err))
	{
		GSETERROR(err, "Cannot set the body (the flag set) on the request");
		goto errorLabel;
	}

	if (!metaXClient_reply_sequence_run_from_addrinfo (err, request, meta1, ms, &data))
	{
		GSETERROR(err,"An error occured while executing the SET_FLAG request");
		goto errorLabel;
	}

	message_destroy(request, NULL);
	return TRUE;
errorLabel:
	if (request)
		message_destroy(request, NULL);
	return FALSE;
}


gboolean 
meta1_remote_get_container_flag (addr_info_t *meta1, gint ms, GError **err,
		const container_id_t cID, guint32 *flags)
{
	gboolean extract_flags (GError **e1, gpointer udata, gint code, guint8 *body, gsize bodySize)
	{
		(void) udata;
		(void) code;
		(void) e1;

		if (!body || bodySize<sizeof(*flags))
			return FALSE;
		memcpy(flags, body, bodySize);
		return TRUE;
	}
	struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL|REPSEQ_BODYMANDATORY, extract_flags, NULL },
		{ 0, 0, NULL, NULL },
	};
	struct reply_sequence_data_s data = { NULL , 0 , codes };
	MESSAGE request=NULL;

	if (!message_create (&request, err))
	{
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}

	if (!meta1_container_request_common (request, M1_OP_GETFLAGS, cID, NULL, err))
	{
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	if (!metaXClient_reply_sequence_run_from_addrinfo (err, request, meta1, ms, &data))
	{
		GSETERROR(err,"An error occured while executing the GET_CONTAINER request");
		goto errorLabel;
	}
	message_destroy(request, NULL);
	return TRUE;
errorLabel:
	if (request)
		message_destroy(request, NULL);
	return FALSE;
}



gboolean 
meta1_remote_range_add (addr_info_t *meta1, gint ms, GError **err,
		prefix_t prefix, prefix_data_t *pData)
{
	struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, NULL },
		{ 0, 0, NULL, NULL },
	};
	struct reply_sequence_data_s data = { NULL , 0 , codes };
	MESSAGE request=NULL;

	if (!message_create (&request, err))
	{
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}

	if (!meta1_range_request_common (request, M1_OP_RANGE_ADD, &prefix, pData, err))
	{
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	if (!metaXClient_reply_sequence_run_from_addrinfo (err, request, meta1, ms, &data))
	{
		GSETERROR(err,"An error occured while executing the RANGE_ADD request");
		goto errorLabel;
	}

	message_destroy(request, NULL);
	return TRUE;
errorLabel:
	if (request)
		message_destroy(request, NULL);
	return FALSE;
}


gboolean 
meta1_remote_range_del (addr_info_t *meta1, gint ms, GError **err,
		prefix_t prefix)
{
	struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, NULL },
		{ 0, 0, NULL, NULL },
	};
	struct reply_sequence_data_s data = { NULL , 0 , codes };
	MESSAGE request=NULL;

	if (!message_create (&request, err))
	{
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}

	if (!meta1_range_request_common (request, M1_OP_RANGE_DEL, &prefix, NULL, err))
	{
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	if (!metaXClient_reply_sequence_run_from_addrinfo (err, request, meta1, ms, &data))
	{
		GSETERROR(err,"An error occured while executing the RANGE_DEL request");
		goto errorLabel;
	}

	message_destroy(request, NULL);
	return TRUE;
errorLabel:
	if (request)
		message_destroy(request, NULL);
	return FALSE;
}


gboolean 
meta1_remote_range_set (addr_info_t *meta1, gint ms, GError **err,
		prefix_t prefix, prefix_data_t *pData)
{
	struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, NULL },
		{ 0, 0, NULL, NULL },
	};
	struct reply_sequence_data_s data = { NULL , 0 , codes };
	MESSAGE request=NULL;

	if (!message_create (&request, err))
	{
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}

	if (!meta1_range_request_common (request, M1_OP_RANGE_SET, &prefix, pData, err))
	{
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	if (!metaXClient_reply_sequence_run_from_addrinfo (err, request, meta1, ms, &data))
	{
		GSETERROR(err,"An error occured while executing the RANGE_SET request");
		goto errorLabel;
	}

	message_destroy(request, NULL);
	return TRUE;
errorLabel:
	if (request)
		message_destroy(request, NULL);
	return FALSE;
}


gboolean 
meta1_remote_range_get (addr_info_t *meta1, gint ms, GError **err,
		prefix_t prefix, prefix_data_t *pData)
{
	const char pProc[] = "meta1_remote_range_get";
	MESSAGE request=NULL;

	gboolean content_handler_flag (GError **e1, gpointer udata, gint code, guint8 *body, gsize bodySize)
	{
		(void) udata;
		(void) code;

		if (bodySize != sizeof(pData->flags))
		{
			GSETERROR(e1, "<%s> invalid content (bad flag size, %u instead of %u)", pProc, bodySize, sizeof(pData->flags));
			return FALSE;
		}
		memcpy(&(pData->flags), body, bodySize);
		return TRUE;
	}

	gboolean content_handler_addr (GError **e1, gpointer udata, gint code, guint8 *body, gsize bodySize)
	{
		(void) udata;
		(void) code;

		if (!addr_info_unmarshall(&(pData->addr), body, &bodySize, e1))
		{
			GSETERROR(e1, "<%s> inavlid content (cannot unserialize the addr_info list)", pProc);
			return FALSE;
		}
		return FALSE;
	}

	struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL,         &content_handler_flag, NULL },
		{ 206, REPSEQ_BODYMANDATORY, &content_handler_addr, NULL },
		{ 0, 0, NULL, NULL },
	};

	struct reply_sequence_data_s data = { NULL , 0 , codes };

	memset (pData, 0x00, sizeof(prefix_data_t));

	if (!message_create (&request, err))
	{
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}

	if (!meta1_range_request_common (request, M1_OP_RANGE_GET, &prefix, NULL, err))
	{
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	if (!metaXClient_reply_sequence_run_from_addrinfo (err, request, meta1, ms, &data))
	{
		GSETERROR(err,"An error occured while executing the RANGE_GET request");
		goto errorLabel;
	}

	message_destroy(request, NULL);
	return TRUE;
errorLabel:
	if (request)
		message_destroy(request, NULL);
	return FALSE;
}


GSList* 
meta1_remote_range_list( addr_info_t *meta1, gint ms, GError **err)
{
	GSList *result = NULL;
	MESSAGE request = NULL;

	struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL,         &arrays_handler_list, NULL },
		{ 206, REPSEQ_BODYMANDATORY, &arrays_handler_list, NULL },
		{ 0, 0, NULL, NULL },
	};

	struct reply_sequence_data_s data = { &result , 0 , codes };

	if (!message_create (&request, err))
	{
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}

	if (!meta1_range_request_common (request, M1_OP_RANGE_LIST, NULL, NULL, err))
	{
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	if (!metaXClient_reply_sequence_run_from_addrinfo (err, request, meta1, ms, &data))
	{
		GSETERROR(err, "An error occured while executing the RANGE_LIST request");
		goto errorLabel;
	}

	message_destroy(request, NULL);
	return result;
errorLabel:
	if (request)
		message_destroy(request, NULL);
	return NULL;
}


GSList* 
meta1_remote_get_containers_on_meta2( struct metacnx_ctx_s *ctx,
		addr_info_t *m2_addr, GError **err)
{
	void *body = NULL;
	gsize body_size = 0;

	GSList *result = NULL;
	MESSAGE request = NULL;

	struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL,         &cid_handler_list, NULL },
		{ 206, REPSEQ_BODYMANDATORY, &cid_handler_list, NULL },
		{ 0, 0, NULL, NULL },
	};

	struct reply_sequence_data_s data = { &result , 0 , codes };

	if (!message_create (&request, err))
	{
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}

	/*name the request*/
	if (!message_set_NAME (request, NAME_MSGNAME_M1_GETALLONM2, sizeof(NAME_MSGNAME_M1_GETALLONM2)-1, err)) {
		GSETERROR(err, "Cannot set the name of the request");
		goto errorLabel;
	}

	/*serialize the set of meta2 addresses*/
	do {
		GSList *m2_list;

		/*at present, there is just one meta2 in the list*/
		m2_list = g_slist_prepend( NULL, m2_addr );
		if (!m2_list) {
			GSETERROR(err,"Memory allocation failure");
			goto errorLabel;
		}

		if (0 >= addr_info_marshall( m2_list, &body, &body_size, err)) {
			/*error message already set*/
			g_slist_free( m2_list );
			goto errorLabel;
		}

		if (0 >= message_set_BODY(request, body, body_size, err)) {
			/*error message already set*/
			g_slist_free( m2_list );
			goto errorLabel;
		}

		g_slist_free( m2_list );
	} while (0);

	if (!metaXClient_reply_sequence_run_context (err, ctx, request, &data))
	{
		GSETERROR(err, "An error occured while executing the "NAME_MSGNAME_M1_GETALLONM2" request");
		goto errorLabel;
	}

	g_free( body );
	message_destroy( request, err );
	return result;
errorLabel:
	if (request)
		message_destroy( request, err );
	if (body)
		g_free( body );
	return NULL;
}


gboolean 
meta1_remote_force_creation( struct metacnx_ctx_s *ctx, GError **err,
		const container_id_t cID, const gchar *cName, GSList *addr_list)
{
	void *body = NULL;
	gsize body_size = 0;
	MESSAGE request=NULL;

	struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, NULL },
		{ 0, 0, NULL, NULL },
	};

	struct reply_sequence_data_s data = { NULL , 0 , codes };

	if (!ctx || !addr_list) {
		GSETERROR(err,"Invalid parameter (%p %p)", ctx, addr_list);
		return FALSE;
	}

	if (!message_create (&request, err)) {
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}

	if (!meta1_container_request_common (request, M1_OP_FORCECREATE, cID, cName, err))
	{
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	/*serialize the list in the body*/
	if (0>=addr_info_marshall( addr_list, &body, &body_size, err )) {
		GSETERROR(err,"Faile dto serialize the META2 address list");
		goto errorLabel;
	} else if (0>=message_set_BODY(request, body, body_size, err)) {
		GSETERROR(err,"Failed fill the request body");
		goto errorLabel;
	}

	if (!metaXClient_reply_sequence_run_context (err, ctx, request, &data)) {
		GSETERROR(err,"An error occured while executing the RANGE_GET request");
		goto errorLabel;
	}

	/*cleans the working structures*/
	g_free( body );
	message_destroy(request, NULL);
	return TRUE;
errorLabel:
	if (request)
		message_destroy(request, NULL);
	if (body)
		g_free( body );
	return FALSE;
}

struct meta1_raw_container_s* 
meta1_remote_get_container_by_id( struct metacnx_ctx_s *ctx, container_id_t container_id, GError **err,
		gdouble to_step, gdouble to_overall)
{
	struct meta1_raw_container_s *raw_container = NULL;
	struct client_s *client = NULL;
	GByteArray *packed = NULL;
	MESSAGE request=NULL;
	gchar target[64];

	gboolean on_reply(gpointer c1, MESSAGE reply) {
		void *b = NULL;
		gsize bsize = 0;
		(void) c1;
		if (0 < message_get_BODY(reply, &b, &bsize, NULL)) {
			raw_container = meta1_raw_container_unmarshall(b, bsize, err);
		}
		return TRUE;
	}

	if (!ctx || !container_id) {
		GSETERROR(err,"Invalid parameter (%p %p)", ctx, container_id);
		goto end_label;
	}

	if (!message_create (&request, err)) {
		GSETERROR(err, "Cannot create a message");
		goto end_label;
	}

	if (!meta1_container_request_common (request, M1_OP_GETCONTBYID, container_id, NULL, err))
	{
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto end_label;
	}

	addr_info_to_string(&(ctx->addr), target, sizeof(target));
	packed = message_marshall_gba(request, NULL);
	client = gridd_client_create(target, packed, NULL, on_reply);

	if(to_step > 0 && to_overall > 0)
		gridd_client_set_timeout(client, to_step, to_overall);

	gridd_client_start(client);
	if((*err = gridd_client_loop(client)) != NULL) {
		goto end_label;
	}

	do{
		struct client_s *clients[2];
		clients[0] = client;
		clients[1] = NULL;
		if((*err = gridd_clients_error(clients)) != NULL)
			goto end_label;
	} while(0);

end_label:

	if (request) {
		message_destroy(request, NULL);
	}
	if (packed) {
		g_byte_array_unref(packed);
	}

	gridd_client_free(client);

	return(raw_container);
}

struct meta1_raw_container_s* 
meta1_remote_get_container_by_name( struct metacnx_ctx_s *ctx, gchar *container_name, GError **err)
{
	MESSAGE request = NULL;
	struct meta1_raw_container_s *raw_container = NULL;

	struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, &extract_raw_container, NULL },
		{ 0, 0, NULL, NULL },
	};

	raw_container = g_try_malloc0(sizeof(struct meta1_raw_container_s));
	if (raw_container == NULL) {
		GSETERROR(err, "Memory allocation failure");
		goto errorLabel;
	}

	struct reply_sequence_data_s data = { raw_container , 0 , codes };

	if (!ctx || !container_name) {
		GSETERROR(err,"Invalid parameter (%p %p)", ctx, container_name);
		return FALSE;
	}

	if (!message_create (&request, err)) {
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}

	if (!meta1_container_request_common (request, M1_OP_GETCONTBYNAME, NULL, container_name, err))
	{
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	if (!metaXClient_reply_sequence_run_context (err, ctx, request, &data)) {
		GSETERROR(err,"An error occured while executing the GET_CONTAINER_BY_NAME request");
		goto errorLabel;
	}

	/*cleans the working structures*/
	message_destroy(request, NULL);

	return(raw_container);

errorLabel:
	if (request)
		message_destroy(request, NULL);
	if (raw_container)
		g_free(raw_container);

	return(NULL);
}

gboolean
meta1_remote_get_container_names_matching(struct metacnx_ctx_s *ctx, GSList *list_of_patterns,
		GSList **result, GError **err)
{
	static struct code_handler_s codes [] = {
		{ 206, REPSEQ_BODYMANDATORY, &strings_handler_list, NULL },
		{ 200, REPSEQ_FINAL,         &strings_handler_list, NULL },
		{ 0, 0, NULL, NULL },
	};
	MESSAGE request = NULL;
	GSList *res = NULL;
	GByteArray *gba = NULL;

	struct reply_sequence_data_s data = { &res, 0, codes};

	if (!ctx || !list_of_patterns || !result) {
		GSETCODE(err, EINVAL, "Invalid parameter (%p %p %p)", ctx, list_of_patterns, result);
		return FALSE;
	}

	if (!message_create (&request, err)) {
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}

	if (!meta1_container_request_common (request, M1_OP_GETCONTMATCHING, NULL, NULL, err)) {
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	/* Serializes the patterns */
	gba = strings_marshall_gba(list_of_patterns, err);
	if (!gba) {
		GSETERROR(err,"Serialization error");
		goto errorLabel;
	}
	if (0 >= message_set_BODY(request, gba->data, gba->len, err)) {
		GSETERROR(err, "Failed fill the request body");
		g_byte_array_free(gba, TRUE);
		goto errorLabel;
	}
	g_byte_array_free(gba, TRUE);

	if (!metaXClient_reply_sequence_run_context (err, ctx, request, &data)) {
		GSETERROR(err, "Reply sequence error");
		goto errorLabel;
	}

	/*cleans the working structures*/
	message_destroy(request, NULL);

	*result = res;
	return TRUE;

errorLabel:
	if (res) {
		g_slist_foreach(res, g_free1, NULL);
		g_slist_free(res);
	}
	if (request)
		message_destroy(request, NULL);
	return FALSE;
}

gboolean
meta1_remote_change_container_reference(struct metacnx_ctx_s *cnx, const container_id_t cid,
		const addr_info_t *old_m2, const addr_info_t *new_m2,
		GSList **new_set, GError **err)
{
	static struct code_handler_s codes [] = {
		{200, REPSEQ_FINAL, &addr_info_concat, NULL},
		{0, 0, NULL, NULL},
	};
	MESSAGE request = NULL;
	addr_info_t addr;
	GSList wrkl = { &addr, NULL };
	GSList *res = NULL;

	struct reply_sequence_data_s data = { &res, 0, codes};

	if (!cnx || !cid || !old_m2 || !new_m2) {
		GSETCODE(err, EINVAL, "Invalid parameter");
		return FALSE;
	}

	if (!(request = meta1_create_message(NAME_MSGNAME_M1_MIGRATE_CONTAINER, cid, err))) {
		GSETERROR(err, "local error");
		return FALSE;
	}

	memcpy(&addr, old_m2, sizeof(addr_info_t));
	if (!meta1_enheader_addr_list(request, "SRC_ADDR", &wrkl, err)) {
		GSETERROR(err, "local error");
		goto errorLabel;
	}

	memcpy(&addr, new_m2, sizeof(addr_info_t));
	if (!meta1_enheader_addr_list(request, "DST_ADDR", &wrkl, err)) {
		GSETERROR(err, "local error");
		goto errorLabel;
	}

	if (!metaXClient_reply_sequence_run_context (err, cnx, request, &data)) {
		GSETERROR(err, "Reply sequence error");
		goto errorLabel;
	}

	/*cleans the working structures*/
	message_destroy(request, NULL);
	if (new_set)
		*new_set = res;
	else {
		g_slist_foreach(res, addr_info_gclean, NULL);
		g_slist_free(res);
	}
	return TRUE;

errorLabel:
	if (res) {
		g_slist_foreach(res, addr_info_gclean, NULL);
		g_slist_free(res);
	}
	if (request)
		message_destroy(request, NULL);
	return FALSE;
}

gboolean
meta1_remote_update_containers(gchar *meta1_addr_str, GSList *list_of_containers,
		gint ms, GError **err)
{
	(void) ms;
	/* struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, NULL },
		{ 0, 0, NULL, NULL },
	};

	struct reply_sequence_data_s data = { NULL , 0 , codes }; */

	MESSAGE request = NULL;
	gboolean status = FALSE;
	GByteArray *gba = NULL;
	struct client_s *client;
	GError *e = NULL;

	if (!meta1_addr_str || !list_of_containers) {
		GSETCODE(err, EINVAL, "Invalid parameter (%p %p)", meta1_addr_str, list_of_containers);
		return FALSE;
	}

	GRID_DEBUG("Parameters are ok");

	if (!message_create (&request, err)) {
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}

	if (!meta1_container_request_common (request, M1_OP_UPDCONT, NULL, NULL, err)) {
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	void *body = NULL;
	gsize bodySize = 0;

	/*serialize and add the body*/
	if (!container_info_marshall(list_of_containers, &body, &bodySize, err))
	{
		GSETERROR(err,"Cannot serialize the container_info_t* list");
		goto errorLabel;
	}

	if (!body) {
		GSETERROR(err,"Serialization error");
		goto errorLabel;
	}

	if (0 >= message_set_BODY(request, body, bodySize, err)) {
		GSETERROR(err, "Failed fill the request body");
		goto errorLabel;
	}

	GRID_DEBUG("Message created");

	gba = message_marshall_gba_and_clean(request);
	request = NULL;
	GRID_DEBUG("Message converted in binary");

	GRID_DEBUG("Targeting %s", meta1_addr_str);

	client = gridd_client_create_idle(meta1_addr_str);
	if(!client) {
		e = NEWERROR(2, "errno=%d %s", errno, strerror(errno));
	} else {
		GRID_DEBUG("Client created");
		gridd_client_start(client);
		GRID_DEBUG("Client started");
		e = gridd_client_request(client, gba, NULL, NULL);
		if(!e){
			if(!(e = gridd_client_loop(client)))
				e = gridd_client_error(client);
			if (!e)
				status = TRUE;
		}
		GRID_DEBUG("Loop done");
		gridd_client_free(client);
	}

	*err = e;

	g_byte_array_free(gba, TRUE);

errorLabel:

	/*cleans the working structures*/

	if(body)
		g_free(body);
	if (request)
		message_destroy(request, NULL);

	return status;
}

GHashTable*
meta1_remote_get_virtual_ns_state(addr_info_t *meta1, gint ms, GError **err)
{
	GHashTable *result = NULL;
	MESSAGE request = NULL;

	struct code_handler_s codes [] = {
		{ 100, 0,         NULL, NULL },
		{ 200, REPSEQ_FINAL,         &kv_handler_list, NULL },
		{ 204, REPSEQ_FINAL,         &kv_handler_list, NULL },
		{ 0, 0, NULL, NULL },
	};

	struct reply_sequence_data_s data = { &result , 0 , codes };

	if (!message_create (&request, err))
	{
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}

	if (!meta1_container_request_common (request, M1_OP_GETVNSSTATE, NULL, NULL, err)) {
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	if (!metaXClient_reply_sequence_run_from_addrinfo (err, request, meta1, ms, &data))
	{
		GSETERROR(err, "An error occured while executing the VIRTUAL_NS_STATE request");
		goto errorLabel;
	}

errorLabel:

	if (request)
		message_destroy(request, NULL);
	return result;
}

/*********************** META1 V2 REQUESTS *****************************/

static gboolean
on_reply(gpointer ctx, MESSAGE reply)
{
	GByteArray *out = ctx;
	void *b = NULL;
	gsize bsize = 0;

	if (0 < message_get_BODY(reply, &b, &bsize, NULL)) {
		GRID_TRACE2("%s:%d size=%"G_GSIZE_FORMAT,
				__FUNCTION__, __LINE__, bsize);
		if (out != NULL)
			g_byte_array_append(out, b, bsize);
	}
	else {
		GRID_TRACE2("%s:%d empty", __FUNCTION__, __LINE__);
	}

	g_byte_array_append(out, (const guint8*)"", 1);
	g_byte_array_set_size(out, out->len - 1);
	return TRUE;
}

static gchar **
list_request(const addr_info_t *a, gdouble to_step, gdouble to_overall, GError **err, GByteArray *req,
		gchar **master)
{
	gchar stra[128];
	struct client_s *client = NULL;
	GByteArray *gba;
	GError *e = NULL;

	EXTRA_ASSERT(a != NULL);
	EXTRA_ASSERT(req != NULL);
	GRID_TRACE2("%s:%d", __FUNCTION__, __LINE__);

	gba = g_byte_array_new();
	grid_addrinfo_to_string(a, stra, sizeof(stra));
	client = gridd_client_create(stra, req, gba, on_reply);

	if(to_step > 0 && to_overall > 0)
		gridd_client_set_timeout(client, to_step, to_overall);

	gscstat_tags_start(GSCSTAT_SERVICE_META1, GSCSTAT_TAGS_REQPROCTIME);
	gridd_client_start(client);
	if (!(e = gridd_client_loop(client)))
		e = gridd_client_error(client);
	gscstat_tags_end(GSCSTAT_SERVICE_META1, GSCSTAT_TAGS_REQPROCTIME);

	/* in RO request, we don't need this information */
	if(NULL != master) {
		char tmp[64];
		bzero(tmp, sizeof(tmp));
		addr_info_to_string(a, tmp, sizeof(tmp));

		if(g_ascii_strcasecmp(tmp, gridd_client_url(client)))
			*master = g_strdup(gridd_client_url(client));
	}

	gridd_client_free(client);

	if (e) {
		if (err) {
			*err = e;
		}
		else {
			g_clear_error(&e);
		}
		g_byte_array_free(gba, TRUE);
		return NULL;
	}

	gchar **lines = metautils_decode_lines((gchar*)gba->data,
			(gchar*)(gba->data + gba->len));
	g_byte_array_free(gba, TRUE);
	return lines;
}


gboolean 
meta1v2_remote_create_reference (const addr_info_t *meta1, GError **err,
		const char *ns, const container_id_t refid, const gchar *refname,
		gdouble to_step, gdouble to_overall, gchar **master)
{
	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refid != NULL);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_CREATE,
			NULL,
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"CONTAINER_ID", gba_poolify(&pool, metautils_gba_from_cid(refid)),
			"CONTAINER_NAME", gba_poolify(&pool, metautils_gba_from_string(refname)),
			NULL);
	gchar **result = list_request(meta1, to_step, to_overall, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), master);
	message_destroy(req, NULL);
	GBA_POOL_CLEAN(pool);

	if (!result)
		return FALSE;
	g_strfreev(result);
	return TRUE;
}


gboolean
meta1v2_remote_has_reference (const addr_info_t *meta1, GError **err,
		const char *ns, const container_id_t refid, gdouble to_step, gdouble to_overall)
{
	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refid != NULL);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_HAS,
			NULL,
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"CONTAINER_ID", gba_poolify(&pool, metautils_gba_from_cid(refid)),
			NULL);
	gchar **result = list_request(meta1, to_step, to_overall, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), NULL);
	message_destroy(req, NULL);
	GBA_POOL_CLEAN(pool);

	if (!result)
		return FALSE;
	g_strfreev(result);
	return TRUE;
}

gboolean 
meta1v2_remote_delete_reference (const addr_info_t *meta1, GError **err,
		const char *ns, const container_id_t refid, gdouble to_step, gdouble to_overall,
		char **master)
{
	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refid != NULL);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_DESTROY,
			NULL,
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"CONTAINER_ID", gba_poolify(&pool, metautils_gba_from_cid(refid)),
			NULL);
	gchar **result = list_request(meta1, to_step, to_overall, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), master);
	message_destroy(req, NULL);
	GBA_POOL_CLEAN(pool);

	if (!result)
		return FALSE;
	g_strfreev(result);
	return TRUE;
}

gchar** 
meta1v2_remote_link_service(const addr_info_t *meta1, GError **err, const char *ns, const container_id_t refID,
		const gchar *srvtype, gdouble to_step, gdouble to_overall, char **master)
{
	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refID != NULL);
	EXTRA_ASSERT(srvtype != NULL);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_SRVAVAIL,
			NULL,
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"CONTAINER_ID", gba_poolify(&pool, metautils_gba_from_cid(refID)),
			"SRVTYPE", gba_poolify(&pool, metautils_gba_from_string(srvtype)),
			NULL);
	gchar **result = list_request(meta1, to_step, to_overall, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), master);
	message_destroy(req, NULL);
	GBA_POOL_CLEAN(pool);

	return result;
}

gchar** 
meta1v2_remote_list_reference_services(const addr_info_t *meta1, GError **err, const char *ns, const container_id_t refid,
		const gchar *srvtype, gdouble to_step, gdouble to_overall)
{
	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refid != NULL);
	GRID_TRACE2("%s:%d", __FUNCTION__, __LINE__);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_SRVALL,
			NULL,
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"CONTAINER_ID", gba_poolify(&pool, metautils_gba_from_cid(refid)),
			"SRVTYPE", gba_poolify(&pool, metautils_gba_from_string(srvtype)),
			NULL);
	gchar **result = list_request(meta1, to_step, to_overall, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), NULL);

	message_destroy(req, NULL);
	GBA_POOL_CLEAN(pool);

	return result;
}

gboolean 
meta1v2_remote_unlink_service(const addr_info_t *meta1, GError **err,
		const char *ns, const container_id_t refid, const gchar *srvtype
		, gdouble to_step, gdouble to_overall, char **master)
{
	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refid != NULL);
	EXTRA_ASSERT(srvtype != NULL);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_SRVDEL,
			NULL,
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"CONTAINER_ID", gba_poolify(&pool, metautils_gba_from_cid(refid)),
			"SRVTYPE", gba_poolify(&pool, metautils_gba_from_string(srvtype)),
			NULL);
	gchar **result = list_request(meta1, to_step, to_overall, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), master);
	message_destroy(req, NULL);
	GBA_POOL_CLEAN(pool);

	if (!result)
		return FALSE;
	g_strfreev(result);
	return TRUE;
}

gboolean meta1v2_remote_unlink_one_service(const addr_info_t *meta1,
		GError **err, const char *ns, const container_id_t refid,
		const gchar *srvtype , gdouble to_step, gdouble to_overall,
		char **master, gint64 seqid)
{
	GSList *pool = NULL;
	GByteArray *body = NULL;

	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refid != NULL);
	EXTRA_ASSERT(srvtype != NULL);

	body = gba_poolify(&pool, g_byte_array_new());

	if (seqid <= 0) {
		if (err)
			*err = NEWERROR(400, "Invalid sequence number [%"G_GINT64_FORMAT"]", seqid);
		GBA_POOL_CLEAN(pool);
		return FALSE;
	}
	else {
		gchar str[128];
		g_snprintf(str, sizeof(str), "%"G_GINT64_FORMAT"\n", seqid);
		g_byte_array_append(body, (guint8*)str, strlen(str));
		GRID_DEBUG("About to delete seqid=%s", str);
	}

	if (body->len <= 0) {
		if (err)
			*err = NEWERROR(400, "No sequence number provided");
		GBA_POOL_CLEAN(pool);
		return FALSE;
	}

	MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_SRVDEL,
			body,
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"CONTAINER_ID", gba_poolify(&pool, metautils_gba_from_cid(refid)),
			"SRVTYPE", gba_poolify(&pool, metautils_gba_from_string(srvtype)),
			NULL);
	gchar **result = list_request(meta1, to_step, to_overall, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), master);
	message_destroy(req, NULL);
	GBA_POOL_CLEAN(pool);

	if (!result)
		return FALSE;
	g_strfreev(result);
	return TRUE;
}

gchar **
meta1v2_remote_poll_reference_service(const addr_info_t *meta1,
		GError **err, const char *ns, const container_id_t refid,
		const gchar *srvtype, gdouble to_step, gdouble to_overall, char **master)
{
	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refid != NULL);
	EXTRA_ASSERT(srvtype != NULL);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_SRVNEW,
			NULL,
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"CONTAINER_ID", gba_poolify(&pool, metautils_gba_from_cid(refid)),
			"SRVTYPE", gba_poolify(&pool, metautils_gba_from_string(srvtype)),
			NULL);
	gchar **result = list_request(meta1, to_step, to_overall, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), master);

	message_destroy(req, NULL);
	GBA_POOL_CLEAN(pool);
	return result;
}

gchar **
meta1v2_remote_update_m1_policy(const addr_info_t *meta1,
                GError **err, const char *ns,  const container_id_t prefix, const container_id_t refid,
                const gchar *srvtype, const gchar* action, gboolean checkonly, const gchar *excludeurl, gdouble to_step, gdouble to_overall)
{
        EXTRA_ASSERT(meta1 != NULL);
        EXTRA_ASSERT(ns != NULL);
        //EXTRA_ASSERT(refid != NULL);
        EXTRA_ASSERT(srvtype != NULL);

        GSList *pool = NULL;
        MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_UPDATEM1POLICY,
                        NULL,
                        "NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
                        "SRVTYPE", gba_poolify(&pool, metautils_gba_from_string(srvtype)),
			"ACTION", gba_poolify(&pool, metautils_gba_from_string(action)),
                        NULL);

	if (prefix) {
		message_add_fields_gba(req,"PREFIX",gba_poolify(&pool,metautils_gba_from_cid(prefix)),NULL);
	}
	if (refid) {
		message_add_fields_gba(req,"CONTAINER_ID",gba_poolify(&pool,metautils_gba_from_cid(refid)),NULL);
	}
	if (checkonly)
		message_add_field( req,"CHECKONLY", strlen("CHECKONLY"),
                                        "true", sizeof("true")-1,
                                        NULL);
	if( excludeurl )
		message_add_fields_gba(req,"EXCLUDEURL",gba_poolify(&pool,metautils_gba_from_string(excludeurl)),NULL);

        gchar **result = list_request(meta1, to_step, to_overall, err,
                        gba_poolify(&pool, message_marshall_gba(req, NULL)), NULL);
        message_destroy(req, NULL);
       GBA_POOL_CLEAN(pool);
        return result;
}


gboolean
meta1v2_remote_force_reference_service(const addr_info_t *meta1,
		GError **err, const char *ns, const container_id_t refid,
		const gchar *url, gdouble to_step, gdouble to_overall, char **master)
{
	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refid != NULL);
	EXTRA_ASSERT(url != NULL);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_SRVSET,
			gba_poolify(&pool, metautils_gba_from_string(url)),
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"CONTAINER_ID", gba_poolify(&pool, metautils_gba_from_cid(refid)),
			NULL);
	gchar **result = list_request(meta1, to_step, to_overall, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), master);
	message_destroy(req, NULL);
	GBA_POOL_CLEAN(pool);

	if (!result)
		return FALSE;
	g_strfreev(result);
	return TRUE;
}

gboolean
meta1v2_remote_configure_reference_service(const addr_info_t *meta1,
		GError **err, const char *ns, const container_id_t refid,
		const gchar *url, gdouble to_step, gdouble to_overall, char **master)
{
	EXTRA_ASSERT(meta1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refid != NULL);
	EXTRA_ASSERT(url != NULL);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_SRVSETARG,
			gba_poolify(&pool, metautils_gba_from_string(url)),
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"CONTAINER_ID", gba_poolify(&pool, metautils_gba_from_cid(refid)),
			NULL);
	gchar **result = list_request(meta1, to_step, to_overall, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), master);
	message_destroy(req, NULL);
	GBA_POOL_CLEAN(pool);

	if (!result)
		return FALSE;
	g_strfreev(result);
	return TRUE;
}

gboolean
meta1v2_remote_reference_set_property(const addr_info_t *m1, GError **err,
		const gchar *ns, const container_id_t refid, gchar **pairs
		, gdouble to_step, gdouble to_overall, char **master)
{
	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refid != NULL);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_CID_PROPSET,
			gba_poolify(&pool, metautils_encode_lines(pairs)),
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"CONTAINER_ID", gba_poolify(&pool, metautils_gba_from_cid(refid)),
			NULL);
	gchar **result = list_request(m1, to_step, to_overall, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), master);
	message_destroy(req, NULL);
	GBA_POOL_CLEAN(pool);

	if (!result)
		return FALSE;
	g_strfreev(result);
	return TRUE;
}

gboolean
meta1v2_remote_reference_get_property(const addr_info_t *m1, GError **err,
		const gchar *ns, const container_id_t refid,
		gchar **keys, gchar ***result, gdouble to_step, gdouble to_overall)
{
	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refid != NULL);
	EXTRA_ASSERT(result != NULL);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_CID_PROPGET,
			gba_poolify(&pool, metautils_encode_lines(keys)),
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"CONTAINER_ID", gba_poolify(&pool, metautils_gba_from_cid(refid)),
			NULL);
	*result = list_request(m1, to_step, to_overall, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), NULL);
	message_destroy(req, NULL);
	GBA_POOL_CLEAN(pool);

	return *result != NULL;
}

gboolean
meta1v2_remote_reference_del_property(const addr_info_t *m1, GError **err,
		const gchar *ns, const container_id_t refid,
		gchar **keys, gdouble to_step, gdouble to_overall, char **master)
{
	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refid != NULL);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_CID_PROPDEL,
			gba_poolify(&pool, metautils_encode_lines(keys)),
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"CONTAINER_ID", gba_poolify(&pool, metautils_gba_from_cid(refid)),
			NULL);
	gchar **result = list_request(m1, to_step, to_overall, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), master);
	message_destroy(req, NULL);
	GBA_POOL_CLEAN(pool);

	if (!result)
		return FALSE;
	g_strfreev(result);
	return TRUE;
}

static GError *
gba_request(const addr_info_t *a, gdouble to_step, gdouble to_overall,
		GByteArray **result, GByteArray *req)
{
	gboolean _reply(gpointer ctx, MESSAGE reply) {
		void *b = NULL;
		gsize bsize = 0;
		if (0 < message_get_BODY(reply, &b, &bsize, NULL)) {
			if (b && bsize)
				g_byte_array_append((GByteArray*)ctx, b, bsize);
		}
		return TRUE;
	}

	gchar stra[128];
	struct client_s *client = NULL;
	GError *e = NULL;
	gboolean gba_created = FALSE;

	EXTRA_ASSERT(req != NULL);

	grid_addrinfo_to_string(a, stra, sizeof(stra));
	if (!*result) {
		*result = g_byte_array_new();
		gba_created = TRUE;
	}
	client = gridd_client_create(stra, req, *result, _reply);

	if (to_step > 0 && to_overall > 0)
		gridd_client_set_timeout(client, to_step, to_overall);

	gscstat_tags_start(GSCSTAT_SERVICE_META1, GSCSTAT_TAGS_REQPROCTIME);
	gridd_client_start(client);
	if (!(e = gridd_client_loop(client)))
		e = gridd_client_error(client);
	gscstat_tags_end(GSCSTAT_SERVICE_META1, GSCSTAT_TAGS_REQPROCTIME);

	gridd_client_free(client);

	if (!e)
		return NULL;

	if (gba_created) {
		g_byte_array_free(*result, TRUE);
		*result = NULL;
	}
	return e;
}



gchar**
meta1v2_remote_list_services(const addr_info_t *m1, GError **err,
        const gchar *ns, const container_id_t refid  )
{

    EXTRA_ASSERT(m1 != NULL);
    EXTRA_ASSERT(ns != NULL);
    EXTRA_ASSERT(refid != NULL);

    GSList *pool = NULL;
    MESSAGE req = message_create_request(NULL, NULL,
            NAME_MSGNAME_M1V2_SRVALLONM1, NULL /* no body */,
            "NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
            "PREFIX", gba_poolify(&pool, metautils_gba_from_cid(refid)),
            NULL);

    gchar** result = list_request(m1,  60000, 60000, err,
                              gba_poolify(&pool, message_marshall_gba(req, NULL)), NULL);

    message_destroy(req, NULL);
    GBA_POOL_CLEAN(pool);

    return result;
}



GError *
meta1v2_remote_list_references(const addr_info_t *m1,
		const gchar *ns, const container_id_t refid,
		GByteArray **result)
{
	GError *err;

	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refid != NULL);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL,
			NAME_MSGNAME_M1V2_LISTBYPREF, NULL /* no body */,
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"PREFIX", gba_poolify(&pool, metautils_gba_from_cid(refid)),
			NULL);

	err = gba_request(m1, 60000, 60000, result,
			gba_poolify(&pool, message_marshall_gba(req, NULL)));

	message_destroy(req, NULL);
	GBA_POOL_CLEAN(pool);
	return err;
}

GError *
meta1v2_remote_list_references_by_service(const addr_info_t *m1,
		const gchar *ns, const container_id_t refid,
		const gchar *srvtype, const gchar *url,
		GByteArray **result)
{
	GError *err;

	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(ns != NULL);
	EXTRA_ASSERT(refid != NULL);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL,
			NAME_MSGNAME_M1V2_LISTBYSERV, NULL /* no body */,
			"NAMESPACE", gba_poolify(&pool, metautils_gba_from_string(ns)),
			"PREFIX", gba_poolify(&pool, metautils_gba_from_cid(refid)),
			"SRVTYPE", gba_poolify(&pool, metautils_gba_from_string(srvtype)),
			"URL", gba_poolify(&pool, metautils_gba_from_string(url)),
			NULL);

	err = gba_request(m1, 60000, 60000, result,
			gba_poolify(&pool, message_marshall_gba(req, NULL)));

	message_destroy(req, NULL);
	GBA_POOL_CLEAN(pool);
	return err;
}

gboolean
meta1v2_remote_get_prefixes(const addr_info_t *m1, GError **err,
		gchar *** result)
{
	EXTRA_ASSERT(m1 != NULL);

	GSList *pool = NULL;
	MESSAGE req = message_create_request(NULL, NULL, NAME_MSGNAME_M1V2_GETPREFIX,
			NULL,
			NULL);
	*result = list_request(m1, 60000, 60000, err,
			gba_poolify(&pool, message_marshall_gba(req, NULL)), NULL);
	message_destroy(req, NULL);
	GBA_POOL_CLEAN(pool);

	return *result != NULL;
}

