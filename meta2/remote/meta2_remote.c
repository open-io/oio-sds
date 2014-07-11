#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "meta2.remote"
#endif

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <metautils/lib/metautils.h>

#include <glib.h>

#include "meta2_remote.h"
#include "internals.h"

typedef enum meta2_operation_e
{
	M2_OP_INFO,

	M2_OP_CONTAINER_CREATE,
	M2_OP_CONTAINER_DESTROY,
	M2_OP_CONTAINER_OPEN,
	M2_OP_CONTAINER_CLOSE,
	M2_OP_CONTAINER_LIST,

	M2_OP_CONTAINER_GETFLAG,
	M2_OP_CONTAINER_SETFLAG,
	
	M2_OP_CONTENT_SPARE,
	M2_OP_CONTENT_ADD,
	M2_OP_CONTENT_REMOVE,
	M2_OP_CONTENT_RETRIEVE,
	M2_OP_CONTENT_COMMIT,
	M2_OP_CONTENT_ROLLBACK,

	M2_OP_CHUNK_COMMIT,
	M2_OP_CONTENT_APPEND

} meta2_operation_t;


static gint __get_request_name2 (meta2_operation_t mo, gchar **str, gsize *len)
{
#define SETSTR(S) do { *str=S; *len=sizeof(S)-1; } while (0)
	switch (mo)
	{
		case M2_OP_INFO:		    SETSTR(NAME_MSGNAME_M2_INFO);	    return 1;
		case M2_OP_CONTAINER_CREATE:        SETSTR(NAME_MSGNAME_M2_CREATE);         return 1;
		case M2_OP_CONTAINER_DESTROY:       SETSTR(NAME_MSGNAME_M2_DESTROY);        return 1;
		case M2_OP_CONTAINER_OPEN:          SETSTR(NAME_MSGNAME_M2_OPEN);           return 1;
		case M2_OP_CONTAINER_CLOSE:         SETSTR(NAME_MSGNAME_M2_CLOSE);          return 1;
		case M2_OP_CONTAINER_LIST:          SETSTR(NAME_MSGNAME_M2_LIST);           return 1;
		case M2_OP_CONTAINER_GETFLAG:       SETSTR(NAME_MSGNAME_M2_GETFLAG);        return 1;
		case M2_OP_CONTAINER_SETFLAG:       SETSTR(NAME_MSGNAME_M2_SETFLAG);        return 1;

		case M2_OP_CONTENT_SPARE:    SETSTR(NAME_MSGNAME_M2_CONTENTSPARE);    return 1;
		case M2_OP_CONTENT_ADD:      SETSTR(NAME_MSGNAME_M2_CONTENTADD);      return 1;
		case M2_OP_CONTENT_REMOVE:   SETSTR(NAME_MSGNAME_M2_CONTENTREMOVE);   return 1;
		case M2_OP_CONTENT_RETRIEVE: SETSTR(NAME_MSGNAME_M2_CONTENTRETRIEVE); return 1;
		case M2_OP_CONTENT_COMMIT:   SETSTR(NAME_MSGNAME_M2_CONTENTCOMMIT);   return 1;
		case M2_OP_CONTENT_ROLLBACK: SETSTR(NAME_MSGNAME_M2_CONTENTROLLBACK); return 1;

		case M2_OP_CHUNK_COMMIT:     SETSTR(NAME_MSGNAME_M2_CHUNK_COMMIT); return 1;
		case M2_OP_CONTENT_APPEND:   SETSTR(NAME_MSGNAME_M2_CONTENTAPPEND); return 1;
	}
	return 0;
#undef SETSTR
}


static gint
meta2_remote_request_add_path(MESSAGE m, const gchar * path, gboolean hasLength, const content_length_t content_length,
    GError ** err)
{
	gint retCode;
	gchar wrkBuf[32];
	gsize wrkLen;

	if (!m || !path) {
		GSETERROR(err, "Invalid parameter");
		return 0;
	}

	retCode =
	    message_add_field(m, NAME_MSGKEY_CONTENTPATH, sizeof(NAME_MSGKEY_CONTENTPATH) - 1, path, strlen(path), err);
	if (!retCode) {
		GSETERROR(err, "Cannot add the path to the message");
		return 0;
	}

	if (hasLength) {
		wrkLen = g_snprintf(wrkBuf, 31, "%"G_GINT64_FORMAT, content_length);

		retCode =
		    message_add_field(m, NAME_MSGKEY_CONTENTLENGTH, sizeof(NAME_MSGKEY_CONTENTLENGTH) - 1, wrkBuf,
		    wrkLen, err);
		if (!retCode) {
			GSETERROR(err, "Cannot add the path length to the message");
			return 0;
		}
	}

	return 1;
}

static gint
meta2_remote_request_add_vns(MESSAGE m, const gchar *vns, GError ** err) 
{
	gint retCode;

	if (!m || !vns) {
		GSETERROR(err, "Invalid parameter");
		return 0;
	}

	retCode =
	    message_add_field(m, NAME_MSGKEY_VIRTUALNAMESPACE, sizeof(NAME_MSGKEY_VIRTUALNAMESPACE) - 1, vns, strlen(vns), err);
	if (!retCode) {
		GSETERROR(err, "Cannot add the virtual_namespace to the message");
		return 0;
	}

	return 1;
}


static gint
meta2_remote_request_create(MESSAGE m, meta2_operation_t mop, const container_id_t id, GError ** error)
{
	gint retCode;
	gsize wrkLen = 0;
	char *wrkBuf = NULL;

	if (!m || !id) {
		GSETERROR(error, "Invalid parameter");
		return 0;
	}

	/*builds the name of the request */
	retCode = __get_request_name2(mop, &wrkBuf, &wrkLen);
	if (!retCode) {
		GSETERROR(error, "Invalid request type");
		return 0;
	}

	/*sets the request name */
	retCode = message_set_NAME(m, wrkBuf, wrkLen, error);
	if (!retCode) {
		GSETERROR(error, "Cannot set the name of the request");
		return 0;
	}

	/*Sets the container ID */
	retCode =
	    message_add_field(m, NAME_MSGKEY_CONTAINERID, sizeof(NAME_MSGKEY_CONTAINERID) - 1, id,
	    sizeof(container_id_t), error);
	if (!retCode) {
		GSETERROR(error, "Cannot set the containerId in the request");
		return 0;
	}

	return 1;
}

static gint
meta2_remote_container_common_fd_v2(const char *caller, int *fd, gint ms, GError ** err, meta2_operation_t mop,
    const container_id_t cid, const gchar *name, const gchar *vns, const char *stgpol)
{
	static struct code_handler_s codes[] = {
		{200, REPSEQ_FINAL, NULL, NULL},
		{0, 0, NULL, NULL}
	};

	struct reply_sequence_data_s data = { NULL, 0, codes };
	MESSAGE request = NULL;

	if (!message_create(&request, err)) {
		GSETERROR(err, "<%s> Cannot create a message", caller);
		return 0;
	}

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	if (!meta2_remote_request_create(request, mop, cid, err)) {
		GSETERROR(err, "<%s> Cannot init the message as a simple metaX request", caller);
		goto errorLabel;
	}

	if (name
	    && !message_add_field(request, NAME_HEADER_CONTAINERNAME, sizeof(NAME_HEADER_CONTAINERNAME) - 1, name,
		strlen(name), err)) {
		GSETERROR(err, "Cannot set the containerName in the request");
		goto errorLabel;
	}

	if ( NULL != vns
	    && !message_add_field(request, NAME_HEADER_VIRTUALNAMESPACE, sizeof(NAME_HEADER_VIRTUALNAMESPACE) - 1, vns,
		strlen(vns), err)) {
		GSETERROR(err, "Cannot set the virtualNamespace in the request");
		goto errorLabel;
	}

	if ( NULL != stgpol
	    && !message_add_field(request, NAME_HEADER_STORAGEPOLICY, sizeof(NAME_HEADER_STORAGEPOLICY) - 1, stgpol,
		strlen(stgpol), err)) {
		GSETERROR(err, "Cannot set the storagePolicy in the request");
		goto errorLabel;
	}

	if (!metaXClient_reply_sequence_run(err, request, fd, ms, &data)) {
		GSETERROR(err, "<%s> An error occured while executing the request", caller);
		goto errorLabel;
	}

	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	message_destroy(request, NULL);
	return TRUE;

errorLabel:
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	message_destroy(request, NULL);
	return FALSE;
}

static gint
meta2_remote_container_common_fd(const char *caller, int *fd, gint ms, GError ** err, meta2_operation_t mop,
    const container_id_t container_id, const gchar * name)
{
	return meta2_remote_container_common_fd_v2(caller, fd, ms, err, mop, container_id, name, NULL, NULL);
}

static gint
meta2_remote_container_common_v2(const char *caller, const addr_info_t * m2_addr, gint ms,
		GError ** err, meta2_operation_t mop,
		const container_id_t cid, const char *name, const char *vns, const char *stgpol)
{
	int fd = -1;
	gint rc = 0;

	fd = addrinfo_connect(m2_addr, ms, err);
	if (fd < 0) {
		GSETERROR(err, "<%s> Connection failed", caller);
		return 0;
	}

	if (meta2_remote_container_common_fd_v2(caller, &fd, ms, err, mop, cid, name, vns, stgpol)) {
		rc = 1;
	}

	metautils_pclose(&fd);
	return rc;
}

static gint
meta2_remote_container_common(const char *caller, addr_info_t * m2_addr, gint ms, GError ** err, meta2_operation_t mop,
    const container_id_t container_id, const gchar * name)
{
	return meta2_remote_container_common_v2(caller, m2_addr, ms, err, mop, container_id, name, NULL, NULL);
}

/* ------------------------------------------------------------------------- */


gboolean meta2_remote_container_open (addr_info_t *m2_addr, gint ms, GError **err, const container_id_t container_id)
{
	return meta2_remote_container_common (__FUNCTION__, m2_addr, ms, err, M2_OP_CONTAINER_OPEN, container_id, NULL);
}


gboolean meta2_remote_container_close (addr_info_t *m2_addr, gint ms, GError **err, const container_id_t container_id)
{
	return meta2_remote_container_common (__FUNCTION__, m2_addr, ms, err, M2_OP_CONTAINER_CLOSE, container_id, NULL);
}


gboolean meta2_remote_container_destroy (addr_info_t *m2_addr, gint ms, GError **err, const container_id_t container_id)
{
	return meta2_remote_container_common (__FUNCTION__, m2_addr, ms, err, M2_OP_CONTAINER_DESTROY, container_id, NULL);
}

gboolean meta2_remote_container_create (addr_info_t *m2_addr, gint ms, GError **err, const container_id_t container_id, const gchar *name)
{
	return meta2_remote_container_common (__FUNCTION__, m2_addr, ms, err, M2_OP_CONTAINER_CREATE, container_id, name);
}

gboolean meta2_remote_container_create_v2 (addr_info_t *m2_addr, gint ms, GError **err, const container_id_t container_id,
		 const gchar *name, const gchar *virtual_namespace)
{
	return meta2_remote_container_common_v2 (__FUNCTION__, m2_addr, ms, err, M2_OP_CONTAINER_CREATE,
			container_id, name, virtual_namespace, NULL);
}

gboolean meta2_remote_container_create_v3 (const addr_info_t *m2, gint ms, const char *ns, const char *cname,
		const container_id_t cid, const char *stgpol, GError **e)
{
	const char *vns = NULL;
	if( NULL != ns && NULL != strchr(ns, '.'))
		vns = ns;

	return meta2_remote_container_common_v2 (__FUNCTION__, m2, ms, e, M2_OP_CONTAINER_CREATE, cid, cname, vns, stgpol);
}


GSList* meta2_remote_container_list (addr_info_t *m2_addr, gint ms, GError **err, const container_id_t container_id)
{
	static struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL,         &path_info_concat, NULL},
		{ 206, REPSEQ_BODYMANDATORY, &path_info_concat, NULL},
		{ 0, 0, NULL, NULL},
	};

	GSList *result = NULL;
	struct reply_sequence_data_s data = { &result , 0 , codes };
	MESSAGE request = NULL;

	if (!message_create (&request, err)) {
		GSETERROR(err, "Cannot create a message");
		return 0;
	}

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	if (!meta2_remote_request_create (request, M2_OP_CONTAINER_LIST, container_id, err)) {
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	if (!metaXClient_reply_sequence_run_from_addrinfo (err, request, m2_addr, ms, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto errorLabel;
	}

	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	message_destroy(request, NULL);
	return result;

errorLabel:
	if (result) {
		g_slist_foreach (result, path_info_gclean, NULL);
		g_slist_free (result);
		result = NULL;
	}

	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	message_destroy(request, NULL);
	return NULL;
}

gboolean meta2_remote_container_set_flag (addr_info_t *m2_addr, gint ms, GError **err, const container_id_t container_id, guint32 flag)
{
	static struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, NULL },
		{ 0, 0, NULL, NULL },
	};
	
	struct reply_sequence_data_s data = { NULL , 0 , codes };

	MESSAGE request = NULL;

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	if (!message_create (&request, err))
	{
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}
	
	if (!meta2_remote_request_create (request, M2_OP_CONTAINER_SETFLAG, container_id, err))
	{
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	flag = g_htonl(flag);
	if (!message_set_BODY(request, &flag, sizeof(flag), err))
	{
		GSETERROR(err, "Cannot add the new FLAG in the request (as a body)");
		goto errorLabel;
	}
	else
	{
		TRACE("set flag %08x (originally %08x)", flag, g_ntohl(flag));
	}

	if (!metaXClient_reply_sequence_run_from_addrinfo (err, request, m2_addr, ms, &data))
	{
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto errorLabel;
	}

	message_destroy(request, NULL);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	return TRUE;
errorLabel:
	if (request)
	{
		message_destroy(request, NULL);
	}

	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	return FALSE;
}

gboolean
meta2_remote_container_get_flag(addr_info_t * m2_addr, gint ms, GError ** err, const container_id_t container_id,
    guint32 * flag)
{
	gboolean flag_extractor(GError ** err0, gpointer udata, gint code, guint8 * body, gsize bodySize)
	{
		(void) code;
		if (!body || bodySize <= 0) {
			GSETERROR(err0, "Invalid parameter (%p %p %u)", udata, body, bodySize);
			return FALSE;
		}
		else if (bodySize != sizeof(*flag)) {
			GSETERROR(err0, "wrong size for the FLAG in the response");
			return FALSE;
		}
		else {
			guint32 local_flags;

			memcpy(&local_flags, body, bodySize);
			*flag = g_ntohl(local_flags);
			return TRUE;
		}
	}


	struct code_handler_s codes[] = {
		{200, REPSEQ_FINAL, flag_extractor, NULL},
		{0, 0, NULL, NULL},
	};

	struct reply_sequence_data_s data = { NULL, 0, codes };

	MESSAGE request = NULL;

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	if (!message_create(&request, err)) {
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}

	if (!meta2_remote_request_create(request, M2_OP_CONTAINER_GETFLAG, container_id, err)) {
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	if (!metaXClient_reply_sequence_run_from_addrinfo(err, request, m2_addr, ms, &data)) {
		GSETERROR(err, "Cannot execute the query and receive all the responses");
		goto errorLabel;
	}

	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	message_destroy(request, NULL);

	return TRUE;
      errorLabel:
	if (request)
		message_destroy(request, NULL);

	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	return FALSE;
}


/* ------------------------------------------------------------------------- */


gboolean meta2_remote_content_remove (addr_info_t *m2_addr, gint ms, GError **err, const container_id_t container_id, const gchar *content_path)
{
	struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, NULL },
		{ 0, 0, NULL, NULL },
	};
	
	struct reply_sequence_data_s data = { NULL , 0 , codes };

	MESSAGE request = NULL;

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	if (!message_create (&request, err))
	{
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}
	
	if (!meta2_remote_request_create (request, M2_OP_CONTENT_REMOVE, container_id, err))
	{
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	if (!meta2_remote_request_add_path (request, content_path, FALSE, 0, err))
	{
		GSETERROR(err, "Cannot add the content_path in the request (as a field)");
		goto errorLabel;
	}

	if (!metaXClient_reply_sequence_run_from_addrinfo (err, request, m2_addr, ms, &data))
	{
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto errorLabel;
	}

	message_destroy(request, NULL);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	return TRUE;
errorLabel:
	if (request)
	{
		message_destroy(request, NULL);
	}

	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	return FALSE;
}


gboolean meta2_remote_content_commit (addr_info_t *m2_addr, gint ms, GError **err, const container_id_t container_id, const gchar *content_path)
{
	struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, NULL },
		{ 0,0,NULL,NULL}
	};
	
	struct reply_sequence_data_s data = { NULL , 0 , codes };

	MESSAGE request = NULL;

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	if (!message_create (&request, err))
	{
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}
	
	if (!meta2_remote_request_create (request, M2_OP_CONTENT_COMMIT, container_id, err))
	{
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	if (!meta2_remote_request_add_path (request, content_path, FALSE, 0, err))
	{
		GSETERROR(err, "Cannot add the content_path in the request (as a field)");
		goto errorLabel;
	}

	if (!metaXClient_reply_sequence_run_from_addrinfo (err, request, m2_addr, ms, &data))
	{
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto errorLabel;
	}

	message_destroy(request, NULL);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	return TRUE;
errorLabel:
	if (request)
	{
		message_destroy(request, NULL);
	}
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	return FALSE;
}


gint meta2_remote_content_rollback (addr_info_t *m2_addr, gint ms, GError **err,
	const container_id_t container_id, const gchar *content_path)
{
	struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, NULL },
		{ 0,0,NULL,NULL}
	};
	
	struct reply_sequence_data_s data = { NULL , 0 , codes };

	MESSAGE request = NULL;
	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	if (!message_create (&request, err))
	{
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}
	
	if (!meta2_remote_request_create (request, M2_OP_CONTENT_ROLLBACK, container_id, err))
	{
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	if (!message_add_field(request, NAME_MSGKEY_CONTENTPATH, sizeof(NAME_MSGKEY_CONTENTPATH)-1, content_path, strlen(content_path), err))
	{
		GSETERROR(err, "Cannot add the content_path in the request (as a field)");
		goto errorLabel;
	}

	if (!metaXClient_reply_sequence_run_from_addrinfo (err, request, m2_addr, ms, &data))
	{
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto errorLabel;
	}

	message_destroy(request, NULL);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	return 1;
errorLabel:
	if (request)
	{
		message_destroy(request, NULL);
	}
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	return 0;
}


GSList* meta2_remote_content_retrieve (addr_info_t *m2_addr, gint ms, GError **err, const container_id_t container_id, const gchar *content_path)
{
	GSList *result = NULL;
	
	struct code_handler_s codes [] = {
		{ 206, REPSEQ_BODYMANDATORY, chunk_info_concat, NULL },
		{ 200, REPSEQ_FINAL,         chunk_info_concat, NULL },
		{ 0, 0, NULL, NULL }
	};
	
	struct reply_sequence_data_s data = { &result , 0 , codes };

	MESSAGE request = NULL;

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	if (!message_create (&request, err))
	{
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}
	
	if (!meta2_remote_request_create (request, M2_OP_CONTENT_RETRIEVE, container_id, err))
	{
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	if (!meta2_remote_request_add_path(request, content_path, FALSE, 0, err))
	{
		GSETERROR(err, "Cannot add the content_path in the request (as a field)");
		goto errorLabel;
	}

	if (!metaXClient_reply_sequence_run_from_addrinfo (err, request, m2_addr, ms, &data))
	{
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto errorLabel;
	}

	message_destroy(request, NULL);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	return result;
errorLabel:
	if (request)
	{
		message_destroy(request, NULL);
	}

	if (result)
	{
		g_slist_foreach (result, chunk_info_gclean, NULL);
		g_slist_free (result);
	}
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	return NULL;
}

GSList* meta2_remote_content_add (addr_info_t *m2_addr, gint ms, GError **err,
	const container_id_t container_id, const gchar *content_path,
	content_length_t content_length, GByteArray *system_metadata, GByteArray **new_system_metadata)
{
	GSList *result = NULL;

	gboolean get_sys_metadata (GError **err0, gpointer udata, gint code, MESSAGE rep) {
		int rc;
		void *field=NULL;
		gsize fieldLen=0;

		(void)code;
		(void)udata;

		if (!rep)
			return FALSE;
		if (!new_system_metadata)
			return TRUE;
		rc = message_get_field (rep, NAME_HEADER_METADATA_SYS, sizeof(NAME_HEADER_METADATA_SYS)-1, &field, &fieldLen, err0);
		switch (rc) {
			case 1:
				*new_system_metadata = g_byte_array_append( g_byte_array_new(), field, fieldLen);
				return TRUE;
			case 0:
				*new_system_metadata = NULL;
				return TRUE;
		}
		GSETERROR(err0, "Cannot lookup the updated systemetadata");
		return FALSE;
	}

	struct code_handler_s codes [] = {
		{ 206, REPSEQ_BODYMANDATORY, chunk_info_concat, NULL },
		{ 200, REPSEQ_FINAL,         chunk_info_concat, get_sys_metadata },
		{ 0,0,NULL,NULL}
	};

	struct reply_sequence_data_s data = { &result , 0 , codes };

	MESSAGE request = NULL;

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	if (!message_create (&request, err))
	{
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}

	if (!meta2_remote_request_create (request, M2_OP_CONTENT_ADD, container_id, err))
	{
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	if (!meta2_remote_request_add_path(request, content_path, TRUE, content_length, err))
	{
		GSETERROR(err, "Cannot add the content_path in the request (as a field)");
		goto errorLabel;
	}

	if (system_metadata && system_metadata->data && system_metadata->len>0) {
		int rc;
		rc = message_add_field (request,
			NAME_HEADER_METADATA_SYS, sizeof(NAME_HEADER_METADATA_SYS)-1,
			system_metadata->data, system_metadata->len, err);
		if (1 != rc) {
			GSETERROR(err, "Cannot add the system metadata as a field");
			goto errorLabel;
		}
	}

	if (!metaXClient_reply_sequence_run_from_addrinfo (err, request, m2_addr, ms, &data))
	{
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto errorLabel;
	}

	message_destroy(request, NULL);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	return result;
errorLabel:
	if (request)
	{
		message_destroy(request, NULL);
	}

	if (result)
	{
		g_slist_foreach (result, chunk_info_gclean, NULL);
		g_slist_free (result);
	}
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	return NULL;
}


gboolean meta2_remote_chunk_commit (addr_info_t *m2_addr, gint ms, GError **err, const container_id_t container_id, const gchar *content_path, GSList *chunks)
{
	struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, NULL },
		{ 0, 0, NULL, NULL }
	};

	struct reply_sequence_data_s data = { NULL , 0 , codes };

	void *body=NULL;
	gsize bodySize=0;
	MESSAGE request = NULL;
	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	if (!message_create (&request, err))
	{
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}
	
	if (!meta2_remote_request_create (request, M2_OP_CHUNK_COMMIT, container_id, err))
	{
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	if (!meta2_remote_request_add_path(request, content_path, FALSE, 0, err))
	{
		GSETERROR(err, "Cannot add the content_path in the request (as a field)");
		goto errorLabel;
	}

	/*serialize and add the body*/
	if (!chunk_info_marshall(chunks, &body, &bodySize, err))
	{
		GSETERROR(err,"Cannot serialize the chunk_info_t* list");
		goto errorLabel;
	}

	if (0>= message_set_BODY(request, body, bodySize, err))
	{
		GSETERROR(err,"Cannot add the serialized chunks in the message");
		goto errorLabel;
	}

	if (!metaXClient_reply_sequence_run_from_addrinfo (err, request, m2_addr, ms, &data))
	{
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto errorLabel;
	}

	g_free(body);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	message_destroy(request, NULL);
	return TRUE;
errorLabel:
	if (request)
		message_destroy(request, NULL);
	if (body)
		g_free(body);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return FALSE;
}


GSList* meta2_remote_content_spare (addr_info_t *m2_addr, gint ms, GError **err,
	const container_id_t container_id, const gchar *content_path)
{
	GSList *result = NULL;
	
	struct code_handler_s codes [] = {
		{ 206, REPSEQ_BODYMANDATORY, chunk_info_concat, NULL },
		{ 200, REPSEQ_FINAL,         chunk_info_concat, NULL },
		{ 0,0,NULL,NULL}
	};
	
	struct reply_sequence_data_s data = { &result , 0 , codes };

	MESSAGE request = NULL;
	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	if (!message_create (&request, err))
	{
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}
	
	if (!meta2_remote_request_create (request, M2_OP_CONTENT_SPARE, container_id, err))
	{
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	if (!meta2_remote_request_add_path(request, content_path, FALSE, 0, err))
	{
		GSETERROR(err, "Cannot add the content_path in the request (as a field)");
		goto errorLabel;
	}

	if (!metaXClient_reply_sequence_run_from_addrinfo (err, request, m2_addr, ms, &data))
	{
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto errorLabel;
	}

	message_destroy(request, NULL);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	return result;
errorLabel:
	if (request)
	{
		message_destroy(request, NULL);
	}

	if (result)
	{
		g_slist_foreach (result, chunk_info_gclean, NULL);
		g_slist_free (result);
	}
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	return NULL;
}


/* ------------------------------------------------------------------------- */

gboolean meta2_remote_container_create_in_fd (int *fd, gint ms, GError **err, const container_id_t container_id, const gchar *name)
{
	return meta2_remote_container_common_fd (__FUNCTION__, fd, ms, err, M2_OP_CONTAINER_CREATE, container_id, name);
}

gboolean meta2_remote_container_destroy_in_fd (int *fd, gint ms, GError **err, const container_id_t container_id)
{
	return meta2_remote_container_common_fd (__FUNCTION__, fd, ms, err, M2_OP_CONTAINER_DESTROY, container_id, NULL);
}

gboolean meta2_remote_container_open_in_fd (int *fd, gint ms, GError **err, const container_id_t container_id)
{
	return meta2_remote_container_common_fd (__FUNCTION__, fd, ms, err, M2_OP_CONTAINER_OPEN, container_id, NULL);
}

gboolean meta2_remote_container_close_in_fd (int *fd, gint ms, GError **err, const container_id_t container_id)
{
	return meta2_remote_container_common_fd (__FUNCTION__, fd, ms, err, M2_OP_CONTAINER_CLOSE, container_id, NULL);
}


GSList* meta2_remote_content_retrieve_in_fd (int *fd, gint ms, GError **err, const container_id_t container_id, const gchar *content_path)
{
	MESSAGE request = NULL;
	GSList *result = NULL;
	
	struct code_handler_s codes [] = {
		{ 206, REPSEQ_BODYMANDATORY, chunk_info_concat, NULL },
		{ 200, REPSEQ_FINAL,         chunk_info_concat, NULL },
		{ 0, 0, NULL, NULL }
	};
	
	struct reply_sequence_data_s data = { &result , 0 , codes };

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	if (!message_create (&request, err))
	{
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}
	
	if (!meta2_remote_request_create (request, M2_OP_CONTENT_RETRIEVE, container_id, err))
	{
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	if (!meta2_remote_request_add_path(request, content_path, FALSE, 0, err))
	{
		GSETERROR(err, "Cannot add the content_path in the request (as a field)");
		goto errorLabel;
	}

	if (!metaXClient_reply_sequence_run (err, request, fd, ms, &data))
	{
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto errorLabel;
	}

	message_destroy(request, NULL);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return result;
errorLabel:
	if (request)
	{
		message_destroy(request, NULL);
	}

	if (result)
	{
		g_slist_foreach (result, chunk_info_gclean, NULL);
		g_slist_free (result);
	}

	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return NULL;
}


gint meta2_remote_content_rollback_in_fd (int *fd, gint ms, GError **err,
	const container_id_t container_id, const gchar *content_path)
{
	static struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, NULL },
		{ 0,0,NULL,NULL}
	};
	
	struct reply_sequence_data_s data = { NULL , 0 , codes };
	MESSAGE request = NULL;
	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	if (!message_create (&request, err))
	{
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}
	
	if (!meta2_remote_request_create (request, M2_OP_CONTENT_ROLLBACK, container_id, err))
	{
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	if (!message_add_field(request, NAME_MSGKEY_CONTENTPATH, sizeof(NAME_MSGKEY_CONTENTPATH)-1, content_path, strlen(content_path), err))
	{
		GSETERROR(err, "Cannot add the content_path in the request (as a field)");
		goto errorLabel;
	}

	if (!metaXClient_reply_sequence_run (err, request, fd, ms, &data))
	{
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto errorLabel;
	}

	message_destroy(request, NULL);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return 1;
errorLabel:
	if (request)
	{
		message_destroy(request, NULL);
	}

	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return 0;
}


GSList* meta2_remote_content_add_in_fd_v2 (int *fd, gint ms, GError **err,
	const container_id_t container_id, const gchar *content_path, content_length_t content_length,
	GByteArray *user_metadata, GByteArray *system_metadata, GByteArray **new_system_metadata)
{
	GSList *result = NULL;

	gboolean get_sys_metadata (GError **err0, gpointer udata, gint code, MESSAGE rep) {
		int rc;
		void *field=NULL;
		gsize fieldLen=0;

		(void)udata;
		(void)code;

		if (!rep)
			return FALSE;
		if (!new_system_metadata)
			return TRUE;
		rc = message_get_field (rep, NAME_HEADER_METADATA_SYS, sizeof(NAME_HEADER_METADATA_SYS)-1, &field, &fieldLen, err0);
		switch (rc) {
			case 1:
				*new_system_metadata = g_byte_array_append( g_byte_array_new(), field, fieldLen);
				return TRUE;
			case 0:
				*new_system_metadata = NULL;
				return TRUE;
		}
		GSETERROR(err0, "Cannot lookup the updated systemetadata");
		return FALSE;
	}

	struct code_handler_s codes [] = {
		{ 206, REPSEQ_BODYMANDATORY, chunk_info_concat, NULL },
		{ 200, REPSEQ_FINAL,         chunk_info_concat, get_sys_metadata },
		{ 0,0,NULL,NULL}
	};

	struct reply_sequence_data_s data = { &result , 0 , codes };

	MESSAGE request = NULL;
	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	if (!message_create (&request, err))
	{
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}

	if (!meta2_remote_request_create (request, M2_OP_CONTENT_ADD, container_id, err))
	{
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	if (!meta2_remote_request_add_path(request, content_path, TRUE, content_length, err))
	{
		GSETERROR(err, "Cannot add the content_path in the request (as a field)");
		goto errorLabel;
	}

	if (system_metadata) {
		register int rc;
		rc = message_add_field (request,
			NAME_HEADER_METADATA_SYS, sizeof(NAME_HEADER_METADATA_SYS)-1,
			system_metadata->data, system_metadata->len, err);
		if (1 != rc) {
			GSETERROR(err, "Cannot add the system metadata as a field");
			goto errorLabel;
		}
	}

	if (user_metadata) {
		register int rc;
		rc = message_add_field (request,
			NAME_HEADER_METADATA_USR, sizeof(NAME_HEADER_METADATA_USR)-1,
			user_metadata->data, user_metadata->len, err);
		if (1 != rc) {
			GSETERROR(err, "Cannot add the user metadata as a field");
			goto errorLabel;
		}
	}

	if (!metaXClient_reply_sequence_run (err, request, fd, ms, &data))
	{
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto errorLabel;
	}

	message_destroy(request, NULL);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	return result;
errorLabel:
	if (request)
		message_destroy(request, NULL);

	if (result) {
		g_slist_foreach (result, chunk_info_gclean, NULL);
		g_slist_free (result);
	}

	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	return NULL;
}

GSList* meta2_remote_content_add_in_fd (int *fd, gint ms, GError **err,
	const container_id_t container_id, const gchar *content_path, content_length_t content_length,
	GByteArray *system_metadata, GByteArray **new_system_metadata)
{
	return meta2_remote_content_add_in_fd_v2(fd, ms, err, container_id, content_path, content_length, NULL, system_metadata, new_system_metadata);
}

GSList *meta2_remote_content_append_in_fd(int *fd, gint ms, GError ** err,
    const container_id_t container_id, const gchar * content_path, content_length_t content_length)
{
	return meta2_remote_content_append_in_fd_v2(fd, ms, err, container_id, content_path, content_length, NULL);
}

GSList *meta2_remote_content_append_in_fd_v2(int *fd, gint ms, GError ** err,
	    const container_id_t container_id, const gchar * content_path,
		content_length_t content_length, GByteArray **sys_metadata)
{
	GSList *result = NULL;

	gboolean get_sys_metadata (GError **err0, gpointer udata, gint code, MESSAGE rep) {
			int rc;
			void *field=NULL;
			gsize fieldLen=0;

			(void)udata;
			(void)code;

			if (!rep)
				return FALSE;
			if (!sys_metadata)
				return TRUE;
			rc = message_get_field (rep, NAME_HEADER_METADATA_SYS,
					sizeof(NAME_HEADER_METADATA_SYS)-1, &field, &fieldLen, err0);
			switch (rc) {
				case 1:
					*sys_metadata = g_byte_array_append( g_byte_array_new(), field, fieldLen);
					return TRUE;
				case 0:
					*sys_metadata = NULL;
					return TRUE;
			}
			GSETERROR(err0, "Cannot lookup the updated systemetadata");
			return FALSE;
	}

	struct code_handler_s codes[] = {
		{206, REPSEQ_BODYMANDATORY, chunk_info_concat, NULL},
		{200, REPSEQ_FINAL,         chunk_info_concat, get_sys_metadata },
		{0, 0, NULL, NULL}
	};

	MESSAGE request = NULL;
	struct reply_sequence_data_s data = { &result, 0, codes };

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	if (!container_id || !content_path || !content_length) {
		GSETERROR(err, "Invalid parameter");
		goto errorLabel;
	}

	if (!message_create(&request, err)) {
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}
	if (!meta2_remote_request_create(request, M2_OP_CONTENT_APPEND, container_id, err)) {
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}
	if (!meta2_remote_request_add_path(request, content_path, TRUE, content_length, err)) {
		GSETERROR(err, "Cannot add the content_path in the request (as a field)");
		goto errorLabel;
	}

	if (!metaXClient_reply_sequence_run (err, request, fd, ms, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto errorLabel;
	}

	message_destroy(request, NULL);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return result;

errorLabel:
	if (request)
		message_destroy(request, NULL);

	if (result) {
		g_slist_foreach (result, chunk_info_gclean, NULL);
		g_slist_free (result);
	}
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return NULL;
}

GSList* meta2_remote_container_list_in_fd (int *fd, gint ms, GError **err, const container_id_t container_id)
{
	GSList *result = NULL;

	struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL,         &path_info_concat, NULL},
		{ 206, REPSEQ_BODYMANDATORY, &path_info_concat, NULL},
		{ 0, 0, NULL, NULL},
	};
	
	struct reply_sequence_data_s data = { &result , 0 , codes };

	MESSAGE request = NULL;
	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	if (!message_create (&request, err))
	{
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}
	
	if (!meta2_remote_request_create (request, M2_OP_CONTAINER_LIST, container_id, err))
	{
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	if (!metaXClient_reply_sequence_run (err, request, fd, ms, &data))
	{
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto errorLabel;
	}
	
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	message_destroy(request, NULL);
	return result;
errorLabel:
	if (result)
	{
		g_slist_foreach (result, path_info_gclean, NULL);
		g_slist_free (result);
		result = NULL;
	}

	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	
	return NULL;
}


gboolean meta2_remote_chunk_commit_in_fd (int *fd, gint ms, GError **err, const container_id_t container_id, const gchar *content_path, GSList *chunks)
{
	struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, NULL },
		{ 0, 0, NULL, NULL }
	};

	struct reply_sequence_data_s data = { NULL , 0 , codes };

	void *body=NULL;
	gsize bodySize=0;
	MESSAGE request = NULL;

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	if (!message_create (&request, err))
	{
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}
	
	if (!meta2_remote_request_create (request, M2_OP_CHUNK_COMMIT, container_id, err))
	{
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	if (!meta2_remote_request_add_path(request, content_path, FALSE, 0, err))
	{
		GSETERROR(err, "Cannot add the content_path in the request (as a field)");
		goto errorLabel;
	}

	/*serialize and add the body*/
	if (!chunk_info_marshall(chunks, &body, &bodySize, err))
	{
		GSETERROR(err,"Cannot serialize the chunk_info_t* list");
		goto errorLabel;
	}

	if (0>= message_set_BODY(request, body, bodySize, err))
	{
		GSETERROR(err,"Cannot add the serialized chunks in the message");
		goto errorLabel;
	}

	if (!metaXClient_reply_sequence_run (err, request, fd, ms, &data))
	{
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto errorLabel;
	}

	g_free(body);
	message_destroy(request, NULL);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return TRUE;
errorLabel:
	if (request)
		message_destroy(request, NULL);
	if (body)
		g_free(body);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return FALSE;
}


gboolean meta2_remote_content_commit_in_fd (int *fd, gint ms, GError **err, const container_id_t container_id, const gchar *content_path)
{
	struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, NULL },
		{ 0,0,NULL,NULL}
	};
	
	struct reply_sequence_data_s data = { NULL , 0 , codes };

	MESSAGE request = NULL;
	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	if (!message_create (&request, err))
	{
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}
	
	if (!meta2_remote_request_create (request, M2_OP_CONTENT_COMMIT, container_id, err))
	{
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	if (!meta2_remote_request_add_path (request, content_path, FALSE, 0, err))
	{
		GSETERROR(err, "Cannot add the content_path in the request (as a field)");
		goto errorLabel;
	}

	if (!metaXClient_reply_sequence_run (err, request, fd, ms, &data))
	{
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto errorLabel;
	}

	message_destroy(request, NULL);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	return TRUE;
errorLabel:
	if (request)
	{
		message_destroy(request, NULL);
	}
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	return FALSE;
}

gboolean meta2_remote_content_remove_in_fd (int *fd, gint ms, GError **err, const container_id_t container_id, const gchar *content_path)
{
	struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, NULL },
		{ 0, 0, NULL, NULL },
	};
	
	struct reply_sequence_data_s data = { NULL , 0 , codes };

	MESSAGE request = NULL;

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	if (!message_create (&request, err))
	{
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}
	
	if (!meta2_remote_request_create (request, M2_OP_CONTENT_REMOVE, container_id, err))
	{
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	if (!meta2_remote_request_add_path (request, content_path, FALSE, 0, err))
	{
		GSETERROR(err, "Cannot add the content_path in the request (as a field)");
		goto errorLabel;
	}

	if (!metaXClient_reply_sequence_run (err, request, fd, ms, &data))
	{
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto errorLabel;
	}

	message_destroy(request, NULL);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	return TRUE;
errorLabel:
	if (request)
	{
		message_destroy(request, NULL);
	}
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	return FALSE;
}


GSList* meta2_remote_content_spare_in_fd_full (int *fd, gint ms, GError **err, const container_id_t container_id,
		const gchar *content_path, gint count, gint distance, const gchar *notin, const gchar *broken)
{
	static struct code_handler_s codes [] = {
		{ 206, REPSEQ_BODYMANDATORY, chunk_info_concat, NULL },
		{ 200, REPSEQ_FINAL,         chunk_info_concat, NULL },
		{ 0,0,NULL,NULL}
	};

	GSList *result = NULL;
	struct reply_sequence_data_s data = { &result , 0 , codes };
	MESSAGE request = NULL;
	gchar wrkBuf[32];
	gsize wrkLen;

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	if (!message_create (&request, err))
	{
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}
	
	if (!meta2_remote_request_create (request, M2_OP_CONTENT_SPARE, container_id, err))
	{
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}

	if (!meta2_remote_request_add_path(request, content_path, FALSE, 0, err))
	{
		GSETERROR(err, "Cannot get spare chunks for content_path in the request (as a field)");
		goto errorLabel;
	}

	if (count > 0) {
		wrkLen = g_snprintf(wrkBuf, sizeof(wrkBuf) - 1, "%"G_GINT32_FORMAT, count);
		message_add_field(request, "COUNT", sizeof("COUNT") - 1, wrkBuf, wrkLen, err);
	}
	if (distance > 0) {
		wrkLen = g_snprintf(wrkBuf, sizeof(wrkBuf) - 1, "%"G_GINT32_FORMAT, distance);
		message_add_field(request, "DISTANCE", sizeof("DISTANCE") - 1, wrkBuf, wrkLen, err);
	}
	if (notin && *notin)
		message_add_field(request, "NOT-IN", sizeof("NOT-IN") - 1, notin, strlen(notin) + 1, err);
	if (broken && *broken)
		message_add_field(request, "BROKEN", sizeof("BROKEN") - 1, broken, strlen(broken) + 1, err);

	if (!metaXClient_reply_sequence_run (err, request, fd, ms, &data))
	{
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto errorLabel;
	}

	message_destroy(request, NULL);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return result;
errorLabel:
	if (request)
	{
		message_destroy(request, NULL);
	}

	if (result)
	{
		g_slist_foreach (result, chunk_info_gclean, NULL);
		g_slist_free (result);
	}

	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return NULL;
}

GSList* meta2_remote_content_spare_in_fd (int *fd, gint ms, GError **err, const container_id_t container_id, const gchar *content_path)
{
	return meta2_remote_content_spare_in_fd_full(fd, ms, err, container_id, content_path, 1, 1, NULL, NULL);
}


/* ------------------------------------------------------------------------- */


static gboolean
concat_names (GError **err, gpointer udata, gint code, guint8 *body, gsize bodySize)
{
	GSList **pResult = (GSList**) udata;
	GSList *decoded=NULL;

	(void)code;

	if (!pResult)
		return FALSE;
	/*unserialize the body*/
	decoded = meta2_maintenance_names_unmarshall_buffer( body, bodySize, err);
	if (!decoded)
		return FALSE;
	/*append the names*/
	*pResult = g_slist_concat(*pResult, decoded);
	return TRUE;
}


static gboolean
concat_contents (GError **err, gpointer udata, gint code, guint8 *body, gsize bodySize)
{
	struct meta2_raw_content_s **pContent=NULL, *decoded=NULL;

	(void)code;

	pContent = (struct meta2_raw_content_s**) udata;
	if (!pContent)
		return FALSE;
	/*unserialize the body*/
	decoded = meta2_maintenance_content_unmarshall_buffer(body, bodySize, err);
	if (!decoded)
		return FALSE;
	/*append the chunks*/
	if (!(*pContent)) {
		*pContent = decoded;
	} else {
		if ((*pContent)->raw_chunks) {
			(*pContent)->raw_chunks = g_slist_concat( (*pContent)->raw_chunks, decoded->raw_chunks);
		} else {
			(*pContent)->raw_chunks = decoded->raw_chunks;
		}
		decoded->raw_chunks = NULL;
		meta2_maintenance_destroy_content(decoded);
	}
	return TRUE;
}


static MESSAGE
meta2raw_create_request(
	GError **err, GByteArray *id,
	char *name, GByteArray *body, ...)
{
	va_list args;
	MESSAGE msg=NULL;

	message_create(&msg, err);

	if (id) {
		message_set_ID (msg, id->data, id->len, err);
	}

	if (body) {
		message_set_BODY (msg, body->data, body->len, err);
	}
	
	if (name) {
		message_set_NAME (msg, name, strlen(name), err);
	}

	va_start(args,body);
	for (;;) {
		char *k;
		GByteArray *v;
		k = va_arg(args,char*);
		if (!k) break;
		v = va_arg(args,GByteArray*);
		if (!v) break;
		message_add_field(msg, k, strlen(k), v->data, v->len, err);
	}
	va_end(args);
	
	return msg;
}


static struct meta2_raw_content_s*
meta2raw_remote_stat_content(struct metacnx_ctx_s *ctx, const container_id_t cid,
		const gchar *path, gsize path_len, gboolean check_flags, GError **err)
{
	static struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL|REPSEQ_BODYMANDATORY, concat_contents, NULL },
		{ 206, REPSEQ_BODYMANDATORY, concat_contents, NULL },
		{ 0,0,NULL,NULL}
	};
	MESSAGE request=NULL;
	GByteArray *gba_path=NULL, *gba_cid=NULL, *gba_check=NULL;
	struct meta2_raw_content_s *result=NULL;
	struct reply_sequence_data_s data = { &result , 0 , codes };

	if (!ctx || !cid || !path || !path_len) {
		GSETERROR(err,"invalid parameter");
		goto exit_label;
	}

	/*init the request*/
	CID_2_GBA(gba_cid,cid);
	if (!gba_cid) {
		GSETERROR(err,"memory allocation failure");
		goto error_alloc_cid;
	}
	STRING_2_GBA(gba_path, (const guint8*)path, path_len);
	if (!gba_path) {
		GSETERROR(err,"memory allocation failure");
		goto error_alloc_path;
	}
	STRING_2_GBA(gba_check, (guint8*)"1", 1);
	if (!gba_path) {
		GSETERROR(err,"memory allocation failure");
		goto error_alloc_check;
	}

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	/*inits a request with the proper flags*/
	request = meta2raw_create_request( err, ctx->id, NAME_MSGNAME_M2RAW_GETCHUNKS, NULL,
			NAME_MSGKEY_CONTAINERID, gba_cid,
			NAME_MSGKEY_CONTENTPATH, gba_path,
			NAME_HEADER_CHECKFLAGS, (check_flags ? gba_check : NULL),
			NULL);
	if (!request) {
		GSETERROR(err,"memory allocation failure");
		goto error_alloc_request;
	}

	/*send the request*/
	if (!metaXClient_reply_sequence_run_context (err, ctx, request, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto error_meta;
	}

	message_destroy(request, NULL);
	g_byte_array_free( gba_check, TRUE);
	g_byte_array_free( gba_path, TRUE);
	g_byte_array_free( gba_cid, TRUE);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return result;

error_meta:
	message_destroy(request, NULL);
error_alloc_request:
	g_byte_array_free(gba_check, TRUE);
error_alloc_check:
	g_byte_array_free(gba_path, TRUE);
error_alloc_path:
	g_byte_array_free(gba_cid, TRUE);
error_alloc_cid:
exit_label:
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return NULL;
}


gboolean
meta2raw_remote_update_chunks(
        struct metacnx_ctx_s *ctx, GError **err,
	        struct meta2_raw_content_s *content, gboolean allow_update, char *position_prefix)
{
	static struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, NULL },
		{ 0,0,NULL,NULL}
	};
	gboolean rc=FALSE;
	MESSAGE request=NULL;
	GByteArray *body;
	struct reply_sequence_data_s data = { NULL , 0 , codes };

	if (!ctx || !content) {
		GSETERROR(err,"invalid parameter");
		goto exit_label;
	}

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	/*init the request*/
	body = meta2_maintenance_marshall_content( content, err);
	if (!body) {
		GSETERROR(err,"failed to serialize the content structure");
		goto error_alloc_body;
	}

	request = meta2raw_create_request(err,ctx->id,NAME_MSGNAME_M2RAW_SETCHUNKS,body,NULL);
	if (!request) {
		GSETERROR(err,"memory allocation failure");
		goto error_alloc_request;
	}

	if (allow_update)
		message_add_field(request, "ALLOW_UPDATE", sizeof("ALLOW_UPDATE")-1, "1", 1, NULL);

	if (position_prefix)
		message_add_field(request, "POSITION_PREFIX", sizeof("POSITION_PREFIX") - 1,
				position_prefix, strlen(position_prefix), NULL);

	/*send the request*/
	if (!metaXClient_reply_sequence_run_context (err, ctx, request, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto error_meta;
	}

	rc = TRUE;
error_meta:
	message_destroy(request, NULL);
error_alloc_request:
	g_byte_array_free( body, TRUE);
error_alloc_body:
exit_label:
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return rc;
}


gboolean
meta2raw_remote_update_content(
        struct metacnx_ctx_s *ctx, GError **err,
	        struct meta2_raw_content_s *content, gboolean allow_update)
{
	static struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, NULL },
		{ 0,0,NULL,NULL}
	};
	gboolean rc=FALSE;
	MESSAGE request=NULL;
	GByteArray *body;
	struct reply_sequence_data_s data = { NULL , 0 , codes };

	if (!ctx || !content) {
		GSETERROR(err,"invalid parameter");
		goto exit_label;
	}

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	/*init the request*/
	body = meta2_maintenance_marshall_content( content, err);
	if (!body) {
		GSETERROR(err,"failed to serialize the content structure");
		goto error_alloc_body;
	}

	request = meta2raw_create_request(err,ctx->id,NAME_MSGNAME_M2RAW_SETCONTENT,body,NULL);
	if (!request) {
		GSETERROR(err,"memory allocation failure");
		goto error_alloc_request;
	}

	if (allow_update)
		message_add_field(request, "ALLOW_UPDATE", sizeof("ALLOW_UPDATE")-1, "1", 1, NULL);

	/*send the request*/
	if (!metaXClient_reply_sequence_run_context (err, ctx, request, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto error_meta;
	}


	rc = TRUE;
error_meta:
	message_destroy(request, NULL);
error_alloc_request:
	g_byte_array_free( body, TRUE);
error_alloc_body:
exit_label:
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return rc;
}


gboolean
meta2raw_remote_delete_chunks(
	struct metacnx_ctx_s *ctx, GError **err,
	struct meta2_raw_content_s *content)
{
	static struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, NULL },
		{ 0,0,NULL,NULL}
	};
	gboolean rc=FALSE;
	MESSAGE request=NULL;
	GByteArray *body;
	struct reply_sequence_data_s data = { NULL , 0 , codes };

	if (!ctx || !content) {
		GSETERROR(err,"invalid parameter");
		goto exit_label;
	}

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	/*init the request*/
	body = meta2_maintenance_marshall_content( content, err);
	if (!body) {
		GSETERROR(err,"memory allocation failure");
		goto error_alloc_body;
	}
	
	request = meta2raw_create_request(err,ctx->id,NAME_MSGNAME_M2RAW_DELCHUNKS,body,NULL);
	if (!request) {
		GSETERROR(err,"memory allocation failure");
		goto error_alloc_request;
	}

	/*send the request*/
	if (!metaXClient_reply_sequence_run_context (err, ctx, request, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto error_meta;
	}
	
	rc = TRUE;
error_meta:
	message_destroy(request, NULL);
error_alloc_request:
	g_byte_array_free( body, TRUE);
error_alloc_body:
exit_label:

	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	return rc;
}


gboolean
meta2raw_remote_delete_content(
	struct metacnx_ctx_s *ctx, GError **err,
	const container_id_t container_id, const gchar *path, gsize path_len)
{
	static struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, NULL },
		{ 0,0,NULL,NULL}
	};
	gboolean rc=FALSE;
	MESSAGE request=NULL;
	GByteArray *gba_path=NULL, *gba_cid=NULL;
	struct reply_sequence_data_s data = { NULL , 0 , codes };

	if (!ctx || !container_id || !path || !path_len) {
		GSETERROR(err,"invalid parameter");
		goto exit_label;
	}

	/*init the request*/

	CID_2_GBA(gba_cid,container_id);
	if (!gba_cid) {
		GSETERROR(err,"memory allocation failure");
		goto error_alloc_cid;
	}
		
	STRING_2_GBA(gba_path,(const guint8*)path,path_len);
	if (!gba_path) {
		GSETERROR(err,"memory allocation failure");
		goto error_alloc_path;
	}
	
	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	request = meta2raw_create_request( err, ctx->id, NAME_MSGNAME_M2RAW_DELCONTENT, NULL,
		NAME_MSGKEY_CONTAINERID, gba_cid,
		NAME_MSGKEY_CONTENTPATH, gba_path,
		NULL);

	if (!request) {
		GSETERROR(err,"memory allocation failure");
		goto error_alloc_request;
	}

	/*send the request*/
	if (!metaXClient_reply_sequence_run_context (err, ctx, request, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto error_meta;
	}
	
	rc = TRUE;
error_meta:
	message_destroy(request, NULL);
error_alloc_request:
	g_byte_array_free( gba_cid, TRUE);
error_alloc_cid:
	g_byte_array_free( gba_path, TRUE);
error_alloc_path:
exit_label:
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return rc;
}


struct meta2_raw_content_s*
meta2raw_remote_get_content_from_name(
	struct metacnx_ctx_s *ctx, GError **err,
	const container_id_t container_id, const gchar *path, gsize path_len)
{
	static struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL|REPSEQ_BODYMANDATORY, concat_contents, NULL },
		{ 0,0,NULL,NULL}
	};
	MESSAGE request=NULL;
	GByteArray *gba_path=NULL, *gba_cid=NULL;
	struct meta2_raw_content_s *result=NULL;
	struct reply_sequence_data_s data = { &result , 0 , codes };

	if (!ctx || !container_id || !path || !path_len) {
		GSETERROR(err,"invalid parameter");
		goto exit_label;
	}

	/*init the request*/

	CID_2_GBA(gba_cid,container_id);
	if (!gba_cid) {
		GSETERROR(err,"memory allocation failure");
		goto error_alloc_cid;
	}
		
	STRING_2_GBA(gba_path,(const guint8*)path,path_len);
	if (!gba_path) {
		GSETERROR(err,"memory allocation failure");
		goto error_alloc_path;
	}
	
	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	request = meta2raw_create_request( err, ctx->id, NAME_MSGNAME_M2RAW_GETCONTENTBYPATH, NULL,
		NAME_MSGKEY_CONTAINERID, gba_cid,
		NAME_MSGKEY_CONTENTPATH, gba_path,
		NULL);

	if (!request) {
		GSETERROR(err,"memory allocation failure");
		goto error_alloc_request;
	}

	/*send the request*/
	if (!metaXClient_reply_sequence_run_context (err, ctx, request, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto error_meta;
	}

	message_destroy(request, NULL);
	g_byte_array_free( gba_cid, TRUE);
	g_byte_array_free( gba_path, TRUE);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return result;

error_meta:
	message_destroy(request, NULL);
error_alloc_request:
	g_byte_array_free( gba_cid, TRUE);
error_alloc_cid:
	g_byte_array_free( gba_path, TRUE);
error_alloc_path:
exit_label:

	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return NULL;
}


struct meta2_raw_content_s*
meta2raw_remote_get_chunks(struct metacnx_ctx_s *ctx, GError **err,
		const container_id_t container_id, const char *path, gsize path_len)
{
	return meta2raw_remote_stat_content(ctx, container_id, path, path_len, FALSE, err);
}


GSList*
meta2raw_remote_get_contents_names(
	struct metacnx_ctx_s *ctx, GError **err,
	const container_id_t container_id)
{
	static struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL|REPSEQ_BODYMANDATORY, concat_names, NULL },
		{ 206, REPSEQ_BODYMANDATORY, concat_names, NULL },
		{ 0,0,NULL,NULL}
	};
	MESSAGE request=NULL;
	GByteArray *gba_cid;
	GSList *result=NULL;
	struct reply_sequence_data_s data = { &result , 0 , codes };

	if (!ctx || !container_id) {
		GSETERROR(err,"invalid parameter");
		goto exit_label;
	}

	/*init the request*/
	CID_2_GBA(gba_cid,container_id);
	if (!gba_cid) {
		GSETERROR(err,"memory allocation failure");
		goto error_alloc_cid;
	}
		
	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	
	request = meta2raw_create_request( err, ctx->id, NAME_MSGNAME_M2RAW_GETCONTENTS, NULL,
		NAME_MSGKEY_CONTAINERID, gba_cid,
		NULL);
	if (!request) {
		GSETERROR(err,"memory allocation failure");
		goto error_alloc_request;
	}

	/*send the request*/
	if (!metaXClient_reply_sequence_run_context (err, ctx, request, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto error_meta;
	}

	message_destroy(request, NULL);
	g_byte_array_free( gba_cid, TRUE);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return result;

error_meta:
	message_destroy(request, NULL);
error_alloc_request:
	g_byte_array_free( gba_cid, TRUE);
error_alloc_cid:
exit_label:

	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return NULL;
}


struct meta2_raw_content_s*
meta2raw_remote_get_content_from_chunkid(
	struct metacnx_ctx_s *ctx, GError **err,
	const container_id_t container_id, const chunk_id_t *id)
{
	static struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL|REPSEQ_BODYMANDATORY, concat_contents, NULL },
		{ 0,0,NULL,NULL}
	};
	MESSAGE request=NULL;
	GByteArray *gba_id, *gba_cid;
	struct meta2_raw_content_s *result=NULL;
	struct reply_sequence_data_s data = { &result , 0 , codes };

	if (!ctx || !container_id || !id) {
		GSETERROR(err,"invalid parameter");
		goto exit_label;
	}

	/*init the request*/

	CID_2_GBA(gba_cid,container_id);
	if (!gba_cid) {
		GSETERROR(err,"memory allocation failure");
		goto error_alloc_cid;
	}
	
	gba_id = chunk_id_marshall( id, err);
	if (!gba_id) {
		GSETERROR(err,"Cannot serialiaze the chunk_id_t");
		goto error_alloc_id;
	}
	
	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	request = meta2raw_create_request( err, ctx->id, NAME_MSGNAME_M2RAW_GETCONTENTBYCHUNK, NULL,
		NAME_MSGKEY_CONTAINERID, gba_cid,
		NAME_MSGKEY_CHUNKID, gba_id,
		NULL);

	if (!request) {
		GSETERROR(err,"memory allocation failure");
		goto error_alloc_request;
	}

	/*send the request*/
	if (!metaXClient_reply_sequence_run_context (err, ctx, request, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto error_meta;
	}

	message_destroy(request, NULL);
	g_byte_array_free( gba_cid, TRUE);
	g_byte_array_free( gba_id, TRUE);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return result;

error_meta:
	message_destroy(request, NULL);
error_alloc_request:
	g_byte_array_free( gba_id, TRUE);
error_alloc_id:
	g_byte_array_free( gba_cid, TRUE);
error_alloc_cid:
exit_label:
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return NULL;
}


gboolean
meta2raw_remote_mark_container_repaired_in_fd (int *fd, gint ms, GError **err, const container_id_t container_id)
{
	static struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, NULL },
		{ 0,0,NULL,NULL}
	};
	MESSAGE request=NULL;
	GByteArray *gba_cid;
	struct reply_sequence_data_s data = { NULL , 0 , codes };

	if (!container_id) {
		GSETERROR(err,"invalid parameter");
		goto exit_label;
	}

	/*init the request*/

	CID_2_GBA(gba_cid,container_id);
	if (!gba_cid) {
		GSETERROR(err,"memory allocation failure");
		goto error_alloc_cid;
	}
	
	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	request = meta2raw_create_request( err, NULL, NAME_MSGNAME_M2RAW_MARK_REPAIRED, NULL,
		NAME_MSGKEY_CONTAINERID, gba_cid,
		NULL);

	if (!request) {
		GSETERROR(err,"memory allocation failure");
		goto error_alloc_request;
	}

	/*send the request*/
	if (!metaXClient_reply_sequence_run (err, request, fd, ms, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto error_meta;
	}

	message_destroy(request, NULL);
	g_byte_array_free( gba_cid, TRUE);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return TRUE;

error_meta:
	message_destroy(request, NULL);
error_alloc_request:
	g_byte_array_free( gba_cid, TRUE);
error_alloc_cid:
exit_label:

	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return FALSE;
}


gboolean
meta2raw_remote_mark_container_repaired (addr_info_t *ai, gint ms, GError **err, const container_id_t container_id)
{
	static struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, NULL },
		{ 0,0,NULL,NULL}
	};
	MESSAGE request=NULL;
	GByteArray *gba_cid;
	struct reply_sequence_data_s data = { NULL , 0 , codes };

	if (!container_id) {
		GSETERROR(err,"invalid parameter");
		goto exit_label;
	}

	/*init the request*/

	CID_2_GBA(gba_cid,container_id);
	if (!gba_cid) {
		GSETERROR(err,"memory allocation failure");
		goto error_alloc_cid;
	}
	
	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	request = meta2raw_create_request( err, NULL, NAME_MSGNAME_M2RAW_MARK_REPAIRED, NULL,
		NAME_MSGKEY_CONTAINERID, gba_cid,
		NULL);

	if (!request) {
		GSETERROR(err,"memory allocation failure");
		goto error_alloc_request;
	}

	/*send the request*/
	if (!metaXClient_reply_sequence_run_from_addrinfo (err, request, ai, ms, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto error_meta;
	}

	message_destroy(request, NULL);
	g_byte_array_free( gba_cid, TRUE);

	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	return TRUE;

error_meta:
	message_destroy(request, NULL);
error_alloc_request:
	g_byte_array_free( gba_cid, TRUE);
error_alloc_cid:
exit_label:

	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return TRUE;
}


static gboolean
add_header( GHashTable *ht, const char *k, MESSAGE rep, GError **err )
{
	void *field=NULL;
	gsize field_len=0;
	gsize k_len;
	gchar *field_copy, *k_copy;

	k_len = strlen( k );
	if (0 < message_get_field( rep, k, k_len, &field, &field_len, err)) {
		field_copy = g_strndup(field, MIN(field_len,2048));
		k_copy = g_strdup(k);
		if (!field_copy || !k_copy) {
			if (k_copy) g_free(k_copy);
			if (field_copy) g_free(field_copy);
			GSETERROR(err,"Memory allocation failure");
		} else {
			g_hash_table_insert( ht, k_copy, field_copy );
		}
		return TRUE;
	}
	return FALSE;
}

static gboolean
manage_headers( GError **err, gpointer udata, gint code, MESSAGE rep )
{
	GHashTable *ht;

	(void)code;
	ht = *((GHashTable**)udata);
	return add_header(ht, NAME_HEADER_NAMESPACE, rep, err)
		&& add_header(ht, NAME_HEADER_CONFIGURATION, rep, err);
}

GHashTable*
meta2_remote_info ( struct metacnx_ctx_s *ctx, GError **err )
{
	static struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, manage_headers },
		{ 0,0,NULL,NULL}
	};
	MESSAGE request=NULL;
	GHashTable *ht = NULL;
	struct reply_sequence_data_s data = { &ht , 0 , codes };

	ht = g_hash_table_new_full( g_str_hash, g_str_equal, g_free, g_free );
	if (!ht) {
		GSETERROR(err,"Memory allocation failure");
		return NULL;
	}

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);	
	
	request = meta2raw_create_request( err, ctx->id, NAME_MSGNAME_M2_INFO, NULL, NULL);
	if (!request) {
		GSETERROR(err,"Memory allcation failure");
		goto error_request;
	}

	/*send the request*/
	if (!metaXClient_reply_sequence_run_context (err, ctx, request, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto error_meta;
	}

	message_destroy(request, NULL);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return ht;

error_request:
	g_hash_table_destroy( ht );
error_meta:
	message_destroy(request, NULL);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return NULL;
}


GHashTable*
meta2_remote_info_with_fd(int fd, gint ms, GError **err)
{
	struct metacnx_ctx_s ctx;

	memset( &ctx, 0x00, sizeof(ctx));
	ctx.fd = fd;
	ctx.timeout.cnx = ms;
	ctx.timeout.req = ms;

	return 	meta2_remote_info( &ctx, err);
}

GHashTable* meta2_remote_info_with_addr(addr_info_t *m2_addr, gint ms, GError **err)
{
	struct metacnx_ctx_s ctx;

	memset( &ctx, 0x00, sizeof(ctx));
	ctx.fd = -1;
	ctx.timeout.cnx = ms;
	ctx.timeout.req = ms;
	memcpy( &(ctx.addr), m2_addr, sizeof(addr_info_t));

	return 	meta2_remote_info( &ctx, err);
}

static gboolean
manage_body( GError **err, gpointer udata, gint code, guint8 *body, gsize bodySize )
{
	GHashTable *ht;
	GSList *le, *local_names = NULL;
	(void)code;
	ht = *((GHashTable**)udata);
	local_names = meta2_maintenance_names_unmarshall_buffer( body, bodySize, err);
	if (!local_names) {
		if (err && *err) {
			GSETERROR(err,"Failed to unpack the reply body");
			return FALSE;
		} else return TRUE;
	}
	for (le=local_names; le ;le=g_slist_next(le)) {
		gchar **tokens = NULL;
		tokens = g_strsplit(le->data,"=",2);
		if (!tokens) {
			GSETERROR(err,"Invalid server response format");
			goto error_format;
		}
		if (g_strv_length(tokens)<2) {
			GSETERROR(err,"Invalid server response format");
			goto error_format;
		}
		DEBUG("Found key=[%s] value=[%s]", tokens[0], tokens[1]);
		g_hash_table_insert( ht, tokens[0], tokens[1] );
		g_free( tokens );
	}
	g_slist_foreach( local_names, g_free1, NULL );
	g_slist_free( local_names );
	return TRUE;
error_format:
	g_slist_foreach( local_names, g_free1, NULL );
	g_slist_free( local_names );
	return FALSE;
}


GHashTable* meta2raw_remote_get_admin_entries(
	struct metacnx_ctx_s *ctx, GError **err,
	const container_id_t container_id)
{
	static struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL,         manage_body, NULL },
		{ 206, REPSEQ_BODYMANDATORY, manage_body, NULL },
		{ 0,0,NULL,NULL}
	};
	GHashTable *ht = NULL;
	GByteArray *gba_cid = NULL;
	MESSAGE request=NULL;
	struct reply_sequence_data_s data = { &ht, 0 , codes };

	if (!ctx || !container_id) {
		GSETERROR(err,"Invalid parameter");
		return NULL;
	}

	CID_2_GBA(gba_cid,(container_id));
	if (!gba_cid) {
		GSETERROR(err,"memory allocation failure");
		return NULL;
	}

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	request = meta2raw_create_request( err, ctx->id, NAME_MSGNAME_M2ADMIN_GETALL, NULL,
		NAME_MSGKEY_CONTAINERID, gba_cid,
		NULL);
	if (!request) {
		GSETERROR(err,"Memory allcation failure");
		goto error_request;
	}

	/*send the request*/
	ht = g_hash_table_new_full( g_str_hash, g_str_equal, g_free, g_free );
	if (!ht) {
		message_destroy(request, NULL);
		GSETERROR(err,"Memory allocation failure");
		gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
		return NULL;
	}

	if (!metaXClient_reply_sequence_run_context (err, ctx, request, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto error_meta;
	}

	message_destroy(request, NULL);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return ht;
error_request:
	g_hash_table_destroy( ht );
error_meta:
	message_destroy(request, NULL);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return NULL;
}

gboolean
meta2raw_remote_set_admin_entry(
        struct metacnx_ctx_s *ctx, GError **error,
        const container_id_t container_id, const gchar *key,
        void *value, gsize value_size)
{
	static struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, NULL },
		{ 0, 0, NULL, NULL }
	};
	MESSAGE request = NULL;
	GByteArray *gba_cid = NULL, *gba_admin_key = NULL, *gba_admin_value = NULL;
	struct reply_sequence_data_s data = { NULL, 0, codes };

	if (!ctx || !container_id) {
		GSETERROR(error, "Invalid parameter");
		return FALSE;
	}

	CID_2_GBA(gba_cid,(container_id));
	if (!gba_cid) {
		GSETERROR(error, "memory allocation failure");
		return FALSE;
	}

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	gba_admin_key = g_byte_array_append(g_byte_array_new(), (const guint8*)key, strlen(key) + 1);
	gba_admin_value = g_byte_array_append(g_byte_array_new(), (const guint8*)value, value_size);
	request = meta2raw_create_request(error, ctx->id, NAME_MSGNAME_M2ADMIN_SETONE, NULL,
		NAME_MSGKEY_CONTAINERID, gba_cid,
		NAME_HEADER_ADMIN_KEY, gba_admin_key,
		NAME_HEADER_ADMIN_VALUE, gba_admin_value,
		NULL);
	if (!request) {
		GSETERROR(error, "Memory allcation failure");
		goto error_request;
	}

	/*send the request*/
	if (!metaXClient_reply_sequence_run_context (error, ctx, request, &data)) {
		GSETERROR(error, "Cannot execute the query and receive all the responses");
		goto error_meta;
	}

	g_byte_array_free(gba_cid, TRUE);
	g_byte_array_free(gba_admin_key, TRUE);
	g_byte_array_free(gba_admin_value, TRUE);
	message_destroy(request, NULL);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	return TRUE;

error_request:
error_meta:
	g_byte_array_free(gba_cid, TRUE);
	g_byte_array_free(gba_admin_key, TRUE);
	g_byte_array_free(gba_admin_value, TRUE);
	message_destroy(request, NULL);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return FALSE;
}

GSList *
meta2_remote_content_append(struct metacnx_ctx_s *ctx, GError ** err, const container_id_t container_id,
    const gchar * content_path, content_length_t content_length)
{
	return meta2_remote_content_append_v2(ctx, err, NULL, container_id, content_path, content_length);
}

GSList *
meta2_remote_content_append_v2(struct metacnx_ctx_s *ctx, GError ** err, gchar *virtual_namespace, 
	const container_id_t container_id, const gchar * content_path, content_length_t content_length)
{
	static struct code_handler_s codes[] = {
		{206, REPSEQ_BODYMANDATORY, chunk_info_concat, NULL},
		{200, REPSEQ_FINAL, chunk_info_concat, NULL},
		{0, 0, NULL, NULL}
	};
	MESSAGE request = NULL;
	GSList *result = NULL;
	struct reply_sequence_data_s data = { &result, 0, codes };

	if (!ctx || !container_id || !content_path || !content_length) {
		GSETERROR(err, "Invalid parameter");
		goto errorLabel;
	}
	
	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);	

	if (!message_create(&request, err)) {
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}
	if (!meta2_remote_request_create(request, M2_OP_CONTENT_APPEND, container_id, err)) {
		GSETERROR(err, "Cannot init the message as a simple metaX request");
		goto errorLabel;
	}
	if (!meta2_remote_request_add_path(request, content_path, TRUE, content_length, err)) {
		GSETERROR(err, "Cannot add the content_path in the request (as a field)");
		goto errorLabel;
	}

	if(virtual_namespace) {
                if(meta2_remote_request_add_vns(request, virtual_namespace, err) != 1) {
                        GSETERROR(err, "Cannot add the virtual namespace as a field");
                        goto errorLabel;
                }
        }

	if (!metaXClient_reply_sequence_run_context(err, ctx, request, &data)) {
		GSETERROR(err, "Cannot execute the query and receive all the responses");
		goto errorLabel;
	}

	message_destroy(request, NULL);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return result;
      errorLabel:
	if (request)
		message_destroy(request, NULL);
	if (result)
		g_slist_foreach(result, chunk_info_gclean, NULL);
	g_slist_free(result);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return NULL;
}

struct meta2_raw_content_s*
meta2_remote_stat_content(struct metacnx_ctx_s *cnx, const container_id_t container_id,
	const gchar *path, gsize path_len, GError **err)
{
	return meta2raw_remote_stat_content(cnx, container_id, path, path_len, TRUE, err);
}

static MESSAGE
_build_request(GError **err, GByteArray *id, char *name)
{
	MESSAGE msg=NULL;
	message_create(&msg, err);
	if (id)
		message_set_ID (msg, id->data, id->len, err);
	if (name)
		message_set_NAME (msg, name, strlen(name), err);
	return msg;
}

status_t
meta2_remote_touch_content(struct metacnx_ctx_s *ctx,
		const container_id_t var_0, const gchar* var_1, GError **err)
{
	static struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL,         NULL, NULL },
		{ 0,0,NULL,NULL}
	};
	struct reply_sequence_data_s data = { NULL , 0 , codes };
	MESSAGE request;
	status_t status = 0;

	if (!ctx || !var_0 || !var_1) {
		GSETERROR(err,"Invalid parameter ( var_0=%p var_1=%p)"
				, (void*)var_0, (void*)var_1);
		return 0;
	}

	request = _build_request( err, ctx->id, "REQ_M2RAW_TOUCH_CONTENT");
	if (!request) {
		GSETERROR(err,"Memory allocation failure");
		return 0;
	}

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	/*prepare the request, fill all the fields*/
	do {
		int rc;
		GByteArray *gba;

		gba = g_byte_array_append(g_byte_array_new(), (guint8*)var_0, sizeof(container_id_t));

		if (!gba) {
			GSETERROR(err,"Serialization error");
			goto error_label;
		}
		rc = message_add_field(request, "CONTAINER_ID", sizeof("CONTAINER_ID")-1, gba->data, gba->len, err);
		g_byte_array_free(gba, TRUE);

		if (!rc) {
			GSETERROR(err,"Request configuration failure");
			goto error_label;
		}
	} while (0);

	do {
		int rc;
		GByteArray *gba;

		gba = g_byte_array_append(g_byte_array_new(), (guint8*)var_1, strlen(var_1));

		if (!gba) {
			GSETERROR(err,"Serialization error");
			goto error_label;
		}
		rc = message_add_field(request, "CONTENT_PATH", sizeof("CONTENT_PATH")-1, gba->data, gba->len, err);
		g_byte_array_free(gba, TRUE);

		if (!rc) {
			GSETERROR(err,"Request configuration failure");
			goto error_label;
		}
	} while (0);


	/*Now send the request*/
	if (!metaXClient_reply_sequence_run_context (err, ctx, request, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto error_label;
	}

	status = 1;
error_label:
	message_destroy(request,NULL);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return status;
}

status_t
meta2_remote_touch_container(struct metacnx_ctx_s *ctx, const container_id_t var_0, GError **err)
{
	return meta2_remote_touch_container_ex(ctx, var_0, 0, err);
}


status_t meta2_remote_touch_container_ex(struct metacnx_ctx_s *ctx, const container_id_t var_0,
    unsigned int flags, GError **err)
{
	static struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL,         NULL, NULL },
		{ 0,0,NULL,NULL}
	};

	struct reply_sequence_data_s data = { NULL , 0 , codes };
	MESSAGE request;
	status_t status = 0;

	if (!ctx || !var_0) {
		GSETERROR(err,"Invalid parameter ( var_0=%p)" , (void*)var_0);
		return 0;
	}

	request = _build_request( err, ctx->id, "REQ_M2RAW_TOUCH_CONTAINER");
	if (!request) {
		GSETERROR(err,"Memory allocation failure");
		return 0;
	}

	gscstat_tags_start(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);

	/*prepare the request, fill all the fields*/
	do {
		int rc;
		GByteArray *gba;

		gba = g_byte_array_append(g_byte_array_new(), (guint8*)var_0, sizeof(container_id_t));

		if (!gba) {
			GSETERROR(err,"Serialization error");
			goto error_label;
		}
		rc = message_add_field(request, "CONTAINER_ID", sizeof("CONTAINER_ID")-1, gba->data, gba->len, err);
		g_byte_array_free(gba, TRUE);

		if (!rc) {
			GSETERROR(err,"Request configuration failure");
			goto error_label;
		}
	} while (0);

	/*add flags...*/
	if (flags) {
		int rc;
		flags = g_htonl(flags);
	    rc = message_add_field(request, "FLAGS", sizeof("FLAGS")-1,
			            &flags, sizeof(flags), NULL);
		if (!rc) {
        	GSETERROR(err,"Cannot execute the update container size");
			goto error_label;
		}
	}

	/*Now send the request*/
	if (!metaXClient_reply_sequence_run_context (err, ctx, request, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto error_label;
	}

	status = 1;
error_label:
	message_destroy(request,NULL);
	gscstat_tags_end(GSCSTAT_SERVICE_META2, GSCSTAT_TAGS_REQPROCTIME);
	return status;
}



