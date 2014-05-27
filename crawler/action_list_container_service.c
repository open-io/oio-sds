#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "grid.crawler.action_list_container"
#endif //G_LOG_DOMAIN

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include <sqlite3.h>

#include <glib.h>
#include <gmodule.h>
#include <dbus/dbus.h>

#include <grid_client.h>

#include <metautils/lib/metautils.h>
#include <meta2v2/autogen.h>
#include <meta2v2/generic.h>
#include <meta1v2/meta1_remote.h>
#include <grid_client.h>

#include "lib/action_common.h"

#include "listener/listener_remote.h"



//==============================================================================
// constantes
//==============================================================================
#define ALCS_CONTENTNAME_MAX_BYTES      150


//==============================================================================
// structure
//==============================================================================
/**
 * internal structur about statistique to send to listener
 */
struct _ActionListCtStatData_s {

	gchar contentName[ALCS_CONTENTNAME_MAX_BYTES];

	// statistique: META1 global errors...
	int m1_nbBadBddFile;   // ...bdd not opened/not good table, not good field/able
	int m1_nbBadPrefix;    // ...prefix not good format/null, ....
	int m1_nbErrReq;       // ...request meta1 failed
	int m1_notMaster;      // ...meta1 not Matser, dont used

	// statistique: META1 global nb...
	int m1_nbPrefixTotal;   // ...nb prefix total managed
	int m1_nbContainerTotal;// ...nb container total scanned on nbPrefixTotal prefix

	//  statistique: SVC...
	int svc_nbPrefix;         // ...nb prefix Master for this services
	int svc_nbContainerTotal; // ...nb container total  / prefix / service
	int svc_nbErrReq;         // ...request meta1 failed / prefix / service
};




/**
 * save data before save on grid
 */
#define ALCS_SAVEBUF_MAX_BYTES    102400      // 100Ko
typedef struct {
	gchar* contentName; 
	gchar* namespace;
	gboolean bExists;

	gchar data[ALCS_SAVEBUF_MAX_BYTES];
	int   datalen;
}TAlcsSharedMem;



static GSList* g_alcs_listsm = NULL;           // TAlcsSharedMem item





//==============================================================================
// variables
//==============================================================================
//configuration
static gchar*       g_cfg_action_name;
static gchar*       g_cfg_command_name;
static gchar*       g_cfg_namespace_cmd_opt_name;
static gchar*       g_cfg_displayListContainer_cmd_opt_name;
static gchar*       g_cfg_listenerUrl_cmd_opt_name;
static gchar*       g_cfg_crawlerID_cmd_opt_name;
static gchar*       g_cfg_dryrun_cmd_opt_name;
static const gchar* g_cfg_occur_type_string;

// runnine temp data
static TCrawlerBus*    g_conn;
static void*           g_zmq_ctx;
static void*		   g_zmq_sock;

// data
static int       g_service_pid;
static gchar     g_service_name[SERVICENAME_MAX_BYTES];
static gboolean  g_stop_thread;
static int       g_idmsgzmq  = 0;
static gchar*    g_crawlerID = NULL;
static gboolean  g_dryrun_mode = FALSE;
static gs_grid_storage_t* g_hc = NULL;

static char*    g_dbusdaemon_address = NULL;
static GMainLoop *g_main_loop = NULL;

///////////////////////////////////////////////////////
#define ALCS_SETERR(/*(GError **)*/err, msg,...) g_set_error(err, g_quark_from_string(g_cfg_action_name), -1, msg, __VA_ARGS__)

#define ALCS_PRINTF(...) /*fprintf(stderr,__VA_ARGS__); fprintf(stderr, "\n"); */
#define ALCS_ERROR(...) { GRID_ERROR(__VA_ARGS__);  ALCS_PRINTF(__VA_ARGS__); }
#define ALCS_WARN(...)  { GRID_WARN(__VA_ARGS__);   ALCS_PRINTF(__VA_ARGS__); }
#define ALCS_INFO(...)  { GRID_INFO(__VA_ARGS__);   ALCS_PRINTF(__VA_ARGS__); }
#define ALCS_TRACE(...) { GRID_TRACE(__VA_ARGS__);  ALCS_PRINTF(__VA_ARGS__); }
#define ALCS_DEBUG(...) { GRID_DEBUG(__VA_ARGS__);  ALCS_PRINTF(__VA_ARGS__); }




// function: meta1 request
//==============================================================================
/**
 * \brief prepare and convert data
 */
	static GError*
alcs_meta1_PrepareDataIn(const gchar* pMeta1_url_In, addr_info_t *pM1addr_Out,
		const gchar* pPrefixCt_In, container_id_t *pPrefix_Out)
{
	GError* err = NULL;

	if (pPrefixCt_In != NULL) {
		//conv prefix
		if (!hex2bin(pPrefixCt_In, *pPrefix_Out, 
					MIN(strlen(pPrefixCt_In)/2,
						sizeof(container_id_t)), &err)) {
			ALCS_WARN("Invalid hex prefix [%s] : %s", pPrefixCt_In, err->message);
			return err;
		}
	}

	if (pMeta1_url_In != NULL) {
		// update url format
		memset(pM1addr_Out, 0, sizeof(addr_info_t));
		if (!l4_address_init_with_url(pM1addr_Out, pMeta1_url_In, &err)) {
			ALCS_WARN("Invalid M1 URL[%s] : %s", pMeta1_url_In, err->message);
			return err;
		}
	}

	return NULL;
}


/**
 * \brief get list container by service or not
 *
 *  bAllelseByService: 	=TRUE all container, 
 * 				= FALSE all container / service [srvtype|srvurl]
 */
	static GError*
alcs_meta1_GetListContainer(gchar* namespace, addr_info_t *m1addr,
		container_id_t *prefix,	gboolean bAllelseByService,
		gchar* srvtype, gchar* srvurl, GByteArray **result)
{
	GError* err = NULL;

	if (result == NULL)
		return NULL;

	if (bAllelseByService == TRUE) 
		err = meta1v2_remote_list_references(m1addr, namespace, *prefix, result);

	else 
		err = meta1v2_remote_list_references_by_service(m1addr, namespace,
				*prefix, srvtype, srvurl, result);


	if (err) {
		ALCS_WARN("M1V2 error : (%d) %s", err->code, err->message);
		metautils_gba_unref(result);
		return err;
	}

	if ((*result) != NULL) {
		if((*result)->len > 0) {
			// data present: containers...
			g_byte_array_append(*result, (guint8*)"", 1);
		}
	}

	return err;
}



//return list service / cid
static gchar** alcs_meta1_GetListServices(gchar* namespace, addr_info_t *m1addr,
        container_id_t *cid, GError** err)
{
    gchar** result = meta1v2_remote_list_services(m1addr, err, namespace, *cid);
	if (err && *err) {
		ALCS_WARN("M1V2 error : (%d) %s", (*err)->code, (*err)->message);
		g_free(result);
		return NULL;
	}	

    return result;
}





//==============================================================================
//// function: GRIDCLIENT
////==============================================================================
/*
 *  *  * content to load
 *   *   *
 *    *    * */
typedef struct {
	int    content_size;  // taille de stream en Ko
	gchar *stream;       // content
}TALCSStreams;


typedef struct {
	gboolean      bOpened;
	TALCSStreams* pStream;
	int           position;
} TALCSStreamHandle;


	static gs_grid_storage_t*
alcs_gridclient_init(GError ** g_err, gchar* namespace)
{
	gs_grid_storage_t* hc = NULL;
	gs_error_t *err = NULL;

	hc = gs_grid_storage_init((char*)namespace, &err);
	if (hc == NULL) {
		if (g_err != NULL)
			ALCS_SETERR(g_err, "Failed to get grid connection to ns [%s] : %s",
				namespace, gs_error_get_message(err)); 
	}	

	return hc;
}


	static GError*
alcs_gridclient_free(gs_grid_storage_t** hc)
{
	if (*hc == NULL)
		return NULL;

	gs_grid_storage_free(*hc);
	*hc = NULL;
	return NULL;
}



/**
 * create a container on a specific namespace
 *
 */
	static GError*
alcs_gridclient_container_Create(gs_grid_storage_t* hc, gchar* namespace, gchar* sContainer)
{
	gs_error_t     *err   = NULL;
	gs_container_t *c     = NULL;
	GError         *g_err = NULL;
	gchar* stgpol = NULL;

	//ALCS_DEBUG("CREATE container [%s/%s]", namespace, sContainer);

	if (hc == NULL) {
		ALCS_SETERR(&g_err, "%s: grid don't init", __FUNCTION__);
		return g_err;
	}

	//#ifndef RELEASE_18
	//    c = gs_get_storage_container (pHcp->hc, sContainer, 0, &err);
	//#else
	c = gs_get_storage_container (hc, sContainer, stgpol, 0, &err);
	//#endif
	if (c == NULL) {
		// container not found: not an error
		if (err != NULL) gs_error_free(err);
		err = NULL;


		if (g_dryrun_mode == FALSE) {	
			// crezate the container
			c = gs_get_storage_container (hc, sContainer, stgpol, 1, &err);
			if (c != NULL) {
				ALCS_DEBUG("CREATE Container [%s] created in namespace [%s].", sContainer, namespace);                        
			} else {
				// dryrun mode
				DRYRUN_GRID("CREATE Container [%s] created in namespace [%s].\n", sContainer, namespace);

			}

		} else {
			if (err) {
				ALCS_SETERR(&g_err, "Cannot create container: (%d) %s", err->code, err->msg);
			} else
				ALCS_SETERR(&g_err, "Cannot create container: %s", "Unknown Error");
		}


	} else {
		ALCS_WARN("Container [%s] exists", sContainer);                
	}

	if (err != NULL) gs_error_free(err);
	if (c != NULL)   gs_container_free(c);

	return g_err;
}


static ssize_t _alcs_gridclient_content_feed_from_stream(void *uData, char *b, size_t bSize)
{
	ssize_t nbRead = 0;
	int i;
	TALCSStreamHandle* pHandleStream = NULL;
	int nbBytesTotal = 0;

	pHandleStream = (TALCSStreamHandle*) uData;
	if (pHandleStream == NULL) {
		ALCS_WARN("%s: pHandleStream == NULL: no data to write", __FUNCTION__);
		return 0;
	}

	if (!b || !bSize) {
		ALCS_WARN("%s: !b || !bSize", __FUNCTION__);
		return 0;
	}

	nbBytesTotal = pHandleStream->pStream->content_size;
	ALCS_DEBUG("%s: pHandleStream->position= %d / %d - contentSize=%d", __FUNCTION__, pHandleStream->position, (int) bSize, nbBytesTotal);

	if (nbBytesTotal <= pHandleStream->position) {
		nbRead = 0;

	} else {
		TALCSStreams* pStream = NULL;
		char* ptr;

		pStream = pHandleStream->pStream;
		nbRead = bSize;

		if ((pHandleStream->position + nbRead) >= (nbBytesTotal))
			nbRead = nbBytesTotal - pHandleStream->position;

		ptr = (char*) &(pStream->stream[0]);
		ALCS_DEBUG("%s: pHandleStream->position=%d, nbRead=%d\n", __FUNCTION__, pHandleStream->position, (int) nbRead);
		for(i=0;i<nbRead;i++) {
			b[i] = ptr[i];
		}

		pHandleStream->position += nbRead;
	}


	return nbRead;
}



	static GError*
alcs_gridclient_content_PUTorAPPEND(gs_grid_storage_t* hc, gchar* namespace, gchar* sContainer, 
		gchar* sContent, gchar* buf, int64_t len, gboolean bAppendUsed)
{
	GError         *g_err = NULL;
	gs_error_t     *err   = NULL;
	gs_container_t *c     = NULL;
	gchar* stgpol = NULL;
	TALCSStreams* pStream;
	TALCSStreamHandle* pStream_handle = NULL;


	if (buf == NULL ) {
		ALCS_DEBUG("%s: buffer = null", __FUNCTION__);
		return 0;
	}

	// file size...
	pStream = ( TALCSStreams*) g_malloc0(sizeof(TALCSStreams));
	if (pStream == NULL) {
		ALCS_SETERR(&g_err, "%s(%d): %s (errno=%d)", __FUNCTION__, __LINE__,
				"Failed to allocate memory", errno);
		return g_err;
	}
	pStream->content_size = len;
	pStream->stream       = buf;
	ALCS_DEBUG("%s content [%s/%s/%s](%dB)", 
			((bAppendUsed == FALSE)?"PUT":"APPEND"),
			namespace, sContainer, sContent, pStream->content_size);

	pStream_handle = (TALCSStreamHandle*) g_malloc(sizeof(TALCSStreamHandle));
	if (pStream_handle ==NULL) {
		ALCS_SETERR(&g_err, "%s(%d): %s (errno=%d)", __FUNCTION__, __LINE__,
				"Failed to allocate memory", errno);
		g_free(pStream);
		return g_err;
	}

	// file size...

	c = gs_get_storage_container (hc, sContainer, stgpol, 0, &err);
	if (c) {
		// no error
		if (err != NULL) gs_error_free(err);
		err = NULL;


		pStream_handle->bOpened      = TRUE;
		pStream_handle->pStream      = pStream;
		pStream_handle->position     = 0;


		gs_status_t s = 0;

		if (g_dryrun_mode == FALSE) {
			if (bAppendUsed == FALSE) {
				ALCS_DEBUG("%s: PUT command", __FUNCTION__);
				// don't exists, PUT it
				s = gs_upload_content_v2(c, sContent, pStream->content_size /*s.st_size*/, 
						_alcs_gridclient_content_feed_from_stream, pStream_handle/*&in*/, stgpol, NULL, &err);
				//
			} else {
				ALCS_DEBUG("%s: APPEND command", __FUNCTION__);
				// exists: APPEND it
				s = gs_append_content (c, sContent, pStream->content_size,
						_alcs_gridclient_content_feed_from_stream, pStream_handle, &err);
			}
		} else {
			//dryrun mode
			s = 1;
			DRYRUN_GRID("%s content [%s/%s/%s](%dB)\n", ((bAppendUsed == FALSE)?"PUT":"APPEND"), 
					namespace, sContainer, sContent, pStream->content_size);
		}

		if (!s) {
			if (err) {
				ALCS_SETERR(&g_err, "Cannot %s content: %s/%s/%s (%d) %s",
						((bAppendUsed == FALSE)?"put":"append"),
						namespace, sContainer, sContent, err->code, err->msg);
			} else {
				ALCS_SETERR(&g_err, "Cannot %s content: %s/%s/%s () %s", 
						((bAppendUsed == FALSE)?"put":"append"),
						namespace, sContainer, sContent, "Unknown error");
			}
		} else {
			ALCS_DEBUG("%s content uloaded [%s/%s/%s] from [%do stream]",
					((bAppendUsed == FALSE)?"PUT":"APPEND"),
					namespace, sContainer, sContent, pStream->content_size );
		}
	}



	g_free(pStream);
	g_free(pStream_handle);
	if (err != NULL) gs_error_free(err);
	if (c != NULL)   gs_container_free(c);
	return g_err;
}








//==============================================================================
// LISTENER
//==============================================================================

	static gboolean
alcs_listener_connect(const char* listenerUrl)
{
	static gchar s_listenerUrl[100] = "";
	gboolean bInit = FALSE;

	if ((!listenerUrl)||strlen(listenerUrl) == 0) {
		if (g_zmq_sock != NULL)
			return TRUE;
		else return FALSE;
	}

	// other listener ?
	if (g_strcmp0(s_listenerUrl, listenerUrl) != 0) {
		g_strlcpy(s_listenerUrl, listenerUrl, 99);

		// if socket alreadyinit, close it before
		listener_remote_closesocket(g_zmq_sock);
		g_zmq_sock = NULL;
	}

	if (g_zmq_sock == NULL) {
		TLstError* err = NULL;
		g_zmq_sock = listener_remote_connect(&err, g_zmq_ctx, listenerUrl, 2000, -1);
		if (err != NULL) {
			ALCS_ERROR("Error (%d) %s", err->code, err->message);
			listener_remote_error_clean(err);

		} else if (g_zmq_sock != NULL) 
			bInit= TRUE;
	}  else bInit = TRUE;   // already init

	return bInit;

}


/**
 * svc_url / svc_url: meta2, solr, ...
 */
	static void
alcs_listener_sendJSON(const gchar* listenerUrl, json_object* jobj)
{
	TLstError* err = NULL;
	if (alcs_listener_connect(listenerUrl) == TRUE) {

		char* buf = listener_remote_json_getStr(jobj);
		if (buf != NULL) {
			ALCS_DEBUG("send to listener: [%s]\n", buf);
			if (g_dryrun_mode == FALSE) {	
				// real mode
				ALCS_DEBUG("send to listener: [%s]\n", buf);
				err = listener_remote_sendBuffer(g_zmq_sock, buf, strlen(buf));
			} else {
				//drymode
				DRYRUN_SENDTOLISTENER(listenerUrl, "send to listener: [%s]\n", buf);
			}
			if (err != NULL) {
				ALCS_ERROR("Error (%d) %s", err->code, err->message);
				listener_remote_error_clean(err);
			} else { ALCS_DEBUG("zmq_send ok"); }
		} else { ALCS_ERROR("Faile to convert JSON to String"); }
	}
}



	static void
alcs_listener_buildHead(TLstJSONHeader* msgH, char* name, int pid, char* status, char* idcrawl)
{
	msgH->action_name = name;
	msgH->action_pid  = pid;

	if (status)
		g_strlcpy(msgH->status, status, LSTJSON_STATUS_MAX_CARACT);
	else
		g_strlcpy(msgH->status, "", LSTJSON_STATUS_MAX_CARACT);

	msgH->idmsg      = g_idmsgzmq;  g_idmsgzmq++;

	if (idcrawl)
		g_strlcpy(msgH->idcrawl, idcrawl, LSTJSON_IDCRAWL_MAX_CARACT); 
	else
		g_strlcpy(msgH->idcrawl, "", LSTJSON_IDCRAWL_MAX_CARACT);
}

/**
 * return char*, muszt free() the return value if != NULL
 */
	static struct json_object *
alcs_listener_request_buildData(gboolean bMeta1Only, TLstJSONHeader* msgH,
		const gchar* meta1_url, const gchar* svc_type, const gchar* svc_url,
		const gchar* prefixCt, struct _ActionListCtStatData_s* data)
{
	struct json_object *j_root, /**j_head,*/ *j_datah, *j_data;

	//build frame request, with header
	j_root = listener_remote_json_init(msgH, FALSE);
	if (!j_root)
		return NULL;

	//----
	// build common data
	j_datah = listener_remote_json_newSection();
	if (!j_datah) {
		listener_remote_json_clean(j_root);
		return NULL;
	}

	if (  (listener_remote_json_addStringToSection(j_datah, "PREFIX",   (char*) prefixCt) != NULL)
			||(listener_remote_json_addStringToSection(j_datah, "M1_ID",    (char*) meta1_url) != NULL)
			||(listener_remote_json_addStringToSection(j_datah, "SVC_ID",   (char*) svc_url ) != NULL)
			||(listener_remote_json_addStringToSection(j_datah, "SVC_TYPE", (char*) svc_type) != NULL)) {
		listener_remote_json_clean(j_datah);
		listener_remote_json_clean(j_root);
		return NULL;
	} else  
		listener_remote_json_addSection(j_root, LST_SECTION_DATAH, j_datah);



	//----
	// build data toi reduce by listener&reduce
	j_data = listener_remote_json_newSection();
	if (!j_data) {
		listener_remote_json_clean(j_root);
		return NULL;
	}

	if (bMeta1Only == FALSE) {
		//build msg: body about service
		if (  (listener_remote_json_addIntToSection(j_data, "SVC_NB_PREFIX",          data->svc_nbPrefix) != NULL)
				||(listener_remote_json_addIntToSection(j_data, "SVC_NB_CONTAINER_M2onM1",data->svc_nbContainerTotal) != NULL)
				||(listener_remote_json_addIntToSection(j_data, "SVC_ERR_REQ_META1",      data->svc_nbErrReq ) != NULL)) {
			listener_remote_json_clean(j_data);
			listener_remote_json_clean(j_root);
			return NULL;
		}

	} else {

		if (listener_remote_json_addIntToSection(j_data, "M1_NB_CONTAINER", data->m1_nbContainerTotal) != NULL) {
			listener_remote_json_clean(j_data);
			listener_remote_json_clean(j_root);
			return NULL;
		}
	}

	// contentName for list of container?
	if ((data->contentName != NULL)&&(strlen(data->contentName) > 0)) {
		if ( listener_remote_json_addStringToSection(j_data, "LISTCONTAINER" ,data->contentName        ) != NULL) {
			listener_remote_json_clean(j_data);
			listener_remote_json_clean(j_root);
			return NULL;
		}
	}

	if (  (listener_remote_json_addIntToSection(j_data, "M1_NB_PREFIX"     ,data->m1_nbPrefixTotal) != NULL)
			||(listener_remote_json_addIntToSection(j_data, "M1_NB_NOTMASTER"  ,data->m1_notMaster    ) != NULL)
			||(listener_remote_json_addIntToSection(j_data, "M1_ERR_BADBDDFILE",data->m1_nbBadBddFile ) != NULL)
			||(listener_remote_json_addIntToSection(j_data, "M1_ERR_BADPREFIX" ,data->m1_nbBadPrefix  ) != NULL)
			||(listener_remote_json_addIntToSection(j_data, "M1_ERR_REQ_META1" ,data->m1_nbErrReq     ) != NULL)) {
		listener_remote_json_clean(j_data);
		listener_remote_json_clean(j_root);
		return NULL;
	} else listener_remote_json_addSection(j_root, LST_SECTION_DATAR, j_data);


	return j_root;
}


/**
 * build requete command format json
 */
	static struct json_object *
alcs_listener_request_buildCmd(TLstJSONHeader* msgH)
{
	struct json_object *j_root;

	//build empty frame with all section
	j_root = listener_remote_json_init(msgH, TRUE);
	if (!j_root)
		return NULL;

	return j_root; 
}


	static void
alcs_listener_sendData(const char* listenerUrl, const gchar* meta1_url,
		const gchar* svc_type, const gchar* svc_url, const gchar* prefixCt,
		struct _ActionListCtStatData_s* data)
{
	TLstJSONHeader msgH;
	struct json_object* jobj;
	gboolean bMeta1Only = FALSE;

	// listener utiliséOB
	if ((listenerUrl == NULL)||(strlen(listenerUrl)==0))
		return;

	if ((svc_type == NULL)||(svc_url == NULL)) {
		ALCS_DEBUG("meta1:%s [%s]\n", meta1_url, prefixCt);
		bMeta1Only = TRUE;
	} else { ALCS_DEBUG("meta1:%s [%s] [%s|%s]\n", meta1_url, prefixCt, svc_type, svc_url); }

	// header msg
	alcs_listener_buildHead(&msgH, g_cfg_action_name, g_service_pid, 
			LISTENER_JSON_KEYNAME_HEAD_STATUS_data, g_crawlerID);

	jobj = alcs_listener_request_buildData(bMeta1Only, &msgH, meta1_url, svc_type, svc_url, prefixCt, data);
	alcs_listener_sendJSON(listenerUrl, jobj);
	listener_remote_json_clean(jobj);
}

	static void
alcs_listener_sendStopMsg(const char* listenerUrl)
{
	TLstJSONHeader msgH;
	struct json_object* jobj;

	if (listenerUrl == NULL)
		return;

	// header msg
	alcs_listener_buildHead(&msgH, g_cfg_action_name, g_service_pid, 
			LISTENER_JSON_KEYNAME_HEAD_STATUS_stopact, g_crawlerID);

	jobj =   alcs_listener_request_buildCmd(&msgH);
	alcs_listener_sendJSON(listenerUrl, jobj);
	listener_remote_json_clean(jobj);
}




//==============================================================================
// Shared memory
//==============================================================================
	static TAlcsSharedMem*
alcs_sharedmem_get(gchar* namespace, gchar* contentName)
{
	TAlcsSharedMem* ptr = NULL;
	GSList* list = NULL;

	list = g_alcs_listsm;
	for(;list;list = g_slist_next(list)) {
		ptr = (TAlcsSharedMem*) list->data;
		if (ptr == NULL) continue;

		if (g_strcmp0(ptr->contentName, contentName) == 0)
			break;
		else
			ptr = NULL;
	}

	if (ptr == NULL) {
		// create item...
		ptr = g_malloc0(sizeof(TAlcsSharedMem));
		if (ptr == NULL)
			return NULL;

		ptr->contentName = (gchar*) g_malloc0((strlen(contentName) + 2)*sizeof(gchar));
		if (ptr->contentName == NULL) {
			g_free(ptr);
			return NULL;
		}
		g_strlcpy(ptr->contentName, contentName, strlen(contentName) + 2);

		ptr->namespace   = (gchar*) g_malloc0((strlen(namespace) + 2)*sizeof(gchar));
		if (ptr->namespace == NULL) {
			g_free(ptr->contentName);
			g_free(ptr);
			return NULL;
		}
		g_strlcpy(ptr->namespace,   namespace,   strlen(namespace)   + 2);

		ptr->bExists = FALSE;
		ptr->datalen = 0;

		g_alcs_listsm = g_slist_append(g_alcs_listsm, ptr);
	}

	return ptr;
}



	static void
alcs_sharedmem_free(TAlcsSharedMem* ptr)
{
	if (ptr == NULL)
		return;

	if (ptr->contentName != NULL)
		g_free(ptr->contentName);
	if (ptr->namespace != NULL)
		g_free(ptr->namespace);
	g_free(ptr);
}


	static void
alcs_sharedmem_free_all(gchar* crawlerIDonly)
{
	TAlcsSharedMem* ptr = NULL;
	GSList* list = NULL;

	list = g_alcs_listsm;
	while (list) {
		ptr = (TAlcsSharedMem*) list->data;
		if (ptr == NULL) continue;

		if (  (crawlerIDonly == NULL)
				||(g_ascii_strncasecmp(ptr->contentName, crawlerIDonly, strlen(crawlerIDonly)) == 0)) {
			list = g_slist_next(list);
			g_alcs_listsm = g_slist_remove(g_alcs_listsm, ptr);		
			alcs_sharedmem_free(ptr);
		} else list = g_slist_next(list);
	}
}




	static GError*
alcs_sharedmem_saveOnGrid(TAlcsSharedMem* pData, gchar* buf, int len)
{
	GError* g_err = NULL;

	if (pData == NULL) 	return NULL;
	if (buf == NULL)    return NULL;
	if (len <= 0)       return NULL;

	// test and create the container id don't exist
	g_err = alcs_gridclient_container_Create(g_hc, pData->namespace, LISTENER_RESULT_CONTAINER_NAME);
	if (g_err) {
		ALCS_ERROR("%s: %s", __FUNCTION__, g_err->message);
		return g_err;
	}


	//TODO: verif si content existe ou non: pour 	

	//save data on content before
	ALCS_INFO("save on content=[%s]\n", pData->contentName);
	g_err = alcs_gridclient_content_PUTorAPPEND(g_hc, pData->namespace,
			LISTENER_RESULT_CONTAINER_NAME, pData->contentName,
			buf, len,  pData->bExists);  //FALSE: put command
	if (!g_err)
		pData->bExists = TRUE;

	return g_err;
}


/**
 * save on grid only when crawlID is used
 * or all if crawlerID == NULL
 */
	static GError*
alcs_sharedmem_saveOnGrid_all(gchar* crawlerIDonly)
{
	TAlcsSharedMem* ptr = NULL;
	GSList* list = NULL;
	GError* err = NULL;

	list = g_alcs_listsm;
	while (list) {
		ptr = (TAlcsSharedMem*) list->data;
		if (ptr == NULL) continue;

		if ((crawlerIDonly == NULL)
				||(g_ascii_strncasecmp(ptr->contentName, crawlerIDonly, strlen(crawlerIDonly)) == 0)) {
			err = alcs_sharedmem_saveOnGrid(ptr, ptr->data, ptr->datalen);
			ptr->datalen = 0;
		} 

		list = g_slist_next(list);
	}

	return err;
}


	static GError*
alcs_sharedmem_add(gchar* namespace, gchar* contentName, gchar* pDataHead, GByteArray* result)
{
	GError* g_err = NULL;

	// grid dont init ? --> init it
	if (g_hc == NULL) 
		g_hc = alcs_gridclient_init(&g_err, namespace);

	// error if grid not init...
	if (g_hc == NULL) {
		if (!g_err)
			ALCS_SETERR(&g_err, "%s: Unknown error", __FUNCTION__);
		return g_err;
	}

	// build content buffer
	if ((result == NULL)||(result->len == 0)) {
		ALCS_WARN("no result to save");
		return NULL;
	}

	int64_t len = result->len + strlen(pDataHead) + 10;

	TAlcsSharedMem* ptr = alcs_sharedmem_get(namespace, contentName);

	if ((ptr->datalen + len) >= ALCS_SAVEBUF_MAX_BYTES) {
		g_err = alcs_sharedmem_saveOnGrid(ptr, ptr->data, ptr->datalen);
		ptr->datalen = 0;
		if (g_err)
			return g_err;
		ptr->datalen = 0;
	}

	if (len >= ALCS_SAVEBUF_MAX_BYTES) {
		// write directly to the content
		gchar* buf = (gchar*) g_malloc0(len);
		if (buf != NULL) {
			g_snprintf(buf, len, "%s\n%s\n", ((pDataHead!=NULL)?pDataHead:""), result->data);
			len = strlen(buf);
			g_err = alcs_sharedmem_saveOnGrid(ptr, buf, len);
			g_free(buf);

		} else 
			ALCS_SETERR(&g_err, "%s(%d): %s (errno=%d)", __FUNCTION__, __LINE__,
					"Failed to allocate memory", errno);
	} else {
		g_snprintf(&(ptr->data[ptr->datalen]), ALCS_SAVEBUF_MAX_BYTES - ptr->datalen,
				"%s\n%s\n", ((pDataHead!=NULL)?pDataHead:""), result->data);
		ptr->datalen = strlen(ptr->data);
	}

	return g_err;
}




//==============================================================================
// Action
//==============================================================================

/**
 *  * \brief analyze, display and return nb container
 */
	static guint
do_analyzeListContainer(GByteArray* result, gboolean bShowAll)
{
	gchar** listCt = NULL;
	guint nbCt = 0, numCt = 0, nbCtTotal = 0;

	// no container ?
	if ((result == NULL)||(result->len == 0))
		return 0;

	// split result
	listCt = g_strsplit((gchar*) result->data, "\n", 0);
	if (listCt == NULL)
		return 0;

	nbCt = g_strv_length(listCt);
	for(numCt = 0;numCt<nbCt;numCt++) {
		if (listCt[numCt] == NULL)              continue;
		if (strlen((char*) listCt[numCt]) == 0) continue;

		nbCtTotal++;

		if (bShowAll == TRUE)
			fprintf(stdout, "[%s]\n", (char*)listCt[numCt]);
	}

	g_strfreev(listCt);

	return nbCtTotal;
}


	static gboolean
do_verifAndInitPrefix( struct _ActionListCtStatData_s* data,
		const gchar* prefixCt, container_id_t* prefix)
{
	GError* err = NULL;

	memset(prefix, 0, sizeof(container_id_t));

	//valid prefix
	if ((prefixCt == NULL)||(strlen(prefixCt) == 0)) {
		// erreur de prefix: bdd read error
		data->m1_nbBadBddFile++;
		return FALSE;

	} else  if (g_ascii_strncasecmp(prefixCt, "R", 1) == 0) {
		// error code after "R" caracters
		if (g_ascii_strncasecmp(prefixCt, "R003", 4) == 0) data->m1_notMaster++;
		else                                               data->m1_nbBadBddFile++;
		return FALSE;
	}

	//conv prefix
	err = alcs_meta1_PrepareDataIn(NULL, NULL, prefixCt, prefix);
	if (err) {
		g_clear_error(&err);
		data->m1_nbBadPrefix++;
		return FALSE;
	}

	return TRUE;
}



	static void
do_Execute(const char* listenerUrl, const gchar* meta1_url, gchar* namespace,
		const gchar* prefixCt, gchar* srvtype, gchar* srvurl, gboolean ShowDetails, 
		struct _ActionListCtStatData_s* pData, GByteArray* pResultListContainer)
{
	GError* g_err = NULL;

	pData->contentName[0] = '\0';

	//list container shoiuld want
	if (ShowDetails == TRUE) {

		// containers exist ?
		if (pResultListContainer->len > 0) {
			gchar dataHead[150];

			//build future name of content
			g_snprintf(pData->contentName, ALCS_CONTENTNAME_MAX_BYTES, 
					"%s_%s_listcontainer-meta1_%s_%d",
					((g_crawlerID==NULL)?"XXXX":g_crawlerID),
					g_cfg_action_name, meta1_url, g_service_pid); //, numContent);

			//build head of content data
			if ((srvtype != NULL)&&(srvurl!=NULL)){
				g_snprintf(&dataHead[0], 150, "[%s: %s ] (prefix=%s)", srvtype, srvurl, prefixCt);
			} else {
				g_snprintf(&dataHead[0], 150, "(prefix=%s)", prefixCt);
			}

			ALCS_DEBUG("namespace=[%s]", namespace);

			// save list container on GRID
			g_err = alcs_sharedmem_add(namespace, pData->contentName, &dataHead[0], pResultListContainer);
			if (g_err) {
				ALCS_ERROR("do_Execute(): %s", g_err->message);
				g_clear_error(&g_err);			
				g_err = NULL;
			}
		}
	}

	// send result/data to listener
	alcs_listener_sendData(listenerUrl, meta1_url, srvtype, srvurl, prefixCt, pData);

}

/*
 * \brief Mnaage each pf (ShowDetails == TRUE)
 */
	static GError*
do_work(const char* listenerUrl, const gchar* meta1_url,
		gchar* namespace, gchar** meta2cfg,
		const gchar* prefixCt, gboolean ShowDetails)
{
	GError* err = NULL;
	container_id_t prefix;
	addr_info_t m1addr;
	GByteArray* result = NULL;
	struct _ActionListCtStatData_s data;

	memset(&data, 0, sizeof(struct _ActionListCtStatData_s));

	data.m1_nbPrefixTotal++;

	// conv meta1 url
	err = alcs_meta1_PrepareDataIn(meta1_url, &m1addr, NULL, NULL);
	if (err)
		return err;

	// prpare, verufy and conv prefix
	if (do_verifAndInitPrefix(&data, prefixCt, &prefix) == FALSE) {
		// send error...
		alcs_listener_sendData(listenerUrl, meta1_url, NULL, NULL, prefixCt, &data);
		return NULL;
	}


	if (meta2cfg == NULL) {
		// read list all containers on meta1
		err = alcs_meta1_GetListContainer(namespace, &m1addr, &prefix, TRUE,
				NULL, NULL, &result);
		if (err) {
			data.m1_nbErrReq++;
			g_clear_error(&err);
		} else {
			data.m1_nbContainerTotal = do_analyzeListContainer(result, ShowDetails);
		}

		do_Execute(listenerUrl, meta1_url, namespace, prefixCt, NULL, NULL, ShowDetails, &data, result);

		g_byte_array_free(result, TRUE);
		result = NULL;

	} else {

		// get all services on meta1 about this prefix
		gchar** result_m2cfg = alcs_meta1_GetListServices(namespace, &m1addr, &prefix, &err);
        if (err) {
            data.m1_nbErrReq++;
            g_clear_error(&err);

        } else {

			// get all container / services
		    guint /*nb = 0,*/ num = 0;

			data.svc_nbPrefix++;

			while (result_m2cfg[num]) {
				if (result_m2cfg[num] == NULL) break;;
				if (strlen((char*) result_m2cfg[num]) == 0) {num++;  continue; }

				gchar** m2 = g_strsplit((gchar*) result_m2cfg[num], "|", 4);
				if (m2 == NULL)  { num++;  continue; }
				if (g_strv_length(m2)<4) { g_strfreev(m2); m2 = NULL; num++; continue;}

				// read list all containers on meta1
				gchar* srvtype = g_strstrip(m2[1]);
				gchar* srvurl  = g_strstrip(m2[2]);

				ALCS_DEBUG("services check: srvtype=[%s], srvurl[%s]", srvtype, srvurl);

				err = alcs_meta1_GetListContainer(namespace, &m1addr, &prefix, FALSE, 
						srvtype, srvurl, &result);
				if (err) {
					data.svc_nbErrReq = 1;
					g_clear_error(&err);

					alcs_listener_sendData(listenerUrl, meta1_url, srvtype, srvurl, prefixCt, &data);
	
				} else {

					data.svc_nbContainerTotal = do_analyzeListContainer(result, ShowDetails);
	
					do_Execute(listenerUrl, meta1_url, namespace, prefixCt, srvtype, srvurl, 
								ShowDetails, &data, result);

					g_byte_array_free(result, TRUE);
					result = NULL;
				}

				g_strfreev(m2);	
				m2 = NULL;

				num++;
			} //end while
			
			g_free(result_m2cfg);
		} 
	}

	return err;
}



//==============================================================================
// Listening message come from, and execute action function
//==============================================================================


/* ------- */
struct SParamMsgrx {
	gchar* namespaceCfg;
	gchar* displayListContainer;
	gchar* listenerUrl;
	const gchar* source_path;
	const gchar* prefixCt;
	const gchar* meta1_url;
	gchar* crawlerID;
	gchar* dryrun;
};

void init_paramMsgRx(struct SParamMsgrx* pParam)
{
	if (pParam == NULL) return;

	memset(pParam, 0, sizeof(struct SParamMsgrx));
}

void clean_paramMsgRx(struct SParamMsgrx* pParam)
{
	if (pParam == NULL) return;

	if (pParam->namespaceCfg) g_free(pParam->namespaceCfg);
	if (pParam->displayListContainer) g_free(pParam->displayListContainer);
	if (pParam->listenerUrl)  g_free(pParam->listenerUrl);
	if (pParam->crawlerID)    g_free(pParam->crawlerID);
	if (pParam->dryrun)       g_free(pParam->dryrun);

	// clean global variables
    if (g_crawlerID != NULL) {
        g_free(g_crawlerID);
        g_crawlerID = NULL;
    }

	init_paramMsgRx(pParam);
}




static gboolean extract_paramMsgRx(gboolean allParam,  TActParam* pActParam, 
		struct SParamMsgrx* pParam, gboolean* bShowAll)
{
	if (pParam == NULL)
		return FALSE;

	// Namespace extraction
	if (NULL == (pParam->namespaceCfg = get_argv_value(pActParam->argc, pActParam->argv, 
					g_cfg_action_name, g_cfg_namespace_cmd_opt_name))) {
		GRID_TRACE("Failed to get namespace from args");
		return FALSE;
	}

    // show all details configuratio
    if (NULL == (pParam->displayListContainer = get_argv_value(pActParam->argc, pActParam->argv, 
					g_cfg_action_name, g_cfg_displayListContainer_cmd_opt_name))) {
		ALCS_TRACE("Failed to get displayListContainer from args");
    }

    // show all details configuration
	if (NULL == (pParam->listenerUrl = get_argv_value(pActParam->argc, pActParam->argv, 
					g_cfg_action_name, g_cfg_listenerUrl_cmd_opt_name))) {
		ALCS_TRACE("Failed to get listener from args");
    }


	pParam->dryrun = get_argv_value(pActParam->argc, pActParam->argv, 
			g_cfg_action_name, g_cfg_dryrun_cmd_opt_name);


        if (NULL == (pParam->crawlerID = get_argv_value(pActParam->argc, pActParam->argv, 
						g_cfg_action_name, g_cfg_crawlerID_cmd_opt_name))) {
            ALCS_TRACE("Failed to get crawlerID from args");
            return FALSE;
        }

	if (allParam == TRUE) {
		/* ------- */
		// Checking occurence form
		GVariantType* gvt = g_variant_type_new(g_cfg_occur_type_string);
		if (FALSE == g_variant_is_of_type(pActParam->occur, gvt)) {
			g_variant_type_free(gvt);
			return FALSE;
		}
		g_variant_type_free(gvt);
		gvt = NULL;


		// prefix
		pParam->prefixCt = get_child_value_string(pActParam->occur, 1);
		if (pParam->prefixCt != NULL) {
			if (g_strcmp0(pParam->prefixCt, "null") == 0)
				pParam->prefixCt = "";
		}

		// meta1 url
		pParam->meta1_url = get_child_value_string(pActParam->occur, 2);
	} else {
		pParam->source_path = "";
		pParam->prefixCt    = "";
		pParam->meta1_url   = "";
	}


	/////////////////////////////////////////////////
	// save on global variables...
    // ID crawler
    if (g_crawlerID != NULL) {
        g_free(g_crawlerID);
        g_crawlerID = NULL;
    }
    if ((pParam->crawlerID != NULL)&&(strlen(pParam->crawlerID)>0)) {
        g_crawlerID = g_malloc0(strlen(pParam->crawlerID) + 10);
        g_strlcpy(g_crawlerID, pParam->crawlerID, strlen(pParam->crawlerID)+1);
    }

    // display all container or only synthesis
    *bShowAll = TRUE;
    if (pParam->displayListContainer != NULL) {
        if (g_strcmp0(pParam->displayListContainer, "FALSE") == 0)
            *bShowAll = FALSE;
    } else *bShowAll = FALSE;

    //dryrun mode 
   g_dryrun_mode = TRUE;
    if (pParam->dryrun != NULL) {
        if (g_strcmp0(pParam->dryrun, "FALSE") == 0)
            g_dryrun_mode = FALSE;
    } else g_dryrun_mode = FALSE;



	return TRUE;
}



gboolean action_set_data_trip_ex(TCrawlerBusObject *obj, const char* sender,
    const char *alldata, GError **error)
{
	GError* e = NULL;
	gboolean bShowAll = FALSE;
	TActParam actparam;
	struct SParamMsgrx msgRx;
	act_paramact_init(&actparam);
	init_paramMsgRx(&msgRx);

	(void) obj;

	GVariant* param = act_disassembleParam((char*) alldata, &actparam);
	if (extract_paramMsgRx(TRUE, &actparam, &msgRx, &bShowAll) == FALSE) {
		act_paramact_clean(&actparam);
		clean_paramMsgRx(&msgRx);
		*error = NEWERROR(1, "Bad format for received data");
		g_variant_unref(param);
		return FALSE;
	}

	gchar** meta2cfg = NULL;
	gchar* namespace = NULL;
	int nb;

	//-----------------------
	// manage prefix...
	meta2cfg = g_strsplit(msgRx.namespaceCfg, ",", 0);

	nb = g_strv_length(meta2cfg);

	if (nb >= 2) {
		namespace = meta2cfg[0];

		// check list of container associate with prefix
		// check statistique
		e = do_work(msgRx.listenerUrl, msgRx.meta1_url, namespace,
				&meta2cfg[1], msgRx.prefixCt, bShowAll);
	} else if (nb == 1) {
		namespace = meta2cfg[0];
		e = do_work(msgRx.listenerUrl, msgRx.meta1_url, namespace,
				NULL, msgRx.prefixCt, bShowAll);
	}

	if (meta2cfg != NULL)
		g_strfreev(meta2cfg);

	// save response
	char* temp_msg = (char*)g_malloc0((SHORT_BUFFER_SIZE*sizeof(char)) + sizeof(guint64));	
	sprintf(temp_msg, "%s on %s for the context %llu and the file %s",
			((!e)?ACK_OK:ACK_KO), g_cfg_action_name,
			(long long unsigned)actparam.context_id, msgRx.source_path);
	char *status = act_buildResponse(g_cfg_action_name, g_service_pid, actparam.context_id, temp_msg);
	g_free(temp_msg);

	// send
    static TCrawlerReq* req = NULL;
    if (req)
        crawler_bus_req_clear(&req);

    GError* err = crawler_bus_req_init(g_conn, &req, sender, SERVICE_PATH, SERVICE_IFACE_CONTROL);
    if (err) {
        g_prefix_error(&err, "Failed to connectd to crawler services %s : ",
                        sender);
		GRID_WARN("Failed to send ack [%s]: %s", msgRx.source_path, err->message);
		g_clear_error(&err);
	}
	
	tlc_Send_Ack_noreply(req, NULL, ((!e)?ACK_OK:ACK_KO), status);
    g_free(status);	


	if (e) {
		ALCS_WARN("Failed to list containers [%s] : %s", msgRx.source_path, e->message);
		g_clear_error(&e);
	}

	act_paramact_clean(&actparam);
	clean_paramMsgRx(&msgRx);
	g_variant_unref(param);

	return TRUE;
}


gboolean action_command(TCrawlerBusObject *obj, const char* cmd, const char *alldata, 
		char** status, GError **error)
{
	gboolean bShowAll = FALSE;
	TActParam actparam;
	struct SParamMsgrx msgRx;
	act_paramact_init(&actparam);
	init_paramMsgRx(&msgRx);

	(void) obj;
	(void) status;

	GRID_DEBUG("%s...\n", __FUNCTION__);
	GVariant* param = act_disassembleParam((char*) alldata, &actparam);
    if (extract_paramMsgRx(FALSE, &actparam, &msgRx, &bShowAll) == FALSE) {
		act_paramact_clean(&actparam);
		clean_paramMsgRx(&msgRx);
		*error = NEWERROR(1, "Bad format for received data");
		GRID_ERROR((*error)->message);
		g_variant_unref(param);
		return FALSE;
	}

	if (g_strcmp0(cmd, CMD_STARTTRIP) == 0) {
		//-----------------------
		// start process crawling	
		GRID_INFO("start process's crawler");

	} else  if (g_strcmp0(cmd, CMD_STOPTRIP) == 0) {
		//----------------------
		// end process crawling
		GRID_INFO("stop process's crawler");
		sleep(1);

		if (bShowAll == TRUE) {
			alcs_sharedmem_saveOnGrid_all(g_crawlerID);
			alcs_sharedmem_free_all(g_crawlerID);
		}

		// BUGS: if send stop msg when a  few of crawler send on one action process,
		//       listener.py end reduce on the first received stop msg...
		//       if no stop msg received, stop on timeout automatically...
		alcs_listener_sendStopMsg(msgRx.listenerUrl); 
	} else {
		if (cmd)
			GRID_INFO("%s process's crawler", cmd);
		else
            GRID_INFO("%s process's crawler", "Unknown command");
	}

	GRID_DEBUG(">%s process's crawler\n", cmd);

	act_paramact_clean(&actparam);
	clean_paramMsgRx(&msgRx);
	g_variant_unref(param);

	return TRUE;
}

/* GRID COMMON MAIN */
static struct grid_main_option_s * main_get_options(void)
{
	static struct grid_main_option_s options[] = {
		{ NULL, 0, {.b=NULL}, NULL }
	};

	return options;
}

static void main_action(void)
{
	GError* error = NULL;
	//TCrawlerBus* conn = NULL;

	g_type_init();

	g_main_loop = g_main_loop_new (NULL, FALSE);

	//init zmq lib
	g_zmq_ctx = listener_remote_init();
	if (!g_zmq_ctx) {
		fprintf(stderr, "zmq_init failed (%d)", errno);
		exit(EXIT_FAILURE);
	}


	/* DBus connexion */
	error = tlc_init_connection(&g_conn, g_service_name, SERVICE_PATH, 
						"" /*, g_dbusdaemon_address*/ /*pour le bus system: =""*/, 
						(TCrawlerBusObjectInfo*) act_getObjectInfo());
	if (error) {
		ALCS_ERROR("System D-Bus connection failed: %s",
                /*g_cfg_action_name, g_service_pid,*/ error->message);
		exit(EXIT_FAILURE);
	}

	//seztmax size of received messages...

	ALCS_INFO("%s (%d) : System D-Bus %s action signal listening thread started...", 
			g_cfg_action_name, g_service_pid, g_cfg_action_name);

	g_main_loop_run (g_main_loop);
	
	GError* err = alcs_sharedmem_saveOnGrid_all(NULL);
	if (err) {
    	ALCS_ERROR("Failed to save list on grid: %s", err->message);  
		g_clear_error(&err);	
	}

	alcs_sharedmem_free_all(NULL);

	/* zmq: exited */
	ALCS_INFO("Waiting end of tramsit data...");
	listener_remote_close(g_zmq_ctx, g_zmq_sock);
	
	crawler_bus_Close(&g_conn);

	if (g_hc)
		alcs_gridclient_free(&g_hc);

	exit(EXIT_SUCCESS);
}

	static void
main_set_defaults(void)
{
	g_cfg_action_name =  "action_list_container";
	g_cfg_command_name = LISTENER_JSON_KEYNAME_HEAD_NAME_command;
	g_cfg_namespace_cmd_opt_name = "n";
	g_cfg_displayListContainer_cmd_opt_name = "d";
	g_cfg_listenerUrl_cmd_opt_name = "l";
	g_cfg_crawlerID_cmd_opt_name = "crawlerID";
	g_cfg_dryrun_cmd_opt_name = "dryrun";
	g_cfg_occur_type_string = "(sss)";

	g_conn = NULL;
	g_stop_thread = FALSE;
	g_service_pid = getpid();
	g_zmq_ctx  = NULL;
	g_zmq_sock = NULL;

	g_idmsgzmq = 0;
	g_crawlerID = NULL;

    buildServiceName(g_service_name, SERVICENAME_MAX_BYTES,
                    SERVICE_ACTION_NAME, g_cfg_action_name, g_service_pid, FALSE);
}

	static void
main_specific_fini(void)
{
}

	static gboolean
main_configure(int argc, char **args)
{
	argc = argc;
	args = args;

    if (argc >= 1)
        g_dbusdaemon_address = getBusAddress(args[0]);
    GRID_DEBUG("dbus_daemon address:\"%s\"", g_dbusdaemon_address);

	return TRUE;
}

	static const gchar*
main_usage(void)
{
	return "";
}

	static void
main_specific_stop(void)
{
	g_stop_thread = TRUE;
	g_main_loop_quit(g_main_loop);
	ALCS_INFO("%s (%d) : System D-Bus %s action signal listening thread stopped...", 
			g_cfg_action_name, g_service_pid, g_cfg_action_name);
}

static struct grid_main_callbacks cb =
{
	.options = main_get_options,
	.action = main_action,
	.set_defaults = main_set_defaults,
	.specific_fini = main_specific_fini,
	.configure = main_configure,
	.usage = main_usage,
	.specific_stop = main_specific_stop
};

	int
main(int argc, char **argv)
{
	// init var on lib grid_client, 
	// mostly log and g_log_sefault_handler()
	// this init was bad for action process
	// grid_main() init good value about this...
	alcs_gridclient_init(NULL, "");

	return grid_main(argc, argv, &cb);
}


