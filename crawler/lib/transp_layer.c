#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "atos.grid.crawler.crawler_bus"
#endif //G_LOG_DOMAIN

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <glib-object.h>

#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include <metautils/lib/metautils.h>

#include "transp_layer.h"





/**************************************************************************/
/* Constants                                                              */
/**************************************************************************/




/******************************************************************************/
/* Object definition                                                          */
/******************************************************************************/
GType crawler_object_get_type (void);

struct TCrawlerBusObject {
	GObject parent;
};

struct TCrawlerBusObjectClass {
  GObjectClass parent;
};

G_DEFINE_TYPE(TCrawlerBusObject, crawler_object, G_TYPE_OBJECT)


#define CRAWLER_TYPE_OBJECT              (crawler_object_get_type ())
#define CRAWLER_OBJECT(object)           (G_TYPE_CHECK_INSTANCE_CAST ((object), CRAWLER_TYPE_OBJECT, TCrawlerBusObject))
#define CRAWLER_OBJECT_CLASS(klass)      (G_TYPE_CHECK_CLASS_CAST ((klass), CRAWLER_TYPE_OBJECT, TCrawlerBusObjectClass))
#define CRAWLER_IS_OBJECT(object)        (G_TYPE_CHECK_INSTANCE_TYPE ((object), CRAWLER_TYPE_OBJECT))
#define CRAWLER_IS_OBJECT_CLASS(klass)   (G_TYPE_CHECK_CLASS_TYPE ((klass), CRAWLER_TYPE_OBJECT))
#define CRAWLER_OBJECT_GET_CLASS(obj)    (G_TYPE_INSTANCE_GET_CLASS ((obj), CRAWLER_TYPE_OBJECT, TCrawlerBusObjectClass))



static void crawler_object_init (TCrawlerBusObject *obj)
{
	(void) obj;
	// none
}

static void crawler_object_class_init (TCrawlerBusObjectClass *klass)
{
	(void) klass;
}




/******************************************************************************/
/* structure                                                                  */
/******************************************************************************/

/**
 *`\brief obscure structure which contains data about connection bus
 *
 */
struct TCrawlerBus{
	DBusGConnection* conn;    // handle of connection
	TCrawlerBusObject* obj;   // object to remote process
} ;

/**
 * \brief obscure structure which contains data about request SYNC or ASYNC
 */
struct TCrawlerReq {
	char*        svc_name;     // service name
	TCrawlerBus* handle;       // handle connect bus
	DBusGProxy*  proxy;        // proxy to remote process
};




/**
 *
 *
 */
typedef enum {
	RESP_AS = 0,     // array of string
	RESP_S  = 1      // string

} ECrawlerBusCmdCallResponseType;



/**
 * \brief structure which contains data about notification callback (ASYNC Request)
 */
typedef struct {
    TCrawlerReq* req;
    void*        user_data;

	ECrawlerBusCmdCallResponseType resp_typ;


    void (*_notify_callback)(TCrawlerReq* req, GError* error, void* msgReceived, void *user_data);
} TCrawlerBusCmdCall;


/**
 * \brief structure which contains data about notification callback (ASYNC Request)
 */
typedef struct {
    TCrawlerReq* req;
    void*        user_data;

    void (*_notify_callback)(TCrawlerReq* req, char* msgReceived, void *user_data);
} TCrawlerBusCmdSig;





/**************************************************************************/
/* MACRO                                                                  */
/**************************************************************************/
#define CRAWLER_BUSCMD_SAVEUSERDATA(/*(TCrawlerBusCmdCall*)*/ c, req, resp, user_data, cb) \
    c->req = req;\
    c->user_data = user_data;\
	c->resp_typ = (ECrawlerBusCmdCallResponseType) resp;\
	//c->_notify_callback = cb       // comment besause a warning at compil, and not used in real




/******************************************************************************/
/* functions                                                                  */
/******************************************************************************/
GError* _crawler_bus_VerifIsConnected(TCrawlerBus *handle);



/**
 * \brief init a connection to the bus
 *
 * \param[in] address =NULL: used local DBUS_BUS_SYSTEM, else local session
 * 							ex: address = "unix:abstract=/tmp/dbus-YMpX7o46oJ"
 * \param[out] handle id connection
 *
 * \return the errors if error occurs, else =NULL
 */
GError* crawler_bus_Open(TCrawlerBus **handle, gchar* address)
{
	GError* error = NULL;

	if (!handle)
		return NEWERROR(-1, "Bad Handle");

	if (*handle != NULL)
		return NEWERROR(-1, "Handle already allocated");

	*handle = g_malloc0(sizeof(TCrawlerBus));
	TCrawlerBus* h = *handle;

	if ((address == NULL)||(strlen(address) == 0)) {
		/* used dbus system */
	    h->conn = dbus_g_bus_get (DBUS_BUS_SYSTEM, &error);
		 if (!h->conn)	{
			g_prefix_error(&error, "Failed to open connection to bus(system): ");
			return error;
		}


	} else {
		/* used a personal session */
		h->conn = dbus_g_connection_open(address, &error);
		if (error) {
			g_prefix_error(&error, "Failed to open connection to bus(session)");
			return error;
		}
		if (h->conn) {
	        DBusError dberror;

			dbus_error_init(&dberror);
	
			//DBusConnection* conn = dbus_g_connection_get_connection(handle->conn);
	        if (!dbus_bus_register ((DBusConnection*)dbus_g_connection_get_connection(h->conn), 
									&dberror)) {
			//if (dberror != NULL) {				
				if (error) g_clear_error(&error);				
				error =  NEWERROR(-1, "Failed to register connection to bus %s: %s", 
								address, dberror.message);
				crawler_bus_Close(handle);
				//dbus_error_free(dberror);
				return error;
			}
			//if (dberror) dbus_error_free(dberror);
			
		} else return error;
    }

    return NULL;
}


/**
 * \brief close opnened connection
 * \param[in] handle connection to close
 * \return the errors if error occurs, else =NULL
 */
GError* crawler_bus_Close(TCrawlerBus **handle)
{
	// obj
	if ((*handle)->obj) {
		if ((*handle)->conn)
			dbus_g_connection_unregister_g_object((*handle)->conn, (GObject*) (*handle)->obj);
		g_object_unref((*handle)->obj);
	}	

	// conn
	dbus_g_connection_unref((*handle)->conn);	
	
	g_free(*handle);
	*handle = NULL;

	return NULL;
}


GError* _crawler_bus_VerifIsConnected(TCrawlerBus *handle)
{
    if (!handle)
        return NEWERROR(-1, "Bad Handle");

    if (!handle->conn)
        return NEWERROR(-1, "connection not opened");

	return NULL;
}

/**
 * \brief register an object (with interface/methods) to the bus
 * \param[in] handle connection to used
 * \param[in] service_name service name of new object
 * \param[in] service_path service path, ex: "/atos/grid/Crawler"
 * \param[in] object_info object info see DBus-glob spec
 * \return the errors if error occurs, else =NULL
 */
GError* crawler_bus_Register(TCrawlerBus *handle, char* service_name, char* service_path, 
			const TCrawlerBusObjectInfo* object_info)
{
	GError* error = _crawler_bus_VerifIsConnected(handle);	
	if (error) return error;

	// already registerred !
	if (handle->obj)
		return NULL;

	// bad param
	if (!service_path)
		return NEWERROR(-1, "Bad service_path"); 
	if (!object_info)
		return NEWERROR(-1, "Bad object_info");

	// introspection information for given object type
	dbus_g_object_type_install_info (CRAWLER_TYPE_OBJECT, object_info);

	// verif if name elready exist on bus or not
    TCrawlerReq* req = NULL;
    error = crawler_bus_reqBase_init(handle, &req);
    if (error) {
        g_prefix_error(&error, "Failed to init request to %s: ", "org.freedesktop.DBus");
		crawler_bus_req_clear(&req);
		return error;
    }

	gboolean result = FALSE;
	error = crawler_bus_reqBase_IsNameExists(req, service_name, &result);
    if (error) g_clear_error(&error);
	if (result == FALSE) {
		// request the message bus to assign the given name to the method caller
		error = crawler_bus_reqBase_RegisterName(req, service_name);
	} else 
		error = NEWERROR(-1, "Name %s already exist", service_name);

	crawler_bus_req_clear(&req);	
	if (error) return error;

	// registered...
	handle->obj = g_object_new (CRAWLER_TYPE_OBJECT, NULL);
	if (!handle->obj)
		return NEWERROR(-1, "cannot allocate memory for g_object_new() function");		

	dbus_g_connection_register_g_object (handle->conn, service_path, G_OBJECT (handle->obj));

	return NULL;
}



/**
 * BLOCKED FUNCTION !!!
 */
GError* crawler_bus_flush(TCrawlerBus *handle)
{
	dbus_g_connection_flush (handle->conn);
	return NULL;
}


/**************************************************************************/
/* Request SYNC: send request and wait response before return             */
/**************************************************************************/

/**
 * \brief init request obscure stucture
 * \param[in] handle connection to used
 * \param[out] req   request to initialize
 * \param[in] name the destination/service name
 * \param[in] path 
 * \param[in] iface the interface name
 * \return the errors if error occurs, else =NULL
 * \comment example: crawler_bus_req_init(&handle, &req, 
 * 				"org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus");
 */
GError* crawler_bus_req_init(TCrawlerBus *handle, TCrawlerReq** req,
	const char *name, const char *path, const char *iface)
{
	TCrawlerReq* r = NULL;
    GError* error = _crawler_bus_VerifIsConnected(handle);
    if (error) return error;


	if (!req)
		return NEWERROR(-1, "Bad request");
	if (*req)
		return NEWERROR(-1, "Request already exists");
	if (!name)
		return NEWERROR(-1, "Bad name");
    if (!path)
		return NEWERROR(-1, "Bad path");
    if (!iface) 
		return NEWERROR(-1, "Bad interface");

	*req = g_new0(TCrawlerReq, 1);
	r =  *req;
	
	memset(r, sizeof(TCrawlerReq), 0);

	r->svc_name = g_malloc0(strlen(name) + 10);
	g_strlcpy(r->svc_name, name, strlen(name)+9);
	r->handle   = handle;
	r->proxy    = dbus_g_proxy_new_for_name (handle->conn, name, path, iface);
	if (!(r->proxy))
		return NEWERROR(-1, "Failed Request init ");

	return NULL;
}

/**
 * \brief close and clrear a request
 * \param[in] req request to close
 */
void crawler_bus_req_clear(TCrawlerReq** req)
{
	if (!req)
		return;

	if (!(*req))
		return;

	TCrawlerReq* r;
	r = *req;
	if (r->proxy) {	
		g_object_unref (G_OBJECT( r->proxy));
		r->proxy = NULL;
	}

	if (r->svc_name) {
		g_free(r->svc_name);
		r->svc_name = NULL;
	}

	g_free(r);

	*req = NULL;
}




/**************************************************************************/
/* Request to org.freedesktop.DBus                                        */
/* SYNC methods                                                           */
/**************************************************************************/

/**
 * \brief init request obscure stucture
 * \param[in] handle connection to used
 * \param[out] req   request to initialize
 * \return the errors if error occurs, else =NULL
 */
GError* crawler_bus_reqBase_init(TCrawlerBus *handle, TCrawlerReq** req)
{
    static char* dbus_server_name   = "org.freedesktop.DBus";
    static char* dbus_server_path   = "/org/freedesktop/DBus";
    static char* dbus_server_iface  = "org.freedesktop.DBus";

	return crawler_bus_req_init(handle, req, 
			dbus_server_name, dbus_server_path, dbus_server_iface);
}


/**
 * \brief register a name and publish all methods to bus
 * \param[in] req   request to  to used
 * \param[in] name the destination/service name
 * \return the errors if error occurs, else =NULL
 */
GError* crawler_bus_reqBase_RegisterName(TCrawlerReq* req, const char *name)
{
	GError* error = NULL;
	guint request_name_result = 0;

	if (!req)
		return NEWERROR(-1, "Bad req (NULL)");

	if (!name)
		return NEWERROR(-1, "Bad name");

	if (!dbus_g_proxy_call (req->proxy, "RequestName", &error,
                       G_TYPE_STRING, name, G_TYPE_UINT, 0, G_TYPE_INVALID,
                       G_TYPE_UINT, &request_name_result,  G_TYPE_INVALID)) {
		g_prefix_error(&error, "Failed to acquire %s: ", name);
		return error;
    }

	return NULL;
}



/**
 * \brief verif if a name exist on bus
 * \param[in] req   request to  to used
 * \param[in] name the destination/service name
 * \param[out] name_exist =TRUE if name already exist on bus
 * \return the errors if error occurs, else =NULL
 */
GError* crawler_bus_reqBase_IsNameExists(TCrawlerReq* req, const char *name, gboolean* name_exist)
{
	gboolean result = TRUE;
	GError* error = NULL; 

    if (name_exist)
        *name_exist = TRUE;

    if (!dbus_g_proxy_call (req->proxy, "NameHasOwner", &error,
                       G_TYPE_STRING, name, G_TYPE_INVALID,
                       G_TYPE_BOOLEAN, &result,  G_TYPE_INVALID)) {
        if (name_exist) *name_exist = FALSE;
        g_prefix_error(&error, "Failed to acquire %s, name not exist: ", name);
    }

	if (name_exist) 
		*name_exist = result;

    return NULL;
}



/**
 * \brief Get all service name connected on the same bus
 * \param[in] req   request to  to used
 * \param[out] listnames  servicename list altualy conntected
 * \return the errors if error occurs, else =NULL
 */
GError* crawler_bus_reqBase_GetListNames(TCrawlerReq* req, char*** listnames)
{
    GError* error = NULL;

    if (!dbus_g_proxy_call (req->proxy, "ListNames", &error,
                       G_TYPE_INVALID,
						G_TYPE_STRV, listnames, G_TYPE_INVALID)) {
        g_prefix_error(&error, "Failed to acquire ListName: ");
		return error;
    }

	

    return NULL;
}



/**************************************************************************/
/* Generic Request to other interface                                     */
/* SYNC methods                                                           */
/**************************************************************************/
/**
 * \brief Get all service name connected on the same bus
 * \param[in] req   request to  to used
 * \param[in] timeout in ms
 * \param[in] dataToSend1 first string to send
 * \param[in] dataToSend1 2d string to send
 * \param[out] dataToreceiv string to reeived
 * \return the errors if error occurs, else =NULL
 */
GError* crawler_bus_req_Send_ss_s(TCrawlerReq* req, char* method, int timeout,  
									char* dataToSend1, char* dataToSend2, char** dataToreceiv)
{
    GError* error = NULL;

    if (!req) return NEWERROR(-1, "Bad req (NULL)");

	if (!method)       return NEWERROR(-1, "Bad method");
    if (!dataToSend1)  return NEWERROR(-1, "Bad dataToSend1");
	if (!dataToSend2)  return NEWERROR(-1, "Bad dataToSend2");
	if (!dataToreceiv) return NEWERROR(-1, "Bad dataToreceiv");

	gchar* tmp = NULL;
    if (!dbus_g_proxy_call_with_timeout(req->proxy, method, timeout, &error,
                        G_TYPE_STRING, dataToSend1, 
						G_TYPE_STRING, dataToSend2, G_TYPE_INVALID,

                       G_TYPE_STRING, &tmp/*dataToreceiv*/,  G_TYPE_INVALID)) {
        g_prefix_error(&error, "Failed to send %s", method);
        return error;
    }
	*dataToreceiv = tmp;

    return NULL;
}





/**************************************************************************/
/* Generic Request to other interface                                     */
/* A-SYNC methods                                                         */
/**************************************************************************/




static void reply__nc (DBusGProxy *proxy, DBusGProxyCall *call, void *user_data)
{
    GError *error = NULL;
    TCrawlerBusCmdCall* c = (TCrawlerBusCmdCall*)user_data;
	gboolean result = FALSE;

	switch (c->resp_typ) {
	case RESP_AS:{
					char **reply_list  = NULL;
					result = dbus_g_proxy_end_call (proxy, call, &error, G_TYPE_STRV, 
												&reply_list, G_TYPE_INVALID);
					if (result)
						c->_notify_callback(c->req, error, reply_list, c->user_data);
					if (reply_list)
						g_strfreev(reply_list);
				}
				break;
						
	case RESP_S: {
					char* reply = NULL;
					result = dbus_g_proxy_end_call (proxy, call, &error, G_TYPE_STRING,
                                                &reply, G_TYPE_INVALID);
					if (result)
                        c->_notify_callback(c->req, error, reply, c->user_data);
					//else
					//	c->_notify_callback(c->req, error, reply, c->user_data);
					if (reply)
						g_free(reply);
				}
				break;				
	}

	if (result == FALSE) {
		if (!error)
			error = NEWERROR(-1, "Failed to get value from previous request: Unknown error\n");
		c->_notify_callback(c->req, error, NULL, c->user_data);
		g_clear_error(&error);
	}	
	
	if (error)
		g_clear_error(&error);
}


GError* crawler_bus_reqcCall_verifArg(TCrawlerReq* req, char* method_call)
{
    if (!req)
        return NEWERROR(-1, "Request/proxy not available to %s service", "Unknown");

    if (!(req->proxy))
        return NEWERROR(-1, "Request/proxy not available to %s service", req->svc_name);

    if (!method_call)
        return NEWERROR(-1, "Methode not available to %s service", req->svc_name);

	return NULL;
}

/**
 * if _notify_callback == NULL: no reply
 * timeout = -1: infinite
 */
GError* crawler_bus_reqcCall_Send_s_as(TCrawlerReq* req, char* method_call, int timeout,
        void (*_notify_callback)(TCrawlerReq* req, GError* error, char** msgReceived, void *user_data),
        void *user_data, char* dataToSend)
{
    DBusGProxyCall *call = NULL;
    TCrawlerBusCmdCall* c = NULL;
	GError* error = NULL;

	error = crawler_bus_reqcCall_verifArg(req, method_call);
	if (error) return error;

	if (_notify_callback == NULL) {
        dbus_g_proxy_call_no_reply(
                req->proxy,
                method_call, /* data to send */

                /* parameter */
                G_TYPE_STRING, dataToSend,
                G_TYPE_INVALID);

	} else {
		c = g_new0 (TCrawlerBusCmdCall, 1);
    	CRAWLER_BUSCMD_SAVEUSERDATA(c, req, RESP_AS, user_data, _notify_callback);

	    call = dbus_g_proxy_begin_call_with_timeout(
				req->proxy,
                method_call, /* data to send */
                reply__nc, c,     /* callback for reply, user_data pass for it*/
                g_free,     /* function free for user_data */
                timeout,    /* timeout in ms */

                /* parameter */
				G_TYPE_STRING, dataToSend, 
				G_TYPE_INVALID);
	}

	/* Same object will be passed to callback, we can discard it. */
	(void) call;

    return NULL;
}


/**
 * w
 * if _notify_callback == NULL: no reply
 * timeout = -1: infinite
 */
GError* crawler_bus_reqcCall_Send_s_s(TCrawlerReq* req, char* method_call, int timeout,
        void (*_notify_callback)(TCrawlerReq* req, GError* error, char* msgReceived, void *user_data),
        void *user_data, char* dataToSend)
{
    DBusGProxyCall *call = NULL;
    TCrawlerBusCmdCall* c = NULL;
    GError* error = NULL;

    error = crawler_bus_reqcCall_verifArg(req, method_call);
    if (error) return error;

	if (!_notify_callback) {
		dbus_g_proxy_call_no_reply(
                req->proxy,
                method_call, /* data to send */

                /* parameter */
                G_TYPE_STRING, dataToSend,
                G_TYPE_INVALID);

	} else {
	    c = g_new0 (TCrawlerBusCmdCall, 1);
    	CRAWLER_BUSCMD_SAVEUSERDATA(c, req, RESP_S, user_data, _notify_callback);

	    call = dbus_g_proxy_begin_call_with_timeout(
                req->proxy,
                method_call, /* data to send */
                reply__nc, c,     /* callback for reply, user_data pass for it*/
                g_free,     /* function free for user_data */
                timeout,    /* timeout in ms */

                /* parameter */
                G_TYPE_STRING, dataToSend,
                G_TYPE_INVALID);
	}

	(void) call;

    return NULL;
}


/**
 * if _notify_callback == NULL: no reply
 * timeout = -1: infinite
 */
GError* crawler_bus_reqcCall_Send_ss_s(TCrawlerReq* req, char* method_call, int timeout,
        void (*_notify_callback)(TCrawlerReq* req, GError* error, char* msgReceived, void *user_data),
        void *user_data, char* dataToSend1, char* dataToSend2)
{
    DBusGProxyCall *call = NULL;
    TCrawlerBusCmdCall* c = NULL;
    GError* error = NULL;

    error = crawler_bus_reqcCall_verifArg(req, method_call);
    if (error) return error;

	if (!_notify_callback) {
		dbus_g_proxy_call_no_reply(
				req->proxy,
				method_call,

	            /* parameter */
		        G_TYPE_STRING, dataToSend1,
			    G_TYPE_STRING, dataToSend2,
				G_TYPE_INVALID);

	} else {
	    c = g_new0 (TCrawlerBusCmdCall, 1);
	    CRAWLER_BUSCMD_SAVEUSERDATA(c, req, RESP_S, user_data, _notify_callback);

	    call = dbus_g_proxy_begin_call_with_timeout(
	            req->proxy,
		        method_call,  /* data to send */
			    reply__nc, c, /* callback for reply, user_data pass for it*/
				g_free,       /* function free for user_data */
				timeout,      /* timeout in ms */

                /* parameter */
				G_TYPE_STRING, dataToSend1,
				G_TYPE_STRING, dataToSend2,
			    G_TYPE_INVALID);
	}

	(void) call;

    return NULL;
}



/**
 *  * if _notify_callback == NULL: no reply
 *   * timeout = -1: infinite
 *    */
GError* crawler_bus_reqcCall_Send_sss_s(TCrawlerReq* req, char* method_call, int timeout,
        void (*_notify_callback)(TCrawlerReq* req, GError* error, char* msgReceived, void *user_data),
        void *user_data, char* dataToSend1, char* dataToSend2, char* dataToSend3)
{
    DBusGProxyCall *call = NULL;
    TCrawlerBusCmdCall* c = NULL;
    GError* error = NULL;

    error = crawler_bus_reqcCall_verifArg(req, method_call);
    if (error) return error;

    if (!_notify_callback) {
        dbus_g_proxy_call_no_reply(
                req->proxy,
                method_call,

                /* parameter */
                G_TYPE_STRING, dataToSend1,
                G_TYPE_STRING, dataToSend2,
				G_TYPE_STRING, dataToSend3,
                G_TYPE_INVALID);


    } else {
        c = g_new0 (TCrawlerBusCmdCall, 1);
        CRAWLER_BUSCMD_SAVEUSERDATA(c, req, RESP_S, user_data, _notify_callback);

        call = dbus_g_proxy_begin_call_with_timeout(
                req->proxy,
                method_call, /* data to send */
                reply__nc, c,     /* callback for reply, user_data pass for it*/
                g_free,     /* function free for user_data */
                timeout,    /* timeout in ms */

                /* parameter */
                G_TYPE_STRING, dataToSend1,
                G_TYPE_STRING, dataToSend2,
				G_TYPE_STRING, dataToSend3,
                G_TYPE_INVALID);

    }

	(void) call;

    return NULL;
}





/**
 * if _notify_callback == NULL: no reply
 * timeout = -1: infinite
 */
GError* crawler_bus_reqcCall_Send_ts_s(TCrawlerReq* req, char* method_call, int timeout,
        void (*_notify_callback)(TCrawlerReq* req, GError* error, char* msgReceived, void *user_data),
        void *user_data, guint64 dataToSend1, char* dataToSend2)
{
	DBusGProxyCall *call = NULL;
	TCrawlerBusCmdCall* c = NULL;
	GError* error = NULL;

	error = crawler_bus_reqcCall_verifArg(req, method_call);
	if (error) return error;

	if (!_notify_callback) {
		dbus_g_proxy_call_no_reply(
				req->proxy,
				method_call,

				/* parameter */
				G_TYPE_UINT64, dataToSend1,
				G_TYPE_STRING, dataToSend2,
				G_TYPE_INVALID);


	} else {
		c = g_new0 (TCrawlerBusCmdCall, 1);
		CRAWLER_BUSCMD_SAVEUSERDATA(c, req, RESP_S, user_data, _notify_callback);

		call = dbus_g_proxy_begin_call_with_timeout(
				req->proxy,
				method_call, /* data to send */
				reply__nc, c,     /* callback for reply, user_data pass for it*/
				g_free,     /* function free for user_data */
				timeout,    /* timeout in ms */

				/* parameter */
				G_TYPE_UINT64, dataToSend1,
				G_TYPE_STRING, dataToSend2,
				G_TYPE_INVALID);
	}

	(void) call;

	return NULL;
}




/**************************************************************************/
/* Generic Signal management                                              */
/**************************************************************************/



static void reply_sig_cb (DBusGProxy *proxy, const char* message, gpointer user_data)
{
	(void) proxy;
	(void) message;
	(void) user_data;
//	TCrawlerBusCmdSig* signal = (TCrawlerBusCmdSig*) user_data;

//	if (signal->_notify_callback)
//		signal->_notify_callback(signal->req, message, signal->user_data);

//	printf("message=%s\n",  message);
	printf("coucou de %s\n", __FUNCTION__);

	
}


GError* crawler_bus_reqSig_OpenInputQueue(TCrawlerReq* req, const char *signal_name, void *user_data)
{
	TCrawlerBusCmdSig* sig = NULL;

	// signal with one argument string (notification callback
	dbus_g_proxy_add_signal(req->proxy, signal_name, G_TYPE_STRING, G_TYPE_INVALID);
//	 dbus_g_proxy_add_signal(req->proxy, "atos-grid-Crawler-Comm-Action-end_signal_for_test",
//		G_TYPE_STRING, G_TYPE_INVALID);


	sig = g_new0(TCrawlerBusCmdSig, 1);
	sig->req = req;
	sig->user_data = user_data;
	sig->_notify_callback = NULL;

	dbus_g_proxy_connect_signal(req->proxy, signal_name,
                            G_CALLBACK(reply_sig_cb), sig, NULL); 

	return NULL;
}


GError* crawler_bus_reqSig_CloseInputQueue(TCrawlerReq* req, const char *signal_name)
{
	dbus_g_proxy_disconnect_signal(req->proxy, signal_name, G_CALLBACK(reply_sig_cb), NULL);

	return NULL;
}



GError* crawler_bus_reqSig_SendMsg(TCrawlerReq* req, gboolean broadcast, 
		char* service_path, char* service_iface, 
		const char *signal_name, const char* signal_data, void *data)
{
	(void) data;
    DBusMessage *msg = NULL;
    msg = dbus_message_new_signal(service_path, service_iface, signal_name);
	if (!msg) 
		return NEWERROR(-1, "Failed to init msg: Unknown error\n");

	if (signal_data) {
		dbus_message_append_args(msg, DBUS_TYPE_STRING, &signal_data, DBUS_TYPE_INVALID);
	} else {
		static char* tmp = "";
		dbus_message_append_args(msg, DBUS_TYPE_STRING, &tmp, DBUS_TYPE_INVALID);
	}

	
	if (broadcast == FALSE) {
		//unicast
		dbus_g_proxy_send(req->proxy, msg, NULL);

	} else {
	    // broadcast
		if (!dbus_connection_send((DBusConnection*)dbus_g_connection_get_connection(req->handle->conn),
                                msg, NULL)) {
			dbus_message_unref(msg);
			return NEWERROR(-1, "Failed to send msg to %s on %s", service_path, service_iface);
 		}
    }

 
    dbus_message_unref(msg);

	return NULL;
}







