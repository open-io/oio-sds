#ifndef __CRAWLER_BUS_H
#define __CRAWLER_BUS_H



#include <dbus/dbus-glib.h>



typedef struct TCrawlerBus TCrawlerBus;
typedef struct TCrawlerReq TCrawlerReq;

typedef struct TCrawlerBusObject TCrawlerBusObject;
typedef struct TCrawlerBusObjectClass TCrawlerBusObjectClass;

#define TCrawlerBusObjectInfo DBusGObjectInfo



/**
 * \brief init a connection to the bus
 * \param[in] address =NULL: used local DBUS_BUS_SYSTEM, else local session
 *                          ex: address = "unix:abstract=/tmp/dbus-YMpX7o46oJ"
 * \param[out] handle id connection
 * \return the errors if error occurs, else =NULL
 */
GError* crawler_bus_Open(TCrawlerBus **handle, gchar* address);


/**
 * \brief close opnened connection
 * \param[in] handle connection to close
 * \return the errors if error occurs, else =NULL
 */
GError* crawler_bus_Close(TCrawlerBus **handle);

/**
 * \brief register an object (with interface/methods) to the bus
 * \param[in] handle connection to used
 * \param[in] service_name service name of new object
 * \param[in] service_path service path, ex: "/atos/grid/Crawler"
 * \param[in] object_info object info see DBus-glob spec
 * \return the errors if error occurs, else =NULL
 */
GError* crawler_bus_Register(TCrawlerBus *handle, char* service_name, char* service_path,
            const TCrawlerBusObjectInfo* object_info);


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
 *              "org.freedesktop.DBus", "/freedesktop/DBus", "org.freedesktop.DBus");
 */
GError* crawler_bus_req_init(TCrawlerBus *handle, TCrawlerReq** req,
    const char *name, const char *path, const char *iface);


/**
 * \brief close and clrear a request
 * \param[in] req request to close 
 */
void crawler_bus_req_clear(TCrawlerReq** req);



GError* crawler_bus_flush(TCrawlerBus *handle);


GError* crawler_bus_req_Send_ss_s(TCrawlerReq* req, char* method, int timeout, 
                      char* dataToSend1, char* dataToSend2, char** dataToreceiv);



/************************************************************************
* Request to org.freedesktop.DBus                                        
* SYNC methods                                                           
*************************************************************************/
/**
 * \brief init request obscure stucture
 * \param[in] handle connection to used
 * \param[out] req   request to initialize
 * \return the errors if error occurs, else =NULL
 */
GError* crawler_bus_reqBase_init(TCrawlerBus *handle, TCrawlerReq** req);


/**
 * \brief register a name and publish all methods to bus
 * \param[in] req   request to  to used
 * \param[in] name the destination/service name
 * \return the errors if error occurs, else =NULL
 */
GError* crawler_bus_reqBase_RegisterName(TCrawlerReq* req, const char *name);

/**
 * \brief verif if a name exist on bus
 * \param[in] req   request to  to used
 * \param[in] name the destination/service name
 * \param[out] name_exist =TRUE if name already exist on bus
 * \return the errors if error occurs, else =NULL
*/
GError* crawler_bus_reqBase_IsNameExists(TCrawlerReq* req, const char *name, gboolean* name_exist);


/**
 * \brief Get all service name connected on the same bus
 * \param[in] req   request to  to used
 * \param[out] listnames  servicename list altualy conntected
 * \return the errors if error occurs, else =NULL
 */
GError* crawler_bus_reqBase_GetListNames(TCrawlerReq* req, char*** listnames);


/**************************************************************************/
/* Request ASYNC: send request and return imediately                      */
/*                 other function for read response                       */
/**************************************************************************/

GError* crawler_bus_reqCall_Send_s_as(TCrawlerReq* req, char* method_call, int timeout,
        void (*_notify_callback)(TCrawlerReq* req, GError* error, char** msgReceived, void *user_data),
        void *user_data, char* dataToSend);

GError* crawler_bus_reqcCall_Send_ss_s(TCrawlerReq* req, char* method_call, int timeout,
        void (*_notify_callback)(TCrawlerReq* req, GError* error, char* msgReceived, void *user_data),
        void *user_data, char* dataToSend1, char* dataToSend2);

GError* crawler_bus_reqcCall_Send_sss_s(TCrawlerReq* req, char* method_call, int timeout,
        void (*_notify_callback)(TCrawlerReq* req, GError* error, char* msgReceived, void *user_data),
        void *user_data, char* dataToSend1, char* dataToSend2, char* dataToSend3);

GError* crawler_bus_reqcCall_Send_ts_s(TCrawlerReq* req, char* method_call, int timeout,
        void (*_notify_callback)(TCrawlerReq* req, GError* error, char* msgReceived, void *user_data),
        void *user_data, guint64 dataToSend1, char* dataToSend2);

GError* crawler_bus_reqcCall_Send_s_as(TCrawlerReq* req, char* method_call, int timeout,
        void (*_notify_callback)(TCrawlerReq* req, GError* error, char** msgReceived, void *user_data),
        void *user_data, char* dataToSend);


/**************************************************************************/
/* Generic Signal management                                              */
/**************************************************************************/

GError* crawler_bus_reqSig_OpenInputQueue(TCrawlerReq* req, const char *signal_name, void *user_data);
GError* crawler_bus_reqSig_CloseInputQueue(TCrawlerReq* req, const char *signal_name);

GError* crawler_bus_reqSig_SendMsg(TCrawlerReq* req, gboolean broadcast,
		char* service_path, char* service_iface, 
		const char *signal_name, const char* signal_data, void *data);


#endif   //__CRAWLER_BUS_H



