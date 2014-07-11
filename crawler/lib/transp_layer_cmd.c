#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "atos.grid.crawler.crawler_bus"
#endif //G_LOG_DOMAIN

#include <glib-object.h>

#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>


#include <glib-object.h>
#include "../../metautils/lib/metautils.h"

#include "transp_layer.h"
#include "transp_layer_cmd.h"




/**************************************************************************/
/* Constants                                                              */
/**************************************************************************/

// method to send
#define CRAWLER_BUSCMD_CMD           "command"
#define CRAWLER_BUSCMD_SENDDATA      "setDataTripEx"
#define CRAWLER_BUSCMD_ACK           "ack"



/**************************************************************************/
/* MACRO                                                                  */
/**************************************************************************/


/**************************************************************************/
/* common generic function                                                */
/**************************************************************************/
/**
 *
 * bus_address = NULL: used DBUS_SYSTEM bus,
 * else example: ddress = "unix:abstract=/tmp/dbus-CRqd8gz6o7"
 *
 */
GError* tlc_init_connection(TCrawlerBus** conn, char* service_name, char* service_path,
                    char* bus_address, TCrawlerBusObjectInfo* object_info)
{
    GError* error = crawler_bus_Open(conn, bus_address);
    if (error){
        g_prefix_error(&error, "Failed to open connection to %s: ", bus_address);
        return error;
    }

    error = crawler_bus_Register(*conn, service_name, service_path, object_info);
    if (error) {
       g_prefix_error(&error, "Failed to register object %s to %s: ", 
								service_path, bus_address);
       return error;
    }


    return NULL;
}







/**************************************************************************/
/* Request ASYNC: send request and return imediately                      */
/*                 other function for read response                       */
/**************************************************************************/


/**
 * if _notify_callback == NULL: no reply
 * else timeout = -1: infinite
 */
GError* tlc_Send_CmdProc(TCrawlerReq* req, int timeout,
        void (*_notify_callback)(TCrawlerReq* req, GError* error, char* msgReceived, void *user_data),
        void *user_data, char* cmd, char* alldata)
{
    return crawler_bus_reqcCall_Send_ss_s(req, CRAWLER_BUSCMD_CMD, timeout,
   	                _notify_callback, user_data, cmd, alldata);
}


GError* tlc_Send_CmdProcEx(TCrawlerReq* req, int timeout,
        void (*_notify_callback)(TCrawlerReq* req, GError* error, char* msgReceived, void *user_data),
        void *user_data, char* cmd, const char* sender, char* alldata)
{
    return crawler_bus_reqcCall_Send_sss_s(req, CRAWLER_BUSCMD_CMD, timeout,
                    _notify_callback, user_data, cmd, (char*)sender, alldata);
}



GError* tlc_Send_DataTripEx_noreply(TCrawlerReq* req, void *user_data, char* addSender, char* alldata)
{
    return crawler_bus_reqcCall_Send_ss_s(req, CRAWLER_BUSCMD_SENDDATA, 0,
                    NULL, user_data, addSender, alldata);
}


GError* tlc_Send_Ack_noreply(TCrawlerReq* req, void *user_data, char* cmd, char* alldata)
{
    return crawler_bus_reqcCall_Send_ss_s(req, CRAWLER_BUSCMD_ACK, 0,
                    NULL, user_data, cmd, alldata);
}




