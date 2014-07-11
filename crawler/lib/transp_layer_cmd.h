#ifndef __CRAWLER_BUSCMD_H
#define __CRAWLER_BUSCMD_H






GError* tlc_init_connection(TCrawlerBus** conn, char* service_name, char* service_path,
                    char* bus_address, TCrawlerBusObjectInfo* object_info);


/*************/
/* A-SYNCHRO**/

GError* tlc_Send_DataTripEx_noreply(TCrawlerReq* req, void *user_data, char* addSender, char* alldata);

GError* tlc_Send_CmdProc(TCrawlerReq* req, int timeout,
        void (*_notify_callback)(TCrawlerReq* req, GError* error, char* msgReceived, void *user_data),
        void *user_data, char* cmd, char* alldata);


GError* tlc_Send_CmdProcEx(TCrawlerReq* req, int timeout,
        void (*_notify_callback)(TCrawlerReq* req, GError* error, char* msgReceived, void *user_data),
        void *user_data, char* cmd, const char* sender, char* alldata);

GError* tlc_Send_Ack_noreply(TCrawlerReq* req, void *user_data, char* cmd, char* alldata);


#endif   //__CRAWLER_BUSCMD_H

