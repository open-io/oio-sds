#ifndef _RAINX_HTTP_TOOLS_H_
#define _RAINX_HTTP_TOOLS_H_

#include <mod_dav.h>

#include <rainx/rainx_repository.h>

#define MAX_REPLY_HEADER_SIZE 8192
#define REPLY_BUFFER_SIZE 131072
#define REQUEST_BUFFER_SIZE 131072

/*
 * Sends a request to a rawx.
 *
 * stream : The stream to get the APR pool from
 * remote_url : The remote Rawx full URL with the content hexid (ip:port/hexid)
 * req_type : The type of the request (PUT/GET/DELETE)
 * data : The data to send (nullable)
 * data_length : The length of the data
 * reply : The response from the Rawx (nullable)
 *
 * Returns : The APR status
 **/
apr_status_t
rainx_http_req(struct req_params_store* rps);

#endif /* _RAINX_HTTP_TOOLS_H_ */
