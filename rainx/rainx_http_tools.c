#include "rainx_internals.h"
#include "rainx_http_tools.h"
#include "rainx_repository.h"

apr_status_t
rainx_http_req(struct req_params_store* rps) {
	const dav_resource* resource = rps->resource;
	char* remote_uri = rps->service_address;
	char* req_type = rps->req_type;
	char* header = rps->header;
	char* data = rps->data_to_send;
	int data_length = rps->data_to_send_size;
	char** reply = &(rps->reply);
	apr_pool_t *local_pool = rps->pool;
	dav_rainx_server_conf *server_conf = resource_get_server_config(resource);

	if (NULL == resource || NULL == remote_uri ||
			NULL == req_type || NULL == server_conf) {
		DAV_ERROR_POOL(local_pool, APR_EINVAL, "One of these params is wrong: "
				"remote_uri=%p, req_type=%p, server_conf=%p"
				" (__FILE__:__LINE__)",
				remote_uri, req_type, server_conf);
		return APR_EINVAL;
	}

	const gboolean is_get = (0 == g_strcmp0(req_type, "GET"));

	/* Isolating Rawx IP and port */
	char *temp_remote_uri = apr_pstrdup(local_pool, remote_uri);
	char* last;
	char* full_remote_url = apr_strtok(temp_remote_uri, "/", &last);
	char* content_hexid = apr_pstrdup(local_pool, remote_uri + strlen(full_remote_url));

	char* remote_ip = NULL;
	char* scope_id = NULL;
	apr_port_t remote_port;
	apr_parse_addr_port(&remote_ip, &scope_id, &remote_port, full_remote_url, local_pool);
	/* ------- */

	/* Preparing the socket */
	apr_socket_t* sock;
	apr_sockaddr_t* sockaddr;
	apr_status_t status;

	if ((status = apr_sockaddr_info_get(&sockaddr, remote_ip, APR_INET, remote_port, 0, local_pool)) != APR_SUCCESS) {
		DAV_DEBUG_REQ(resource->info->request, 0, "unable to connect to the rawx %s", full_remote_url);
		return status;
	}

	if ((status = apr_socket_create(&sock, sockaddr->family, SOCK_STREAM, APR_PROTO_TCP, local_pool)) != APR_SUCCESS) {
		DAV_DEBUG_REQ(resource->info->request, 0, "unable to create a socket to the rawx %s", full_remote_url);
		return status;
	}

	if ((status = apr_socket_timeout_set(sock, server_conf->socket_timeout)) != APR_SUCCESS) {
		DAV_DEBUG_REQ(resource->info->request, 0, "unable to set timeout for the socket to the rawx %s", full_remote_url);
		return status;
	}

	if ((status = apr_socket_connect(sock, sockaddr)) != APR_SUCCESS) {
		DAV_DEBUG_REQ(resource->info->request, 0, "unable to establish the connection to the rawx %s", full_remote_url);
		return status;
	}
	/* ------- */

	/* Forging the message */
	char* forged_header = apr_psprintf(local_pool, "%s %s HTTP/1.1\nHost: %s", req_type, content_hexid, full_remote_url);
	if (header)
		forged_header = apr_psprintf(local_pool, "%s\n%s", forged_header, header);
	if (data)
		forged_header = apr_psprintf(local_pool, "%s\nContent-Length: %d\n\n", forged_header, data_length);
	else
		forged_header = apr_psprintf(local_pool, "%s\n\n", forged_header);
	/* ------- */

	/* Sending the message */
	int remaining_to_send = strlen(forged_header);
	char* ptr_start = forged_header;
	apr_size_t send_buffer_size;
	while (remaining_to_send > 0) {
		if (remaining_to_send < REQUEST_BUFFER_SIZE)
			send_buffer_size = (apr_size_t)remaining_to_send;
		else
			send_buffer_size = REQUEST_BUFFER_SIZE;

		if ((status = apr_socket_send(sock, ptr_start, &send_buffer_size)) != APR_SUCCESS) {
            DAV_DEBUG_REQ(resource->info->request, 0, "failed to send the %s request to the rawx %s", req_type, full_remote_url);
            apr_status_t status_sav = status;
            apr_socket_close(sock);
            return status_sav;
        }

		remaining_to_send -= send_buffer_size;
		ptr_start = ptr_start + send_buffer_size;
	}
	if (NULL != data) {
		remaining_to_send = data_length;
		ptr_start = data;
		while (remaining_to_send > 0) {
			if (remaining_to_send < REQUEST_BUFFER_SIZE)
				send_buffer_size = (apr_size_t)remaining_to_send;
			else
				send_buffer_size = REQUEST_BUFFER_SIZE;

			if ((status = apr_socket_send(sock, ptr_start, &send_buffer_size)) != APR_SUCCESS) {
				DAV_DEBUG_REQ(resource->info->request, 0, "failed to send the %s request to the rawx %s", req_type, full_remote_url);
				apr_status_t status_sav = status;
				apr_socket_close(sock);
				return status_sav;
			}

			remaining_to_send -= send_buffer_size;
			ptr_start = ptr_start + send_buffer_size;
		}
	}

	DAV_DEBUG_REQ(resource->info->request, 0, "%s request to the rawx %s sent for the content %s", req_type, full_remote_url, content_hexid);
    /* ------ */

	/* Getting the reply */
	char* reply_ptr = *reply;
	apr_size_t total_size;
	if (!is_get)
		total_size = REPLY_BUFFER_SIZE; // PUT or DELETE
	else
		total_size = MAX_REPLY_HEADER_SIZE + data_length; // GET
	apr_size_t reply_size = (apr_size_t)total_size;
	apr_size_t total_replied_size;
	do {
		status = apr_socket_recv(sock, reply_ptr, &reply_size);
		reply_ptr += reply_size;
		total_replied_size = reply_ptr - *reply;
		/* Leave when OK, or error != timeout, or buffer full */
        if (status == APR_EOF || (status == APR_SUCCESS && !is_get) ||
				(reply_size == 0) ||
				total_replied_size >= total_size) {
            break;
		}
		/* Take care of overflows! */
		reply_size = total_size - total_replied_size;
	} while (total_replied_size < total_size);
	/* ------- */

	apr_socket_close(sock);

	return status;
}
