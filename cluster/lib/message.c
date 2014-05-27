#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.lib"
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <metautils/lib/metautils.h>

#include "connect.h"
#include "message.h"

#define CONNECT_TIMEOUT 5000
#define SOCKET_TIMEOUT 5000

static void message_clean (message_t *msg) {
	if (!msg)
		return;
	if (msg->data)
		g_free( msg->data);
	memset( msg, 0x00, sizeof(message_t));
}

int read_response_from_message(response_t *response, message_t *message, GError **error) {
	guint32 status;

	/* Test message length which should contain at least the status code */
	if (message->length < sizeof(status)) {
		GSETERROR(error, "Message to short to contain a gridagent response");
		return(0);
	}
	
	/* read status */
	memcpy(&status, message->data, sizeof(status));
	response->status = status;

	/* read data */
	if (message->length > sizeof(status)) {
		response->data = g_try_malloc0(message->length - sizeof(status));
		if (response->data == NULL) {
			GSETERROR(error, "Memory allocation failure");
			return(0);
		}

		response->data_size = message->length - sizeof(status);
		memcpy(response->data, message->data + sizeof(status), message->length - sizeof(status));
	}
		
	
	return(1);
}

int
build_message_from_request(message_t * message, request_t * request, GError ** error)
{
	GByteArray *req_gba;

	(void) error;

	req_gba = g_byte_array_new();
	g_byte_array_append(req_gba, (const guint8*)request->cmd, strlen(request->cmd));
	g_byte_array_append(req_gba, (const guint8*)" ", 1);

	if (request->arg) {
		g_byte_array_append(req_gba, (const guint8*)request->arg,
		    (request->arg_size > 0) ? request->arg_size : strlen(request->arg));
	}

	message->data = req_gba->data;
	message->length = req_gba->len;
	g_byte_array_free(req_gba, FALSE);
	return (1);
}

int send_request(request_t *req, response_t *resp, GError **error) {
	int fd;
	size_t size_to_send, u_size_sent, u_size_read;
	gint size_sent, size_read;
	message_t message;
	void *buff = NULL;

	memset(&message, 0, sizeof(message_t));

       if (!build_message_from_request(&message, req, error)) {
                GSETERROR(error, "Failed to build message");
                return(0);
        }

        if (!connect_socket(&fd, error)) {
                GSETERROR(error, "Connection to agent failed");
                goto error_connect;
        }

        size_to_send = message.length + sizeof(message.length);
        buff = g_try_malloc0(size_to_send);
        if (buff == NULL) {
                GSETERROR(error, "Memory allocation failure");
                goto error_alloc_buff;
        }

        memcpy(buff, &(message.length), sizeof(message.length));
        memcpy(buff + sizeof(message.length), message.data, message.length);

	size_sent = sock_to_write(fd, CONNECT_TIMEOUT, buff, size_to_send, error);
	if (size_sent<0) {
                GSETERROR(error, "Failed to send all data to agent");
                goto error_write;
	}
        if ((u_size_sent=size_sent) < size_to_send) {
                GSETERROR(error, "Failed to send all data to agent");
                goto error_write;
        }

        /* Clean message to reuse it */
	message_clean( &message);
	size_read = sock_to_read_size(fd, SOCKET_TIMEOUT, &(message.length), sizeof(message.length), error);
        if ((u_size_read=size_read) < sizeof(message.length)) {
                GSETERROR(error, "Failed to read message size");
                goto error_read_size;
        }

        message.data = g_try_malloc0(message.length);
        if (message.data == NULL) {
                GSETERROR(error, "Memory allocation failure");
                goto error_alloc_data;
        }

	size_read = sock_to_read_size(fd, SOCKET_TIMEOUT, message.data, message.length, error);
        if ((u_size_read=size_read) < message.length) {
                GSETERROR(error, "Failed to read all data from agent");
                goto error_read;
        }

        if (!read_response_from_message(resp, &message, error)) {
                GSETERROR(error, "Failed to extract response from message");
                goto error_read_resp;
        }
	
	metautils_pclose(&fd);

	g_free(buff);

	message_clean( &message);
	return(1);

error_read_resp:
error_read:
error_alloc_data:
error_read_size:
error_write:
	if (buff)
		g_free(buff);
error_alloc_buff:
	metautils_pclose(&fd);
error_connect:
	message_clean( &message);
	return(0);
}

