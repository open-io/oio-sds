#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.agent.http_request_worker"
#endif

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <metautils/lib/metautils.h>

#include "./http_request_worker.h"
#include "./io_scheduler.h"

#define HTTP_REQ_MAX_SIZE 256
#define DEFAULT_BUFFER_SIZE 256
#define EOL "\r\n"
#define HTTP_STATUS_PATTERN "HTTP/1.0 %u"
#define HTTP_STATUS_OK 200
#define CONTENT_LENGTH_PATTERN "Content-Length: %u"

static int write_request(worker_t *worker, GError **error);
static int read_http_status(worker_t *worker, GError **error);
static int read_content_length(worker_t *worker, GError **error);
static int read_response_body(worker_t *worker, GError **error);

int
http_request_worker(worker_t *worker, GError **error)
{
	int fd;
	worker_data_t *data = NULL;
	http_session_t *http_session = NULL;

	TRACE("Executing http_request worker");

	data = &(worker->data);
	http_session = (http_session_t*)data->session;

	if (0 > (fd = addrinfo_connect_nopoll(http_session->addr, 1000, error))) {
		GSETERROR(error, "Connection to HTTP server failed");
		goto error;
	}

	worker->func = write_request;
	worker->data.fd = fd;

	if (!add_fd_to_io_scheduler(worker, EPOLLOUT, error)) {
		GSETERROR(error, "Failed to add socket to io_scheduler");
		goto error;
	}

	return(1);

error:
	return(0);
}

int write_request(worker_t *worker, GError **error) {
	ssize_t wl;
	worker_data_t *data = NULL;
	http_session_t *http_session;
	char request[HTTP_REQ_MAX_SIZE];

	TRACE("Executing write_request worker");

        data = &(worker->data);
	http_session = (http_session_t*)data->session;
	memset(request, '\0', HTTP_REQ_MAX_SIZE);

        if (data->buffer == NULL) {
		switch (http_session->method) {
			case E_GET :
				snprintf(request, HTTP_REQ_MAX_SIZE, "GET %s HTTP/1.0%s%s", http_session->url, EOL, EOL);
				break;
			case E_POST :
				break;
			default :
				break;
		}

		DEBUG("Sending HTTP request [%s]", request);

                data->buffer_size = strlen(request);

                data->buffer = g_try_malloc0(data->buffer_size);
                if (data->buffer == NULL) {
                        GSETERROR(error, "Memory allocation failure");
                        goto error_alloc_buffer;
                }

		memcpy(data->buffer, request, data->buffer_size);
	}

        wl = write(data->fd, data->buffer + data->done, data->buffer_size - data->done);
        if (wl < 0) {
                GSETERROR(error, "Write on socket failed with error : %s", strerror(errno));
                goto error_write;
        }

        data->done += wl;

        if (data->done >= data->buffer_size) {

                g_free(data->buffer);
                data->buffer = NULL;
                data->buffer_size = 0;
                data->done = 0;

                /* Schedule next worker */
                worker->func = read_http_status;

                if (!change_fd_events_in_io_scheduler(worker, EPOLLIN, error)) {
                        GSETERROR(error, "Failed to change polling event on fd %d", data->fd);
                        goto error_sched;
                }
        }

        return(1);

error_sched:
error_write:
        g_free(data->buffer);
error_alloc_buffer:

        return(http_session->error_handler(worker, error));
}

int read_http_status(worker_t *worker, GError **error) {
        ssize_t rl;
        worker_data_t *data = NULL;
	http_session_t *http_session = NULL;
        unsigned int http_status;

        TRACE("Executing read_http_status worker");

        data = &(worker->data);
	http_session = (http_session_t*)data->session;

        if (data->buffer == NULL) {
                data->buffer_size = DEFAULT_BUFFER_SIZE;
                data->buffer = g_try_malloc0(data->buffer_size+1);      /* Allocate 1 byte for \0 */
                if (data->buffer == NULL) {
                        GSETERROR(error, "Memory allocation failure");
                        goto error_alloc_buffer;
                }
        } else if (data->done >= data->buffer_size) {
                data->buffer_size += DEFAULT_BUFFER_SIZE;
                data->buffer = g_try_realloc(data->buffer, data->buffer_size+1); /* Allocate 1 byte for \0 */
                if (data->buffer == NULL) {
                        GSETERROR(error, "Memory allocation failure");
                        goto error_alloc_buffer;
                } else {
                        /* Init newly alloced memory */
                        memset(data->buffer + (data->buffer_size - DEFAULT_BUFFER_SIZE), 0, DEFAULT_BUFFER_SIZE + 1);
                }
        }

        rl = read(data->fd, data->buffer + data->done, data->buffer_size - data->done);
        if (rl < 0) {
                GSETERROR(error, "Read on socket failed with error : %s", strerror(errno));
                goto error_read;
        }

        data->done += rl;

        /* Make sure we read the first line completely */
        if (strstr((char*)data->buffer, EOL)) {
                if (sscanf((char*)data->buffer, HTTP_STATUS_PATTERN, &http_status) == 1) {
                        DEBUG("Found HTTP status %u", http_status);

                        if (http_status == HTTP_STATUS_OK) {
                                worker->func = read_content_length;

                        } else {
                                GSETERROR(error, "HTTP request failed with status %d", http_status);
				goto error_status;
                        }

                } else {
                        GSETERROR(error, "Failed to read HTTP status");
			goto error_status;
                }
        } else if (rl == 0) {
                GSETERROR(error, "Connection closed while reading HTTP status");
                goto error_read;
        }

        return(1);

error_read:
error_status:
        g_free(data->buffer);
error_alloc_buffer:

        return(http_session->error_handler(worker, error));
}

int read_content_length(worker_t *worker, GError **error) {
        ssize_t rl;
        worker_data_t *data = NULL;
        http_session_t *http_session = NULL;
        unsigned int content_length;
        char *header_end = NULL;
        char *content_length_line = NULL;
        char *buffer = NULL;

        TRACE("Executing read_content_length worker");

        data = &(worker->data);
        http_session = (http_session_t*)data->session;
        header_end = strstr(data->buffer, "\r\n\r\n");
        content_length_line = strstr(data->buffer, "Content-Length");

        if (content_length_line && header_end) {

                if (sscanf(content_length_line, CONTENT_LENGTH_PATTERN, &content_length) == 1) {
                        DEBUG("Found a Content-Length header with value %u", content_length);

                        /* Prepare the buffer */
                        buffer = g_strdup(header_end + 4);
                        CLEAR_WORKER_DATA(data);

                        data->buffer_size = content_length;
                        data->buffer = g_try_malloc0(data->buffer_size+1);
                        if (data->buffer == NULL) {
                                GSETERROR(error, "Memory allocation failure");
                                g_free(buffer);
                                goto error_alloc_buffer;
                        }

                        strcpy(data->buffer, buffer);
                        data->done = strlen(buffer);

                        g_free(buffer);

                        worker->func = read_response_body;

                        return(1);
                }

        } else if (header_end) {
                GSETERROR(error, "Header Content-Length was not found in headers");
                goto error_content_length_not_found;
        }

        if (data->done >= data->buffer_size) {
                data->buffer_size += DEFAULT_BUFFER_SIZE;
                data->buffer = g_try_realloc(data->buffer, data->buffer_size+1); /* Allocate 1 byte for \0 */
                if (data->buffer == NULL) {
                        GSETERROR(error, "Memory allocation failure");
                        goto error_alloc_buffer;
                } else {
                        /* Init newly alloced memory */
                        memset(data->buffer + (data->buffer_size - DEFAULT_BUFFER_SIZE), 0, DEFAULT_BUFFER_SIZE + 1);
                }
        }

        rl = read(data->fd, data->buffer + data->done, data->buffer_size - data->done);
        if (rl < 0) {
                GSETERROR(error, "Read on socket failed with error : %s", strerror(errno));
                goto error_read;
        }

        if (rl == 0 && data->done < data->buffer_size) {
                GSETERROR(error, "Connection closed while reading Content-Length");
                goto error_read;
        }

        data->done += rl;

        return(1);

error_content_length_not_found:
error_read:
        g_free(data->buffer);
error_alloc_buffer:

        return(http_session->error_handler(worker, error));
}

int read_response_body(worker_t *worker, GError **error) {
        ssize_t rl;
        worker_data_t *data = NULL;
        http_session_t *http_session = NULL;

        TRACE("Executing read_response_body worker");

        data = &(worker->data);
        http_session = (http_session_t*)data->session;

        if (data->done >= data->buffer_size) {  /* All content was read */

		http_session->body = g_strndup(data->buffer, data->buffer_size);

		DEBUG("HTTP response body : [%s]", http_session->body);

                /* Remove fd from sched to close connection */
                remove_fd_from_io_scheduler(worker, error);

                /* Clean data */
                CLEAR_WORKER_DATA(data);

		return(http_session->response_handler(worker, error));

        } else {

                rl = read(data->fd, data->buffer + data->done, data->buffer_size - data->done);
                if (rl < 0) {
                        GSETERROR(error, "Read on socket failed with error : %s", strerror(errno));
                        goto error_read;
                }

                if (rl == 0 && data->done < data->buffer_size) {
                        GSETERROR(error, "Connection closed while parsing rawx status");
                        goto error_read;
                }

                data->done += rl;
        }

	return(1);

error_read:

        return(http_session->error_handler(worker, error));
}
