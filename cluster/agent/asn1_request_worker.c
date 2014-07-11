#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "gridcluster.agent.asn1_request_worker"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <metautils/lib/metacomm.h>

#include "./asn1_request_worker.h"
#include "./config.h"
#include "./io_scheduler.h"

#define RESPONSE_SIZE_SIZE 4

static int write_request(worker_t *worker, GError **error);
static int read_response_size(worker_t *worker, GError **error);
static int read_response(worker_t *worker, GError **error);

asn1_session_t*
asn1_worker_get_session(worker_t* asn1_worker)
{
	if (!asn1_worker)
		return NULL;
	return asn1_worker->data.session;
}

void*
asn1_worker_get_session_data( worker_t *asn1_worker )
{
	asn1_session_t *asn1_session;
	
	TRACE_POSITION();
	
	asn1_session = asn1_worker_get_session(asn1_worker);
	return asn1_session ? asn1_session->session_data : NULL;
}

void
asn1_worker_set_session_data(worker_t *asn1_worker, void* data, GDestroyNotify clean)
{
	asn1_session_t *asn1_session;

	TRACE_POSITION();

	asn1_session = asn1_worker ? asn1_worker_get_session(asn1_worker) : NULL;
	if (asn1_session) {
		asn1_session->session_data = data;
		asn1_session->clear_session_data = clean;
	}
}

void
asn1_worker_set_handlers(worker_t *asn1_worker, worker_func_f response,
	worker_func_f error, worker_func_f final)
{
	asn1_session_t *asn1_session;

	TRACE_POSITION();

	if (!asn1_worker)
		return;

	asn1_session = asn1_worker_get_session(asn1_worker);
	if (response)
		asn1_session->response_handler = response;
	if (final)
		asn1_session->final_handler = final;
	if (error)
		asn1_session->error_handler = error;
}

static void
free_asn1_session( asn1_session_t *asn1_session)
{
	TRACE_POSITION();

	if (!asn1_session)
		return;

	if (asn1_session->session_data && asn1_session->clear_session_data)
		asn1_session->clear_session_data(asn1_session->session_data);

	if (asn1_session->req_headers)
		g_hash_table_destroy(asn1_session->req_headers);
	if (asn1_session->resp_headers)
		g_hash_table_destroy(asn1_session->resp_headers);
	if (asn1_session->req_body)
		g_free(asn1_session->req_body);
	if (asn1_session->addr)
		g_free(asn1_session->addr);
	if (asn1_session->req_name)
		g_free(asn1_session->req_name);

	memset( asn1_session, 0x00, sizeof(asn1_session_t));
	g_free(asn1_session);
}

static void
asn1_worker_liberator(worker_t *worker)
{
	int fd;
	
	TRACE_POSITION();

	if (!worker)
		return;

	fd = worker->data.fd;

	if (worker->clean != &asn1_worker_liberator)
		ALERT("An ASN.1 worker has a cleaner (%p) that is not asn1_worker_liberator (%p)",
			worker->clean, asn1_worker_liberator);

	free_asn1_session(asn1_worker_get_session(worker));
	CLEAR_WORKER_DATA(&(worker->data));

	/*saving the fd helps to detect more easily wich worker it was*/
	memset(worker,0x00,sizeof(worker_t));
	worker->data.fd = fd;

	remove_fd_from_io_scheduler(worker, NULL);
}

worker_t*
create_asn1_worker(addr_info_t *addr, const gchar *req_name)
{
	asn1_session_t *asn1_session;
	worker_t *asn1_worker;

	TRACE_POSITION();

	asn1_session = g_malloc0(sizeof(asn1_session_t));
	asn1_session->addr = g_memdup(addr, sizeof(addr_info_t));
        asn1_session->req_name = g_strdup(req_name);
        asn1_session->req_body_size = 0;
        asn1_session->req_body = NULL;
        asn1_session->response_handler = agent_asn1_default_response_handler;
        asn1_session->error_handler = agent_worker_default_func;
        asn1_session->final_handler = agent_worker_default_func;

	asn1_session->clear_session_data = NULL;
	asn1_session->session_data = NULL;

	asn1_session->resp_headers = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, metautils_gba_clean);
	asn1_session->req_headers = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, metautils_gba_clean);

	/*create the worker*/
        asn1_worker = g_malloc0(sizeof(worker_t));
	asn1_worker->timeout = SOCK_TIMEOUT;
	asn1_worker->clean = asn1_worker_liberator;
	asn1_worker->data.sock_timeout = SOCK_TIMEOUT;
	asn1_worker->data.session = asn1_session;
	return asn1_worker;
}

void
free_asn1_worker( worker_t *worker, int worker_too )
{
	asn1_worker_liberator( worker );
	if (worker_too)
		g_free(worker);
}


int
agent_asn1_default_response_handler(worker_t *worker, GError **error)
{
	(void)worker;
	(void)error;
	return 1;
}

void
asn1_worker_set_request_header(worker_t *asn1_worker, const char *key, const char *value)
{
	asn1_session_t *asn1_session;
	if (!key || !value || !asn1_worker)
		return;

	asn1_session = asn1_worker_get_session(asn1_worker);
	g_hash_table_insert(asn1_session->req_headers, g_strdup(key),
			g_byte_array_append(g_byte_array_new(), (const guint8*) value, strlen(value)));
}

void
asn1_worker_set_request_body(worker_t *asn1_worker, GByteArray *body)
{
	asn1_session_t *asn1_session;
	if (!body || !body->data)
		return;
	if (!asn1_worker) {
		g_free(body->data);
		return;
	}
	asn1_session = asn1_worker_get_session(asn1_worker);
	asn1_session->req_body_size = body->len;
	asn1_session->req_body = body->data;
}

void
asn1_worker_set_request_body_from_buffer(worker_t *asn1_worker, guint8 *body, gsize body_size)
{
	asn1_session_t *asn1_session;
	if (!body || !body_size)
		return;
	if (!asn1_worker) {
		g_free(body);
		return;
	}
	asn1_session = asn1_worker_get_session(asn1_worker);
	asn1_session->req_body_size = body_size;
	asn1_session->req_body = body;
}

int
asn1_request_worker(worker_t *worker, GError **error)
{
	gchar str_addr[STRLEN_ADDRINFO];
	int fd;
	asn1_session_t *asn1_session = NULL;

	TRACE_POSITION();

	asn1_session = asn1_worker_get_session(worker);
	if (!asn1_session) {
		GSETERROR(error,"Invalid worker");
		return 0;
	}

	if (0 > (fd = addrinfo_connect_nopoll(asn1_session->addr, 1000, error))) {
		GSETERROR(error, "Connection to gridd server failed");
		return 0;
	}

	sock_set_linger_default(fd);
	sock_set_nodelay(fd, TRUE);

	worker->func = write_request;
	worker->data.fd = fd;

	if (!add_fd_to_io_scheduler(worker, EPOLLOUT, error)) {
		GSETERROR(error, "Failed to add socket to io_scheduler");
		return 0;
	}

	addr_info_to_string(asn1_session->addr, str_addr, sizeof(str_addr));
	DEBUG("ASN.1 request '%s' sent to %s (fd=%d)", asn1_session->req_name, str_addr, fd);
	return(1);
}

int
write_request(worker_t *worker, GError **error)
{
	ssize_t wl;
	worker_data_t *data = NULL;
	asn1_session_t *asn1_session = NULL;
	MESSAGE req = NULL;

	TRACE_POSITION();

	data = &(worker->data);
	asn1_session = (asn1_session_t*)data->session;

        if (data->buffer == NULL) {

		if (!message_create(&req, error)) {
			GSETERROR(error, "Failed to create a new asn1 message");
			goto error_mes_create;
		}

		if (asn1_session->req_headers) {
			GList *key = NULL;
			GList *keys = g_hash_table_get_keys(asn1_session->req_headers);

			for (key = keys; key && key->data; key = key->next) {
				GByteArray *value = (GByteArray*)g_hash_table_lookup(
						asn1_session->req_headers, key->data);
				if (!message_add_field(req, key->data, strlen((char*)key->data),
							value->data, value->len, error)) {
					GSETERROR(error, "Failed to add field [%s] to message",
							(char*)key->data);
					goto error_set_headers;
				}
			}

			g_list_free(keys);
		}

		if (asn1_session->req_body && !message_set_BODY(req, asn1_session->req_body, asn1_session->req_body_size, error)) {
			GSETERROR(error, "Failed to set asn1 message body");
			goto error_set_body;
		}

		if (!message_set_NAME(req, asn1_session->req_name, strlen(asn1_session->req_name), error)) {
			GSETERROR(error, "Failed to set message name");
			goto error_set_name;
		}

		do {
			gsize ds = 0;
			if (!message_marshall(req, &(data->buffer), &ds, error)) {
				GSETERROR(error, "Failed to marshall asn1 message");
				message_destroy(req, NULL);
				goto error_marshall_message;
			}
			data->buffer_size = ds;
		} while (0);

                message_destroy(req, NULL);

        } else if (data->done >= data->buffer_size) {

                CLEAR_WORKER_DATA(data);

		g_free(asn1_session->req_body);
		asn1_session->req_body=NULL;

                worker->func = read_response_size;

                if (!change_fd_events_in_io_scheduler(worker, EPOLLIN, error)) {
                        GSETERROR(error, "Failed to change polling event on fd %d", data->fd);
                        goto error_sched;
                }

        } else {
                wl = write(data->fd, data->buffer + data->done, data->buffer_size - data->done);
                if (wl < 0) {
                        GSETERROR(error, "Write error on socket : %s", strerror(errno));
                        goto error_write;
                }

                data->done += wl;
        }

        return(1);

error_sched:
error_write:
error_marshall_message:
error_set_name:
error_set_body:
error_set_headers:
        message_destroy(req, NULL);
error_mes_create:
	asn1_session->error_handler(worker, error);
	free_asn1_worker( worker, 0 );
	return 0;
}

int
read_response_size(worker_t *worker, GError **error)
{
        ssize_t rl;
        guint32 response_size;
        worker_data_t *data = NULL;
	asn1_session_t *asn1_session = NULL;

        TRACE_POSITION();

        data = &(worker->data);
	asn1_session = (asn1_session_t*)data->session;

        if (data->buffer == NULL) {
                data->buffer_size = RESPONSE_SIZE_SIZE;
                data->buffer = g_try_malloc0(data->buffer_size);
                if (data->buffer == NULL) {
                        GSETERROR(error, "Memory allocation failure");
                        goto error_alloc_buffer;
                }

        } else if (data->done >= data->buffer_size) {

                memcpy(&response_size, data->buffer, RESPONSE_SIZE_SIZE);

                data->buffer_size += g_ntohl(response_size);
                data->buffer = g_try_realloc(data->buffer, data->buffer_size);
                if (data->buffer == NULL) {
                        GSETERROR(error, "Memory allocation failure");
                        goto error_alloc_buffer;
                } else {
                        memset(data->buffer + data->done, 0, g_ntohl(response_size));
                }

                worker->func = read_response;

        } else {
                rl = read(data->fd, data->buffer + data->done, data->buffer_size - data->done);
                if (rl < 0) {
                        GSETERROR(error, "Read error on socket : %s", strerror(errno));
                        goto error_read;
                }

                if (rl == 0 && data->done < data->buffer_size) {
                        GSETERROR(error, "Connection closed while reading response size");
                        goto error_read;
                }

                data->done += rl;
        }

        return(1);

error_read:
error_alloc_buffer:
	asn1_session->error_handler(worker, error);
	free_asn1_worker( worker, 0 );
        return 0;
}

int
read_response(worker_t *worker, GError **error)
{
	int rc;
        ssize_t rl;
        worker_data_t *data = NULL;
	asn1_session_t *asn1_session = NULL;
        MESSAGE resp = NULL;
        gint status = 999;
        gchar *msg = NULL;
        gsize msg_size;

        TRACE_POSITION();

        data = &(worker->data);
	asn1_session = (asn1_session_t*)data->session;

	/*read a bit more*/
        rl = read(data->fd, data->buffer + data->done, data->buffer_size - data->done);
        if (rl < 0) {
                GSETERROR(error, "Read error on socket : %s", strerror(errno));
                goto error_read;
        }

        if (rl == 0 && data->done < data->buffer_size) {
                GSETERROR(error, "Connection closed while reading response");
                goto error_read;
        }

        data->done += rl;

	/*manage the message*/
        if (data->done >= data->buffer_size) {

		TRACE("Data available : (done=%d) >= (size=%d)", data->done, data->buffer_size);

                if (!message_create(&resp, error)) {
                        GSETERROR(error, "Failed to create response message");
                        goto error_message_create;
                }

                msg_size = data->buffer_size;

                if (!message_unmarshall(resp, data->buffer, &msg_size, error)) {
                        GSETERROR(error, "Failed to unmarshall response");
                        goto error_unmarshall;
                }

                if (!metaXClient_reply_simple(resp, &status, &msg, error)) {
                        GSETERROR(error, "Failed to decode response");
                        goto error_decode;
                }

                if (status!=200 && status!=206) {
			GSETERROR(error, "ASN1 request failed with status %d :\n%s", status, msg);
			goto error_status;
		}

		/*free the old headers and get the new*/
		if (asn1_session->resp_headers) {
			g_hash_table_destroy(asn1_session->resp_headers);
			asn1_session->resp_headers = NULL;
		}
		if (!message_get_fields(resp, &(asn1_session->resp_headers), error)) {
			GSETERROR(error, "Failed to extract headers from message");
			goto error_headers;
		}

		/*free the old body and get the new*/
		asn1_session->resp_body = NULL;
		asn1_session->resp_body_size = 0;
		if (message_has_BODY(resp, error)) {
			if (!message_get_BODY(resp, &(asn1_session->resp_body), &(asn1_session->resp_body_size), error)) {
				GSETERROR(error, "Failed to extract body from message");
				goto error_body;
			}
		}

		rc = asn1_session->response_handler( worker, error );
		asn1_session->resp_body_size = 0;
		asn1_session->resp_body = NULL;

		if (asn1_session->resp_headers) {
			g_hash_table_remove_all(asn1_session->resp_headers);
			g_hash_table_destroy(asn1_session->resp_headers);
			asn1_session->resp_headers = NULL;
		}
		
                g_free(msg);
                message_destroy(resp, error);

		if (status==200 || !rc) {
			TRACE("Reply sequence terminated (status=%d rc=%d)", status, rc);
			
			if (rc) {
				if (asn1_session->final_handler)
					rc = asn1_session->final_handler( worker, error );
			} else {
				if (asn1_session->error_handler)
					rc = asn1_session->error_handler( worker, error );
			}
			
			free_asn1_worker( worker, rc );
			return rc;
		} else {
			TRACE("Reply sequence not terminated (status=%d rc=%d)", status, rc);
                	CLEAR_WORKER_DATA(data);
			worker->func = read_response_size;
			return 1;
		}
        }

	/*worker is left unchanged, wa wait for the remaining of the reply*/
        return(1);

error_body:
error_headers:
error_status:
        g_free(msg);
error_decode:
error_unmarshall:
        message_destroy(resp, error);
error_message_create:
error_read:
        asn1_session->error_handler(worker, error);
	free_asn1_worker( worker, 0 );
	return 0;
}

