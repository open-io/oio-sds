#ifndef ASN1_REQUEST_WORKER_H
# define ASN1_REQUEST_WORKER_H
# include <metautils/lib/metatypes.h>
# include <cluster/agent/agent.h>
# include <cluster/agent/worker.h>

typedef struct asn1_session_s {
	addr_info_t *addr;
	gchar *req_name;
	GHashTable *req_headers;
	gsize req_body_size;
	void *req_body;
	GHashTable *resp_headers;
	gsize resp_body_size;
	void *resp_body;
        worker_func_f response_handler;
        worker_func_f error_handler;
        worker_func_f final_handler;
	/**/
	GDestroyNotify clear_session_data;
	void *session_data;
} asn1_session_t;

int asn1_request_worker(worker_t *worker, GError **error);

int agent_asn1_default_response_handler(worker_t *worker, GError **error);

worker_t* create_asn1_worker(addr_info_t *addr, const gchar *req_name);

void free_asn1_worker(worker_t *worker, int worker_too);

asn1_session_t* asn1_worker_get_session(worker_t* asn1_worker);

void* asn1_worker_get_session_data( worker_t *asn1_worker );

void asn1_worker_set_handlers(worker_t *asn1_worker, worker_func_f response, worker_func_f error, worker_func_f final);

void asn1_worker_set_session_data(worker_t *asn1_worker, void* data, GDestroyNotify clean);

void asn1_worker_set_request_header(worker_t *asn1_worker, const char *key, const char *value);

void asn1_worker_set_request_body(worker_t *asn1_worker, GByteArray *body);

void asn1_worker_set_request_body_from_buffer(worker_t *asn1_worker, guint8 *body, gsize body_size);

#endif	/* ASN1_REQUEST_WORKER_H */
