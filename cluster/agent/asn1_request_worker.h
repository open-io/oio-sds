/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef ASN1_REQUEST_WORKER_H
# define ASN1_REQUEST_WORKER_H
# include <glib.h>
# include <metatypes.h>
# include "./agent.h"
# include "./worker.h"

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

void asn1_worker_set_request_body(worker_t *asn1_worker, GByteArray *body);

void asn1_worker_set_request_body_from_buffer(worker_t *asn1_worker, guint8 *body, gsize body_size);

#endif	/* ASN1_REQUEST_WORKER_H */
