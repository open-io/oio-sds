#ifndef CONTENT_CHECK_H
#define CONTENT_CHECK_H

#include <event.h>
#include <evdns.h>
#include <evhttp.h>
#include <evutil.h>

#include <metautils/lib/metautils.h>
#include <grid_client.h>

#include "check.h"

enum cnx_status_e {
        CNX_NONE = 0,
        CNX_STARTED,
        CNX_SUCCEEDED,
        CNX_FAILED
};

enum reply_parsing_e {
        PARSE_STATUS = 0,
        PARSE_HEADER,
        PARSE_BODY
};

typedef struct chunk_attrinfo_s
{
	container_id_t cid;
	gchar *content_path;
	gint64 content_size;
	guint32 nb_chunks;
	gchar *sys_metadata;
	gchar *usr_metadata;
} chunk_attrinfo_t;

struct chunk_transfer_s {
	chunk_attrinfo_t *attrs;
	meta2_raw_chunk_t *source_chunk;
	gchar *source_path;
	GSList *dst_chunks;
	GSList *dst_rawx;
	struct event_base *evt_base;
	struct evdns_base *evt_dns;
	struct evhttp_connection *src_cnx;
	struct evhttp_request *src_req;
	GSList *dst_bevents;		/* List of struct bufferevent* */
	enum cnx_status_e src_status;
	enum cnx_status_e dst_status;
	enum reply_parsing_e reply_parsing;
	gint64 dst_size;
	gint64 dst_size_remaining;
};

struct dup_chunk_info_s {
	GSList *chunks;
	GSList *used_loc;
};

gboolean check_content_storage_policy(const gchar *namespace, const gchar *container_id, const gchar *content_name,
		gboolean check_only, GError **error);

/* dup_check_ctx structure utils */
void content_check_ctx_clear(struct meta2_ctx_s *ctx);

/* chunk_transfer structure utils */

struct chunk_transfer_s * chunk_transfer_new(void);

void chunk_transfer_set_source_uri(struct chunk_transfer_s *ct, gchar *source);

void chunk_transfer_set_source_chunk(struct chunk_transfer_s *ct, meta2_raw_chunk_t *source_chunk);

void chunk_transfer_set_source_chunk_attrinfo(struct chunk_transfer_s *ct, chunk_attrinfo_t *info);

void chunk_transfer_set_target_rawx(struct chunk_transfer_s *ct, GSList *rawx);

void chunk_transfer_init_base_conn(struct chunk_transfer_s *ct, const gchar *host, short port);

void chunk_transfer_set_base_conn_close_cb(struct chunk_transfer_s *ct, void (*cb)(struct evhttp_connection *, void *), void *arg);

void chunk_transfer_init_req(struct chunk_transfer_s *ct, void (*cb)(struct evhttp_request *, void *), void *arg);

void chunk_transfer_set_req_chunked_cb(struct chunk_transfer_s *ct, void (*cb)(struct evhttp_request *, void *));

int chunk_transfer_make_request(struct chunk_transfer_s *ct);

void chunk_tranfer_generate_chunks_path(struct chunk_transfer_s *ct);

struct evbuffer* chunk_transfer_get_input_buffer(struct chunk_transfer_s *ct);

void chunk_transfer_write_to_dst(struct chunk_transfer_s *ct, gchar *buf, size_t size);

void chunk_transfer_set_dst_remaining_size(struct chunk_transfer_s *ct, gint64 size);

void chunk_transfer_flush_dst(struct chunk_transfer_s *ct);

const char *chunk_transfer_find_req_header(struct chunk_transfer_s *ct, const gchar *header);

guint chunk_transfer_get_target_rawx_count(struct chunk_transfer_s *ct);

enum cnx_status_e chunk_transfer_get_dst_status(struct chunk_transfer_s *ct);

GSList *chunk_transfer_build_target_chunk_list(struct chunk_transfer_s *ct);

void chunk_transfer_generate_chunks_path(struct chunk_transfer_s *ct);

void chunk_transfer_clear(struct chunk_transfer_s *ct);

gchar* chunk_transfer_get_content_path(struct chunk_transfer_s *ct); 

gint64 chunk_transfer_get_content_size(struct chunk_transfer_s *ct);

guint32 chunk_transfer_get_content_nb_chunks(struct chunk_transfer_s *ct);

void chunk_transfer_get_container_id(struct chunk_transfer_s *ct, container_id_t cid);

gchar* chunk_transfer_get_content_sys_metadata(struct chunk_transfer_s *ct);

gchar* chunk_transfer_get_content_usr_metadata(struct chunk_transfer_s *ct);

/* dup_chunk_info utils */

struct dup_chunk_info_s * dup_chunk_info_new(void);

void dup_chunk_info_add_chunk(struct dup_chunk_info_s *dup_chunk, meta2_raw_chunk_t *chunk, gchar *location);

GSList *dup_chunk_info_get_used_locations(struct dup_chunk_info_s *dup_chunk);

GSList *dup_chunk_info_get_chunks(struct dup_chunk_info_s *dup_chunk);

void dup_chunk_info_clear(struct dup_chunk_info_s *dup_chunk);

guint dup_chunk_info_get_copy_count(struct dup_chunk_info_s *dup_chunk);

/***********/

void srv_info_debug_display(gpointer data, gpointer udata);

void raw_chunk_debug_display(gpointer data, gpointer udata);

service_info_t * get_rawx_from_raw_chunk(meta2_raw_chunk_t *c, GSList *rawx);

chunk_attrinfo_t *build_chunk_attrinfo_from_content(meta2_raw_content_t *content);

GError* download_and_check_chunk(const meta2_raw_chunk_t *rc, struct storage_policy_s *sp);

GError* delete_chunk(const meta2_raw_chunk_t *rc);

gboolean is_rawx_reachable(const service_info_t *rawx);

/* V2 */

/*
 * V2 integrity check function. This function works only with META2V2
 */
GError *check_content(struct hc_url_s *url, gboolean check_only);


/**
 * Check if struct content_textinfo_s given as argument id filled
 *
 * @param content the struct content_textinfo_s to check
 * @param error
 *
 * @return TRUE or FALSE if a field is missing
 */
gboolean check_content_info(struct content_textinfo_s *content, GError **p_error);

#endif
