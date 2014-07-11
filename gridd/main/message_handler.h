#ifndef __MESSAGE_HANDLER_H__
# define __MESSAGE_HANDLER_H__
# include <sys/time.h>
# include <metautils/lib/metacomm.h>

struct request_context_s {
	MESSAGE request;
	gint fd;
	addr_info_t* remote_addr;
	addr_info_t* local_addr;
	struct timeval tv_start;
};

typedef gint (*message_matcher_f) (MESSAGE m, void *param, GError **err);
typedef gint (*message_handler_f) (MESSAGE m, gint cnx, void *param, GError **err);
typedef gint (*message_handler_v2_f) (struct request_context_s *ctx, GError **err);

gint message_handler_add (const char *name, message_matcher_f m, message_handler_f h, GError **err);
gint message_handler_add_v2 (const char *name, message_matcher_f m, message_handler_v2_f h, const GPtrArray *tags, GError **err);


#define GO_ON 2
#define DONE 1
#define FAIL 0
#define REPLYCTX_DESTROY_ON_CLEAN 0x000000001
#define REPLYCTX_COPY 0x000000002

struct reply_context_s {
	struct request_context_s *req_ctx;
	GError *warning;
	struct {
		gint code;
		gchar *msg;
	} header;
	struct {
		void *buffer;
		gsize size;
		gboolean copy;
	} body;
	GHashTable *extra_headers;/* (char*) -> (GByteArray*) */
};

/**
 * @param ctx
 */
void reply_context_clear (struct reply_context_s *ctx, gboolean all);

/**
 * @param ctx
 * @param code
 * @param msg
 */
void reply_context_set_message (struct reply_context_s *ctx, gint code, const gchar *msg);


/**
 * @param ctx
 * @param body
 * @param bodySize
 */
void reply_context_set_body (struct reply_context_s *ctx, void *body, gsize bodySize, guint32 flags);

/**
 * @param ctx
 * @param err
 */
gint reply_context_reply (struct reply_context_s *ctx, GError **err);

/*k and v parameters are copied!*/
void reply_context_add_header_in_reply (struct reply_context_s *ctx, const char *k, GByteArray *v);

void reply_context_add_strheader_in_reply (struct reply_context_s *ctx, const char *k, const char *v);

/**/
void reply_context_log_access (struct reply_context_s *ctx,
	const gchar *fmt, ...);

/**/
void request_context_clear(struct request_context_s* ctx);

/**
 * @param ctx
 */
void request_context_free(struct request_context_s* ctx);

/**
 * @param p1
 * @param p2
 */
void request_context_gclean(gpointer p1, gpointer p2);

/*!
 * @param fd_peer can be NULL, then getpeeraddr(fd) will be used.
 */
struct request_context_s* request_context_create(int fd, addr_info_t *fd_peer);

/**/
void requets_context_gclean(gpointer p1, gpointer p2);

namespace_info_t* gridd_get_namespace_info(GError **error);

gint get_network_socket (message_handler_f h, char **addr, int *port, GError **error);

gchar* gridd_get_ns_name(void);

#endif /*__MESSAGE_HANDLER_H__*/
