/**
 * @file transport_http.h
 */

#ifndef GRID__TRANSPORT_HTTP__H
# define GRID__TRANSPORT_HTTP__H 1
# include <server/slab.h>

/**
 * @defgroup server_transhttp HTTP features
 * @ingroup server
 * @brief
 * @details
 * @{
 */

/* Avoids an include */
struct network_client_s;

/* Hidden type, internally defined */
struct http_request_dispatcher_s;

/**
 *
 */
struct http_request_s
{
	struct network_client_s *client;
	void (*notify_body) (struct http_request_s *);

	/* unpacked request line */
	gchar *cmd;
	gchar *req_uri;
	gchar *version;

	/* all the headers mapped as <gchar*,gchar*> */
	GTree *tree_headers;
	GByteArray *body;
};

/**
 *
 */
struct http_reply_ctx_s
{
	void (*set_status) (int code, const gchar *msg);
	void (*set_content_type)(const gchar *type);
	void (*add_header) (const gchar *name, gchar *v);
	void (*add_header_gstr) (const gchar *name, GString *value);
	void (*set_body) (guint8 *d, gsize l);
	void (*set_body_gstr) (GString *gstr);
	void (*set_body_gba) (GByteArray *gstr);

	void (*finalize) (void);
};

enum http_rc_e { HTTPRC_DONE, HTTPRC_NEXT, HTTPRC_ABORT };

/**
 *
 */
struct http_request_descr_s
{
	const gchar *name;

	enum http_rc_e (*handler) (gpointer u,
		 struct http_request_s *request,
		 struct http_reply_ctx_s *reply);
};


/**
 * Associates the given client to the given request dispatcher into
 * a transport object.
 *
 * @param dispatcher
 * @param client
 */
void transport_http_factory0(struct http_request_dispatcher_s *dispatcher,
		struct network_client_s *client);


/**
 * Wrapper over transport_http_factory0() to provide a factory function,
 * without having to cast transport_http_factory0().
 *
 * @see transport_http_factory0()
 * @param dispatcher
 * @param client
 */
static inline void
transport_http_factory(gpointer dispatcher, struct network_client_s *client)
{
	transport_http_factory0(dispatcher, client);
}


/**
 * @param d
 */
void http_request_dispatcher_clean(struct http_request_dispatcher_s *d);


/**
 * @param u
 * @param descr
 * @return
 */
struct http_request_dispatcher_s * transport_http_build_dispatcher(
		gpointer u, const struct http_request_descr_s *descr);


/**
 * @param req
 * @param n
 * @return
 */
const gchar * http_request_get_header(struct http_request_s *req,
		const gchar *n);


/** @} */

#endif /* GRID__TRANSPORT_HTTP__H */
