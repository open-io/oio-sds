/**
 * @file transport_gridd.h
 */

#ifndef GRID__TRANSPORT_GRIDD__H
# define GRID__TRANSPORT_GRIDD__H 1
# include <glib.h>

# ifndef INNER_STAT_NAME_REQ_COUNTER
#  define INNER_STAT_NAME_REQ_COUNTER "gridd.counter.allreq"
# endif

# ifndef INNER_STAT_NAME_REQ_TIME
#  define INNER_STAT_NAME_REQ_TIME "gridd.counter.alltime"
# endif

/**
 * @defgroup server_transgrid GRIDD transport
 * @ingroup server
 * @brief
 * @details
 * @{
 */

/* Forward declarations externally defined */
struct network_client_s;
struct network_transport_s;

/* Hidden structures internally definied */
struct gridd_request_dispatcher_s;
struct grid_stats_holder_s;

/**
 * Given to the request dispatcher, it allows him to reply to
 * the client.
 */
struct gridd_reply_ctx_s
{
	/* ------------------------------
	 * Context belonging to the reply
	 * ------------------------------ */

	/**
	 * @param name
	 * @param value
	 */
	void (*add_header) (const gchar *name, GByteArray *value);
	
	/**
	 * @param body
	 */
	void (*add_body)   (GByteArray *body);

	/**
	 * @param code
	 * @param message
	 */
	void (*send_reply) (gint code, gchar *message);
	
	/**
	 * @param code
	 * @param err
	 */
	void (*send_error) (gint code, GError *err);

	/**
	 * @param fmt
	 * @param ...
	 */
	void (*subject) (const gchar *fmt, ...);

	void (*uid) (const gchar *fmt, ...);

	/**
	 * @param key
	 * @param data
	 * @param cleanup
	 */
	void (*register_cnx_data) (const gchar *key, gpointer data,
			GDestroyNotify cleanup);

	/* Dissociates the data or does nothing if data not present */
	void (*forget_cnx_data) (const gchar *key);

	/* Return a data previously associated, or NULL if not found. */
	gpointer (*get_cnx_data) (const gchar *key);


	/* --------------------------------
	 * Context belonging to the request
	 * -------------------------------- */

	/* Provide access to the network layer */
	struct network_client_s *client;

	/* ASN.1 request decoded */
	struct message_s *request;

	/* extracted from the request */
	const struct hashstr_s *reqname;
};

/**
 * Describes a request that can be managed by a GRIDD.
 */
struct gridd_request_descr_s
{
	/** The choice has been made to identify a request by its name,
	 * and not a pattern (as in the legacy gridd). This helps building
	 * a more efficient structure to match  */
	const gchar *name;

	/** How to manage this request.
	 * @param handler_data the arbitrary pointer registered with the request only
	 * @param group_data the arbitrary pointer registered with the request set
	 * @param reply all the callbacks to manage the replies flow
	 * @return FALSE in case of an error strong enough to require closing
	 *         the connection. A TRUE value if the connection might be
	 *         kept open.
	 */
	gboolean (*handler) (struct gridd_reply_ctx_s *reply,
			gpointer group_data, gpointer handler_data);

	gpointer handler_data;
};

/**
 * Adds support for a requests to the given gridd_dispatcher.
 *
 * @param dispatcher
 * @param descr
 * @param group_data a 
 * @return
 */
GError *
transport_gridd_dispatcher_add_requests(
		struct gridd_request_dispatcher_s *dispatcher,
		const struct gridd_request_descr_s *descr,
		gpointer group_data);

/**
 * Build an optimized gridd_request dispatcher, without any request
 * configured. 
 *
 * @return
 */
struct gridd_request_dispatcher_s * transport_gridd_build_empty_dispatcher(void);

/**
 * Build an optimized gridd_request dispatcher, based on a set of
 * request handler descriptions.
 *
 * Services that want to work on top of a gridd service just have to
 * provide an array of gridd_request_handler_s.
 *
 * @see transport_gridd_dispatcher_add_requests()
 * @see transport_gridd_build_empty_dispatcher()
 * @param descriptions
 * @param u
 * @return
 */
struct gridd_request_dispatcher_s * transport_gridd_build_dispatcher(
		const struct gridd_request_descr_s *descriptions,
		gpointer u);

/**
 * Cleans a GRIDD request dispatcher and all the internal structures
 * associated to requests.
 *
 * Obviously, please do not call this when still using the dispatcher.
 * Rather call this when no worker threads still exsist.
 *
 * @param disp
 */
void gridd_request_dispatcher_clean(struct gridd_request_dispatcher_s *disp);

/**
 * Associates the given client to the given request dispatcher into
 * a transport object.
 *
 * @param disp
 * @param client
 */
void transport_gridd_factory0(struct gridd_request_dispatcher_s *disp,
		struct network_client_s *client);

/**
 * Wrapper over transport_gridd_factory0() to provide a factory function,
 * without having to cast transport_gridd_factory0().
 * @param dispatcher
 * @param client
 * @see transport_gridd_factory0()
 */
static inline void
transport_gridd_factory(gpointer dispatcher, struct network_client_s *client)
{
	return transport_gridd_factory0(dispatcher, client);
}

/**
 * Adds zeroed stats for the given request handler.
 *
 * Internal feature, do not use this directly unless you know what you're
 * doing!
 * @param stats
 * @param dispatcher
 */
void gridd_register_requests_stats(struct grid_stats_holder_s *stats,
		struct gridd_request_dispatcher_s *dispatcher);

/**
 * All these requests ignore their first argument
 * @return
 */
const struct gridd_request_descr_s* gridd_get_common_requests(void);

/** @} */

#endif
