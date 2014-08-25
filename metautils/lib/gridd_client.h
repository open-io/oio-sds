#ifndef HC_GRIDD_CLIENT_H
# define HC_GRIDD_CLIENT_H 1
# include <glib.h>
# include <sys/time.h>


/**
 * @defgroup metautils_client
 * @ingroup metautils
 * @brief
 * @details
 *
 * @{
 */

# ifndef GRIDC_DEFAULT_TIMEOUT_STEP
#  define GRIDC_DEFAULT_TIMEOUT_STEP 10.0
# endif

# ifndef GRIDC_DEFAULT_TIMEOUT_OVERALL
#  define GRIDC_DEFAULT_TIMEOUT_OVERALL 30.0
# endif

#define client_s gridd_client_s

struct gridd_client_s;
struct gridd_client_factory_s;

struct message_s;
struct addr_info_s;

enum client_interest_e
{
	CLIENT_RD = 0x01,
	CLIENT_WR = 0x02
};

typedef gboolean (*client_on_reply)(gpointer ctx, struct message_s *reply);

struct gridd_client_vtable_s
{
	// Destructor
	void (*clean) (struct gridd_client_s *c);

	// Connectors
	GError* (*connect_url) (struct gridd_client_s *c, const gchar *target);
	GError* (*connect_addr) (struct gridd_client_s *c, const struct addr_info_s *a);

	// Sets the next request to be sent, and what to do with the reply.
	GError* (*request) (struct gridd_client_s *c, GByteArray *req,
			gpointer ctx, client_on_reply cb);

	// Returns a copy of the last error that occured.
	GError* (*error) (struct gridd_client_s *c);

	// Tells which among client_interest_e is to be monitored
	int (*interest) (struct gridd_client_s *c);

	// Returns the last URL we connected to
	const gchar* (*get_url) (struct gridd_client_s *c);

	// Returns the file descriptor currently used
	int (*get_fd) (struct gridd_client_s *c);

	// Force a new descriptor
	GError* (*set_fd) (struct gridd_client_s *c, int fd);

	// Tells to keep the connection open between requests.
	void (*set_keepalive) (struct gridd_client_s *c, gboolean on);

	// Force the timeout for each signel request (step), and for each request
	// and its redirections.
	void (*set_timeout) (struct gridd_client_s *c, gdouble step, gdouble overall);

	// Returns if the client's last change is older than 'now'
	gboolean (*expired) (struct gridd_client_s *c, GTimeVal *now);

	// Returns FALSE if the client is still expecting events.
	gboolean (*finished) (struct gridd_client_s *c);

	// Initiate the request.
	gboolean (*start) (struct gridd_client_s *c);

	// Manage the events raised
	void (*react) (struct gridd_client_s *c);

	// If expired() is true, sets the internal error and mark the client
	// as failed.
	void (*expire) (struct gridd_client_s *c, GTimeVal *now);

	void (*fail) (struct gridd_client_s *c, GError *why);
};

struct abstract_client_s
{
	struct gridd_client_vtable_s *vtable;
};

#define gridd_client_free(p) \
	((struct abstract_client_s*)(p))->vtable->clean(p)

#define gridd_client_connect_url(p,u) \
	((struct abstract_client_s*)(p))->vtable->connect_url(p,u)

#define gridd_client_connect_addr(p,a) \
	((struct abstract_client_s*)(p))->vtable->connect_addr(p,a)

#define gridd_client_request(p,req,ctx,cb) \
	((struct abstract_client_s*)(p))->vtable->request(p,req,ctx,cb)

#define gridd_client_error(p) \
	((struct abstract_client_s*)(p))->vtable->error(p)

#define gridd_client_interest(p) \
	((struct abstract_client_s*)(p))->vtable->interest(p)

#define gridd_client_url(p) \
	((struct abstract_client_s*)(p))->vtable->get_url(p)

#define gridd_client_fd(p) \
	((struct abstract_client_s*)(p))->vtable->get_fd(p)

#define gridd_client_set_fd(p,fd) \
	((struct abstract_client_s*)(p))->vtable->set_fd(p,fd)

#define gridd_client_set_keepalive(p,on) \
	((struct abstract_client_s*)(p))->vtable->set_keepalive(p,on)

#define gridd_client_set_timeout(p,t0,t1) \
	((struct abstract_client_s*)(p))->vtable->set_timeout(p,t0,t1)

#define gridd_client_expired(p,now) \
	((struct abstract_client_s*)(p))->vtable->expired(p,now)

#define gridd_client_finished(p) \
	((struct abstract_client_s*)(p))->vtable->finished(p)

#define gridd_client_start(p) \
	((struct abstract_client_s*)(p))->vtable->start(p)

#define gridd_client_expire(p,now) \
	((struct abstract_client_s*)(p))->vtable->expire(p,now)

#define gridd_client_react(p) \
	((struct abstract_client_s*)(p))->vtable->react(p)

#define gridd_client_fail(p,why) \
	((struct abstract_client_s*)(p))->vtable->fail(p,why)

// Instanciate a client with the default VTABLE
struct gridd_client_s * gridd_client_create_empty(void);


/* ------------------------------------------------------------------------- */

struct gridd_client_factory_vtable_s
{
	void (*clean) (struct gridd_client_factory_s *self);

	// Instatiates an empty client (no target, ni request).
	struct gridd_client_s* (*create) (struct gridd_client_factory_s *f);
};

struct abstract_client_factory_s
{
	struct gridd_client_factory_vtable_s *vtable;
};

#define gridd_client_factory_clean(p) \
	((struct abstract_client_factory_s*)(p))->vtable->clean(p)

#define gridd_client_factory_create_client(p) \
	((struct abstract_client_factory_s*)(p))->vtable->create(p)

// Instanciate a clients factory with the default VTABLE. This factory will
// provide clients with the same VTABLE than those created with
// gridd_client_create_empty().
struct gridd_client_factory_s * gridd_client_factory_create(void);

/** @} */

#endif /* HC_GRIDD_CLIENT_H */
