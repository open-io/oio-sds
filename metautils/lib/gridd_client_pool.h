#ifndef SQLX__CLIENTPOOL_H
# define SQLX__CLIENTPOOL_H 1
# include <glib.h>

struct client_s;

/** Used to associate the information necessary to manage FD events.
 * This will be set in the epoll_event data pointer. */
struct event_client_s
{
	/** when the connection is over, after on_end() has been called, this
	 * field will be freed unless the on_end() callback has cleared it. */
	struct client_s *client;
	/** Called when the connection is closed. */
	void (*on_end)(struct event_client_s *);
	/** arbitrary */
	gpointer udata;
};

struct gridd_client_pool_s;

struct gridd_client_pool_vtable_s
{
	void (*destroy) (struct gridd_client_pool_s *p);

	/** Return the maximum of client file descriptors allowed to the pool.
	 * This is not mandatorily the exact number of clients, since the pool
	 * itself might require descriptors for its own work. */
	guint (*get_max) (struct gridd_client_pool_s *pool);

	/** Sets the maximum number of file descriptors allowed to run this pool
	 * The pool is reponsible to limit the number of outgoing clients and
	 * reserve some slots. */
	void (*set_max) (struct gridd_client_pool_s *pool, guint max);

	void (*defer) (struct gridd_client_pool_s *p, struct event_client_s *ev);

	/** Destined to be called continuously, it shouldn't block more than 'sec'
	 * seconds between each run of the polling loop. */
	GError* (*round) (struct gridd_client_pool_s *p, time_t sec);
};

struct abstract_client_pool_s
{
	struct gridd_client_pool_vtable_s *vtable;
};

#define gridd_client_pool_destroy(p) \
	((struct abstract_client_pool_s*)p)->vtable->destroy(p)

#define gridd_client_pool_defer(p,ev) \
	((struct abstract_client_pool_s*)p)->vtable->defer(p,ev)

#define gridd_client_pool_round(p,sec) \
	((struct abstract_client_pool_s*)p)->vtable->round(p,sec)

#define gridd_client_pool_get_max(p) \
	((struct abstract_client_pool_s*)p)->vtable->get_max(p)

#define gridd_client_pool_set_max(p,max) \
	((struct abstract_client_pool_s*)p)->vtable->set_max(p,max)

/* Public API -------------------------------------------------------------- */

struct gridd_client_pool_s * gridd_client_pool_create(void);

#endif /* SQLX__CLIENTPOOL_H */
