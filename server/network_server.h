#ifndef GRID__NETWORK_SERVER__H
# define GRID__NETWORK_SERVER__H 1
# include <sys/time.h>
# include <server/slab.h>

struct network_server_s;
struct grid_stats_holder_s;
struct network_client_s;
struct network_transport_s;
struct gba_view_s;

/* To be defined by the application instatiating the transport */
struct transport_client_context_s;

enum {
	RC_ERROR,
	RC_NODATA,
	RC_NOTREADY,
	RC_PROCESSED,
};

struct network_transport_s
{
	/* Associate private data to the  */
	struct transport_client_context_s *client_context;

	void (*clean_context) (
			struct transport_client_context_s*);

	/* Be notified that a piece of data is ready */
	int (*notify_input)  (struct network_client_s *);
	void (*notify_error)  (struct network_client_s *);
	gboolean waiting_for_close;
};

struct network_client_s
{
	int fd;
	enum { CLT_READ=0X01, CLT_WRITE=0X02, CLT_ERROR=0X04 } events;
	struct network_server_s *server;

	struct grid_stats_holder_s *main_stats; /*!< XXX DO NOT USE XXX
	(unless you know what you're doing). This is a direct (and unprotected)
	pointer to the stats_holder of the main server. It is shared among 
	all threads. */

	struct grid_stats_holder_s *local_stats; /*!< Can be safely used
	by any app. This is a pointer to the stats_holder local to the thread
	that is running the current client. */

	gchar local_name[128];
	gchar peer_name[128];
	int flags;
	struct {
		time_t cnx;
		time_t evt_in;
		time_t evt_out;
	} time;

	/* Pending input */
	struct data_slab_sequence_s input;
	/* Pending output */
	struct data_slab_sequence_s output;
	/* What to do with pending data */
	struct network_transport_s transport;
	GError *current_error;

	struct network_client_s *prev; /*!< XXX DO NOT USE */
	struct network_client_s *next; /*!< XXX DO NOT USE */
};

/*! Creates a new server
 * @return
 */
struct network_server_s * network_server_init(void);

/*! Changes the maximum number of concurrent connections that can be
 * managed by the given server.
 *
 * This can be done while the server is working.
 *
 * @param srv
 * @param max
 */
void network_server_set_maxcnx(struct network_server_s *srv, guint max);

/*! Changes the number of connection backlog that can be
 * used by the given server.
 *
 * This can be done while the server is working.
 *
 * @param srv
 * @param cnx_bl
 */
void network_server_set_cnx_backlog(struct network_server_s *srv,
		guint cnx_bl);

typedef void (*network_transport_factory) (gpointer u,
		struct network_client_s *clt);

/*!
 * @param srv * @param url
 * @param factory
 */
void network_server_bind_host(struct network_server_s *srv,
		const gchar *url, gpointer factory_udata,
		network_transport_factory factory);

void network_server_bind_host_throughput(struct network_server_s *srv,
		const gchar *url, gpointer factory_udata,
		network_transport_factory factory);

void network_server_bind_host_lowlatency(struct network_server_s *srv,
		const gchar *url, gpointer factory_udata,
		network_transport_factory factory);

/*!
 * @param srv
 */
void network_server_close_servers(struct network_server_s *srv);

/*!
 * @param srv
 * @return
 */
GError * network_server_open_servers(struct network_server_s *srv);

/*!
 * @param srv
 * @return
 */
GError * network_server_run(struct network_server_s *srv);

/*!
 * @param srv
 */
void network_server_stop(struct network_server_s *srv);

/*!
 * @param srv
 */
void network_server_clean(struct network_server_s *srv);

/*!
 * @param srv
 * @return
 */
struct grid_stats_holder_s * network_server_get_stats(
		struct network_server_s *srv);

/*!
 * @param srv
 * @return
 */
gint network_server_pending_events(struct network_server_s *srv);

/*!
 * @param srv
 * @return
 */
gdouble network_server_reqidle(struct network_server_s *srv);

/* -------------------------------------------------------------------------- */

void network_client_allow_input(struct network_client_s *clt, gboolean v);

void network_client_close_output(struct network_client_s *clt, int now);

int network_client_send_slab(struct network_client_s *client,
		struct data_slab_s *slab);

/* Convenience easy factories ----------------------------------------------- */

static inline void
transport_devnull_factory(gpointer factory_udata,
		struct network_client_s *clt)
{
	(void) factory_udata;
	(void) clt;
}

#endif
