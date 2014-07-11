#ifndef HC_GRIDD_CLIENT_H
# define HC_GRIDD_CLIENT_H 1

/**
 * @defgroup metautils_client
 * @ingroup metautils
 * @brief
 * @details
 *
 * @{
 */

# include <glib.h>
# include <sys/time.h>

# ifndef GRIDC_DEFAULT_TIMEOUT_STEP
#  define GRIDC_DEFAULT_TIMEOUT_STEP 10.0
# endif

# ifndef GRIDC_DEFAULT_TIMEOUT_OVERALL
#  define GRIDC_DEFAULT_TIMEOUT_OVERALL 30.0
# endif

struct client_s;
struct message_s;
struct addr_info_s;

enum client_interest_e
{
	CLIENT_RD = 0x01,
	CLIENT_WR = 0x02
};

typedef gboolean (*client_on_reply)(gpointer ctx, struct message_s *reply);

/* CONSTRUCTORS & DESTRUCTORS ---------------------------------------------- */

struct client_s * gridd_client_create_empty(void);

struct client_s * gridd_client_create_idle(const gchar *target);

struct client_s * gridd_client_create(const gchar *target,
		GByteArray *req, gpointer ctx, client_on_reply cb);

void gridd_client_clean(struct client_s *client);

void gridd_client_free(struct client_s *client);

/* TRIGGERS ---------------------------------------------------------------- */

GError* gridd_client_connect_url(struct client_s *client, const gchar *url);

GError* gridd_client_connect_addr(struct client_s *client,
		const struct addr_info_s *ai);

GError* gridd_client_request(struct client_s *client,
		GByteArray *req, gpointer ctx, client_on_reply cb);

/* GETTERS ----------------------------------------------------------------- */

GError* gridd_client_error(struct client_s *client);

int gridd_client_interest(struct client_s *client);

const gchar* gridd_client_url(struct client_s *client);

int gridd_client_fd(struct client_s *client);

/* SETTERS ----------------------------------------------------------------- */

GError* gridd_client_set_fd(struct client_s *client, int fd);

void gridd_client_set_keepalive(struct client_s *client, gboolean on);

void gridd_client_set_timeout(struct client_s *client, gdouble to_step,
		gdouble to_overall);

void gridd_clients_set_timeout(struct client_s **clients, gdouble to_step,
		gdouble to_overall);

/* LOOPING ----------------------------------------------------------------- */

gboolean gridd_client_expired(struct client_s *client, GTimeVal *now);

void gridd_client_cnx_error(struct client_s *client);

gboolean gridd_client_finished(struct client_s *client);

gboolean gridd_client_start(struct client_s *client);

GError* gridd_client_step(struct client_s *client);

GError* gridd_client_loop(struct client_s *client);

void gridd_client_react(struct client_s *client);

/* ----------------------------------------------------------------------------
 * ARRAYS of clients
 *
 *
 * ------------------------------------------------------------------------- */

/**
 * @return NULL if one of the subsequent client creation fails
 */
struct client_s ** gridd_client_create_many(gchar **targets,
		GByteArray *request, gpointer ctx, client_on_reply cb);

void gridd_clients_free(struct client_s **clients);

gboolean gridd_clients_finished(struct client_s **clients);

GError * gridd_clients_error(struct client_s **clients);

void gridd_clients_start(struct client_s **clients);

// Poll for network events (using poll()), and call gridd_client_react()
// if a non-error event occured.
GError * gridd_clients_step(struct client_s **clients);

GError * gridd_clients_loop(struct client_s **clients);

/** @} */

#endif /* HC_GRIDD_CLIENT_H */
