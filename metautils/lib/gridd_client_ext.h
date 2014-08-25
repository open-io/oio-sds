#ifndef HC_GRIDD_CLIENT_EXT_H
# define HC_GRIDD_CLIENT_EXT_H 1
# include <glib.h>

/**
 * @defgroup metautils_client_ext
 * @ingroup metautils
 * @brief
 * @details
 *
 * @{
 */

struct client_s;

/* ------------------------------------------------------------------------- */
/* Wrappers for single clients --------------------------------------------- */
/* ------------------------------------------------------------------------- */

// Wraps .interest(), .get_fd(), .react() and poll()
GError* gridd_client_step(struct client_s *p);

// Wrap a loop on step() until finished() or error().
GError* gridd_client_loop(struct client_s *client);

// Wraps create_empty() and connect_url()
struct client_s * gridd_client_create_idle(const gchar *target);

// Wraps create_idle() and request()
struct client_s * gridd_client_create(const gchar *target,
		GByteArray *req, gpointer ctx, client_on_reply cb);

/* ------------------------------------------------------------------------- */
/* Implementation specifics / array of structures -------------------------- */
/* ------------------------------------------------------------------------- */

// @return NULL if one of the subsequent client creation fails
struct client_s ** gridd_client_create_many(gchar **targets,
		GByteArray *request, gpointer ctx, client_on_reply cb);

// Cleans everything allocated by gridd_client_create_many()
void gridd_clients_free(struct client_s **clients);

// Calls set_timeout() on each pointed client
void gridd_clients_set_timeout(struct client_s **clients, gdouble to_step,
		gdouble to_overall);

// Returns FALSE if at least finished() returns FALSE for at least one client
gboolean gridd_clients_finished(struct client_s **clients);

// Return the first non-NULL return of each call to error()
GError * gridd_clients_error(struct client_s **clients);

// Trigger a start on each client
void gridd_clients_start(struct client_s **clients);

// Poll for network events (using poll()), and call gridd_client_react()
// if a non-error event occured.
GError * gridd_clients_step(struct client_s **clients);

// Wraps gridd_clients_step() and gridd_clients_finished()
GError * gridd_clients_loop(struct client_s **clients);

#endif /* HC_GRIDD_CLIENT_EXT_H */
