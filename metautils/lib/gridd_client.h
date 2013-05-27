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

void gridd_client_set_timeout(struct client_s *client,
		gdouble to_step, gdouble to_overall);

/* LOOPING ----------------------------------------------------------------- */

gboolean gridd_client_expired(struct client_s *client, GTimeVal *now);

void gridd_client_cnx_error(struct client_s *client);

gboolean gridd_client_finished(struct client_s *client);

gboolean gridd_client_start(struct client_s *client);

GError* gridd_client_step(struct client_s *client);

GError* gridd_client_loop(struct client_s *client);

/* ----------------------------------------------------------------------------
 * ARRAYS of clients
 *
 *
 * ------------------------------------------------------------------------- */

struct client_s ** gridd_client_create_many(gchar **targets,
		GByteArray *request, gpointer ctx, client_on_reply cb);

void gridd_clients_free(struct client_s **clients);

gboolean gridd_clients_finished(struct client_s **clients);

GError * gridd_clients_error(struct client_s **clients);

void gridd_clients_start(struct client_s **clients);

GError * gridd_clients_step(struct client_s **clients);

GError * gridd_clients_loop(struct client_s **clients);

/** @} */

#endif /* HC_GRIDD_CLIENT_H */
