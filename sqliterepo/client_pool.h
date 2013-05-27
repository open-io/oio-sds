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

#ifndef SQLX__CLIENTPOOL_H
# define SQLX__CLIENTPOOL_H 1
# include <glib.h>


/*! Used to associate the information necessary to manage FD events.
 * This will be set in the epoll_event data pointer. */
struct event_client_s
{
	struct client_s *client;
	void (*on_end)(struct event_client_s *);
	gpointer udata;
};

struct client_pool_s
{
	struct event_client_s **active_clients;
	GMutex *lock;
	GQueue *pending_clients;
	GQueue *notifications;
	int fdmon;

	guint active_clients_size;
	guint active_max;
	guint active_count;

	/* notifications */
	int fd_in; /*!< consumes the notifications here */
	int fd_out; /*!< send anything to notify */

	/* if set to any non-zero value, new requests are not started */
	int closed;
};

struct client_pool_s * client_pool_create(guint max);

void client_pool_destroy(struct client_pool_s *p);

void client_pool_defer(struct client_pool_s *p, struct event_client_s *ev);

GError * client_pool_round(struct client_pool_s *p, time_t sec);

guint client_pool_get_max(struct client_pool_s *pool);

void client_pool_set_max(struct client_pool_s *pool, guint max);

#endif /* SQLX__CLIENTPOOL_H */
