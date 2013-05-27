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

#ifndef __SOCK_H__
#define __SOCK_H__

#include <pthread.h>
#include <sys/socket.h>
#include <glib.h>

#define  AP_BACKLOG 256

typedef struct accept_pool_s
{
#ifdef HAVE_EPOLL
	int epoll_fd;
#endif /*HAVE_EPOLL*/
	GStaticRecMutex mut;
	gint *srv;
	gint size;
	gint count;
} *ACCEPT_POOL;


gint format_addr (struct sockaddr *sa, gchar *h, gsize hL, gchar *p, gsize pL, GError **err);

gint resolve (struct sockaddr_storage *sa, const gchar *h, const gchar *p, GError **err);

/**
 * Starts a new accept pool.
 */
gint accept_make (ACCEPT_POOL *s, GError **err);


gint accept_add (ACCEPT_POOL ap, const gchar *l, GError **err);

/** add a unix server socket bond to the given local path*/
gint accept_add_local (ACCEPT_POOL ap, const gchar *l, GError **err);

/**
 * Add a new server socket in the accept pool based
 * on its listen port and bind address.
 */
gint accept_add_inet  (ACCEPT_POOL ap, const gchar *h, const gchar *p, GError **err);

/**
 * Returns a new connection file description
 */
gint accept_do   (ACCEPT_POOL ap, addr_info_t *cltaddr, GError **err);

/**
 *
 */
gint accept_close_servers (ACCEPT_POOL ap, GError **err);

gsize accept_pool_to_string( ACCEPT_POOL ap, gchar *dst, gsize dst_size );

gboolean wait_for_socket(int fd, long ms);

#endif /*__SOCK_H__*/
