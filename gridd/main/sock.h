/*
OpenIO SDS gridd
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef OIO_SDS__gridd__main__sock_h
# define OIO_SDS__gridd__main__sock_h 1

#include <sys/socket.h>
#include <glib.h>

#define  AP_BACKLOG 256

enum gridd_flag_e {
	GRIDD_FLAG_NOLINGER = 0x01,
	GRIDD_FLAG_KEEPALIVE = 0x02,
	GRIDD_FLAG_QUICKACK = 0x04,
	GRIDD_FLAG_SHUTDOWN = 0x08
};

extern guint32 gridd_flags;

extern void gridd_set_flag(enum gridd_flag_e flag, int onoff);

typedef struct accept_pool_s
{
	GRecMutex mut;
	gint *srv;
	gint size;
	gint count;
} *ACCEPT_POOL;

gint format_addr (struct sockaddr *sa, gchar *h, gsize hL, gchar *p, gsize pL, GError **err);

gint resolve (struct sockaddr_storage *sa, const gchar *h, const gchar *p, GError **err);

gint accept_make (ACCEPT_POOL *s, GError **err);

gint accept_add (ACCEPT_POOL ap, const gchar *l, GError **err);

gint accept_do   (ACCEPT_POOL ap, addr_info_t *cltaddr, GError **err);

void accept_close_servers (ACCEPT_POOL ap);

gboolean wait_for_socket(int fd, long ms);

#endif /*OIO_SDS__gridd__main__sock_h*/