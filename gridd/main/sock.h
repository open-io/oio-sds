#ifndef __SOCK_H__
#define __SOCK_H__

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
