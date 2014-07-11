#ifndef _CONNECT_H
#define _CONNECT_H

#include <glib.h>

/**
  *	Connect to the agent unix socket
  *
 */
int connect_socket(int *fd, GError **error);

#endif	/* _CONNECT_H */
