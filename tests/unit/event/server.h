#ifndef __SERVER_IMPORT_H__
#define __SERVER_IMPORT_H__

#include <sys/socket.h>
#include <arpa/inet.h>
#include <glib.h>

#endif

#ifndef __SERVER_H__
#define __SERVER_H__

#define POLL_TIMEOUT 500

struct server_s
{
	int fd;
	int running;
};

struct client_s
{
	int fd;
	struct server_s *server;
	struct sockaddr_storage peer;
	socklen_t peer_len;
};

void launch_server(int, gchar* (*_manage_request) (gchar*));
void stop_server(void);

#endif
