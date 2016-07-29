#include "server.h"
#include "string.h"
#include <assert.h>
#include <poll.h>
#include <unistd.h>
#include <events/oio_events_queue.h>
#include <events/oio_events_queue_beanstalkd.h>
#include <core/oio_core.h>
#include <stdlib.h>
#include <metautils/lib/metautils.h>
#include <glib/gprintf.h>

#define BUFFER_SIZE 1024

struct server_s *server;
GMutex mutex_server;

#define SERVER_ACTION(action) do { \
	g_mutex_lock(&mutex_server);		\
	action					\
	g_mutex_unlock(&mutex_server);		\
	} while(0)

static void
manage_client (struct client_s *client, gchar* (*_manage_request) (gchar*))
{
	while (client->server->running) {
		struct pollfd pfd;
		pfd.fd = client->fd;
		pfd.events = POLLIN | POLLERR | POLLHUP;
		pfd.revents = 0;
		
		int rc = poll(&pfd, 1, POLL_TIMEOUT);
		if (rc <= 0)
			continue;
		if (pfd.revents & POLLHUP)
			break;
		if (pfd.revents & POLLERR)
			break;
		int nb_recv = 0;
		gchar *content = g_malloc(sizeof(gchar) * BUFFER_SIZE);
		gchar *buffer = g_malloc(sizeof(gchar) * BUFFER_SIZE);
		gint length_recv;
		gint bytes_read = 0;
		do {
			if(nb_recv != 0) {
				content = g_realloc(content,
						    BUFFER_SIZE * \
						    (nb_recv + 1) * \
						    sizeof(gchar));
			}
			length_recv = recv(client->fd,
					   buffer, BUFFER_SIZE, MSG_DONTWAIT);
			if (length_recv > 0)
				memcpy(content + bytes_read * nb_recv,
				       buffer, sizeof(gchar) * length_recv);
			nb_recv ++;
			bytes_read += length_recv;
		} while(length_recv > 0);
		content[bytes_read] = '\0';
		gchar *response = _manage_request(content);
		write(client->fd, response, strlen(response));
		g_free(response);
		g_free(buffer);
		g_free(content);
		
	}
	close (client->fd);
	client->fd = -1;
}

static void
server_run (gchar* (*_manage_request) (gchar*))
{
	while (server->running) {
		struct pollfd pfd;
		pfd.fd = server->fd;
		pfd.events = POLLIN | POLLERR | POLLHUP;
		pfd.revents = 0;

		int rc = poll (&pfd, 1, POLL_TIMEOUT);
		if (rc <= 0)
			continue;
		assert (!(pfd.revents & (POLLERR|POLLHUP)));

		struct client_s client;
		client.server = server;
		client.peer_len = sizeof(client.peer);
		client.fd = accept(server->fd, (struct sockaddr*)&client.peer, &client.peer_len);
		if (client.fd >= 0)
			manage_client (&client, _manage_request);
	}
	close(server->fd);
	g_free(server);
}

static gpointer
_run_server(gpointer data) {
	gchar* (*_manage_request) (gchar*) = data;
	server_run(_manage_request);
	return NULL;
}

void
launch_server(int port, gchar* (*_manage_request) (gchar*)) {

	int fd = socket (AF_INET, SOCK_STREAM, 0);
	assert (fd >= 0);

	struct sockaddr_in in;
	in.sin_family = AF_INET;
	in.sin_port = htons (port);
	int rc = inet_pton (AF_INET, "127.0.0.1", &in.sin_addr);
	assert (rc == 1);

	rc = bind (fd, (struct sockaddr*)&in, sizeof(in));
	assert (rc == 0);

	rc = listen (fd, 8192);
	assert (rc == 0);
	
	server = malloc(sizeof(struct server_s));
	server->fd = fd;
	server->running = 1;
	GThread *thr = g_thread_new("server_run", _run_server,
				    _manage_request);
	(void) thr;
}

void
stop_server(void) {
	SERVER_ACTION(server->running = 0;);
}
