#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "gridcluster.agent.accept_worker"
#endif

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <metautils/lib/metautils.h>

#include "./agent.h"
#include "./accept_worker.h"
#include "./gridagent.h"
#include "./message.h"
#include "./io_scheduler.h"
#include "./read_message_worker.h"

int
accept_worker(worker_t *worker, GError **error)
{
	int fd;
	struct sockaddr_un remote;
	socklen_t remote_len = 0;
	worker_t *mes_worker = NULL;

	(void) error;
	TRACE_POSITION();

	memset(&remote, 0, sizeof(struct sockaddr_un));
	remote_len = sizeof(remote);

	fd = accept_nonblock(worker->data.fd, (struct sockaddr *)&remote, &remote_len);
	if (fd < 0) {
		ERROR("Failed to accept on socket %d : %s", worker->data.fd, strerror(errno));
		return 1;
	}

	DEBUG("Accepting new connection on sock %d", worker->data.fd);

	/* Create worker */
	mes_worker = g_malloc0(sizeof(worker_t));
	mes_worker->func = read_message_size_worker;
	mes_worker->clean = NULL;
	mes_worker->timeout = worker->data.sock_timeout;
	mes_worker->data.fd = fd;
	mes_worker->data.sock_timeout = worker->data.sock_timeout;
	mes_worker->data.session = NULL;

	GError *e = NULL;
	if (!add_fd_to_io_scheduler(mes_worker, EPOLLIN, &e)) {
		ERROR("Failed to add fd to io_scheduler : %s", e->message);
		g_clear_error(&e);
		g_free(mes_worker);
	}

	return(1);
}

