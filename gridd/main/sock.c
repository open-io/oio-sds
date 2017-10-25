/*
OpenIO SDS gridd
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <metautils/lib/metautils.h>

#include "./sock.h"
#include "./server_internals.h"
#include "./srvalert.h"

ACCEPT_POOL
accept_make(void)
{
	struct accept_pool_s *ap = g_malloc0 (sizeof(struct accept_pool_s));
	g_rec_mutex_init(&(ap->mut));
	ap->count = 0;
	ap->size = 2;
	ap->srv = g_malloc0 (ap->size * sizeof(gint));
	for (int i=0; i<ap->size ;i++)
		ap->srv[i]=-1;
	return ap;
}

static void
accept_add_any (ACCEPT_POOL ap, int srv)
{
	EXTRA_ASSERT(ap != NULL);
	EXTRA_ASSERT(ap->srv != NULL);
	EXTRA_ASSERT(srv >= 0);

	g_rec_mutex_lock (&(ap->mut));

	/*make the arrays grows if it is too small*/
	if (ap->size <= ap->count) {
		gint *newSrv, newSize;
		newSize = ap->size + 2;
		newSrv = g_realloc (ap->srv, sizeof(gint) * newSize);
		memset (newSrv+ap->size, 0x00, sizeof(gint) * 2);
		ap->size = newSize;
		ap->srv = newSrv;
	}

	ap->srv [ap->count++] = srv;

	g_rec_mutex_unlock (&(ap->mut));
}

gint
accept_add (ACCEPT_POOL ap, const gchar *url, GError **err)
{
	EXTRA_ASSERT(ap != NULL);
	EXTRA_ASSERT(url != NULL);

	struct sockaddr_storage sa = {};
	gsize sa_len = sizeof(sa);
	gint srv = -1;

	if (!metautils_url_valid_for_bind(url)) {
		GSETERROR(err,"Invalid address [%s]", url);
		return 0;
	}
	if (!grid_string_to_sockaddr(url, (struct sockaddr*)&sa, &sa_len)) {
		GSETERROR(err,"Cannot resolve [%s]", url);
		return 0;
	}

	/*create the server socket*/
	if (-1 == (srv = socket_nonblock (sa.ss_family, SOCK_STREAM, 0))) {
		GSETERROR(err,"socket() error: (%d) %s", errno, strerror(errno));
		return 0;
	}

	sock_set_reuseaddr(srv, TRUE);

	if (-1 == bind (srv, (struct sockaddr*)&sa, sa_len)) {
		GSETERROR(err,"Cannot bind %d on [%s]: (%d) %s",
				srv, url, errno, strerror(errno));
		goto errorLabel;
	}

	if (-1 == listen (srv,AP_BACKLOG)) {
		GSETERROR(err,"Cannot listen on %d [%s]: (%d) %s",
				srv, url, errno, strerror(errno));
		goto errorLabel;
	}

	accept_add_any(ap,srv);
	return 1;
errorLabel:
	if (srv>=0)
		metautils_pclose(&srv);
	return 0;
}

static int
UNSAFE_accept_many_server(struct pollfd *pfd, int max,
		struct sockaddr *sa, socklen_t *saSize, GError **err)
{
	int nbEvents = poll(pfd, max, 2000);

	/* timeout or error */
	if (nbEvents == 0)
		return -1;
	if (nbEvents < 0) {
		if (errno != EINTR && errno != EAGAIN)
			GSETERROR(err,"poll error : %s", strerror(errno));
		return -1;
	}

	/* events! */
	for (int i=0; i<max ;i++) {
		if (!pfd[i].revents)
			continue;
		if (pfd[i].revents & POLLIN) {
			int clt = accept_nonblock(pfd[i].fd, sa, saSize);
			if (clt >= 0)
				return clt;
			if (errno != EAGAIN && errno != EINTR)
				GSETERROR(err,"accept error : %s", strerror(errno));
			return -1;
		}
	}

	return -1;
}

static int
UNSAFE_accept_do(ACCEPT_POOL ap, struct sockaddr *sa, socklen_t *saSize, GError **err)
{
	if (ap->count <= 0) {
		GSETERROR(err,"No server configured");
		return -1;
	}

	struct pollfd *pfd = g_alloca(ap->count * sizeof(struct pollfd));
	for (int i=0; i<ap->count ;i++) {
		pfd[i].fd = ap->srv[i];
		pfd[i].events = POLLIN;
		pfd[i].revents = 0;
	}

	int clt = -1;
	if (may_continue) {
		g_rec_mutex_lock (&(ap->mut));
		if (may_continue)
			clt = UNSAFE_accept_many_server(pfd, ap->count, sa, saSize, err);
		g_rec_mutex_unlock (&(ap->mut));
	}

	return clt;
}

gint
accept_do (ACCEPT_POOL ap, addr_info_t *cltaddr, GError **err)
{
	EXTRA_ASSERT(ap != NULL);

	if (!ap->srv || ap->count<=0) {
		GSETERROR(err, "Empty server socket pool");
		return -1;
	}

	struct sockaddr_storage sa = {};
	socklen_t saSize = sizeof(sa);

	errno=0;
	int clt = UNSAFE_accept_do (ap, (struct sockaddr*) &sa, &saSize, err);
	if (clt < 0)
		return -1;

	if (cltaddr != NULL) {
		memset(cltaddr, 0, sizeof(addr_info_t));
		addrinfo_from_sockaddr(cltaddr, (struct sockaddr*)&sa, saSize);
	}

	/*Set all the helpful socket options*/
	if (gridd_flags & GRIDD_FLAG_NOLINGER)
		sock_set_linger_default(clt);
	if (gridd_flags & GRIDD_FLAG_KEEPALIVE)
		sock_set_keepalive(clt, TRUE);
	if (gridd_flags & GRIDD_FLAG_QUICKACK)
		sock_set_tcpquickack(clt, TRUE);

	return clt;
}

void
accept_close_servers (ACCEPT_POOL ap)
{
	EXTRA_ASSERT(ap != NULL);

	int *pSrv = NULL; 
	int max=0;

	g_rec_mutex_lock (&(ap->mut));
	if (ap->srv) {
		pSrv = ap->srv;
		max = ap->count;
	}
	ap->srv = NULL;
	ap->count = 0;
	g_rec_mutex_unlock (&(ap->mut));

	if (pSrv) {
		for (int i=0; i<max ;i++) {
			if (pSrv[i] < 0)
				continue;
			errno=0;
			metautils_pclose(pSrv + i);
		}
	}

	g_free(pSrv);
}

gboolean
wait_for_socket(int fd, long ms)
{
	struct pollfd pfd;

retry:
	pfd.fd = fd;
	pfd.events = POLLIN|POLLERR|POLLHUP;
	pfd.revents = 0;
	int rc = poll(&pfd, 1, ms);
	if (rc < 0 && errno == EINTR)
		goto retry;
	return rc != 0;
}

