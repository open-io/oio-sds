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

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <metautils/lib/metautils.h>

#include "./sock.h"
#include "./server_internals.h"
#include "./srvalert.h"

#define FAMILY(S) ((struct sockaddr*)(S))->sa_family
#define ADDRLEN(A) (((struct sockaddr*)(A))->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))

#include <poll.h>

gint
format_addr (struct sockaddr *sa, gchar *h, gsize hL, gchar *p, gsize pL, GError **err)
{
	if (!sa) {
		GSETERROR(err,"Invalid parameter");
		return 0;
	}

	memset (h, 0x00, hL);
	memset (p, 0x00, pL);

	*h = '?';
	*p = '?';

	/*no reverse resolution, only numeric addresses*/
	if (0 != getnameinfo (sa, ADDRLEN(sa), h, hL, p, pL, NI_NUMERICHOST|NI_NUMERICSERV)) {
		GSETERROR(err, "Cannot format the address (%s)", strerror(errno));
		return 0;
	}

	return 1;
}

gint
resolve (struct sockaddr_storage *sa, const gchar *h, const gchar *p, GError **err)
{
	gint retCode;
	struct addrinfo *ai=0, aiHint;

	if (!sa) {
		GSETERROR(err, "Invalid parameter");
		return 0;
	}

	memset(&aiHint, 0x00, sizeof(struct addrinfo));
	aiHint.ai_family = PF_UNSPEC;
	aiHint.ai_socktype = SOCK_STREAM;
	retCode = getaddrinfo (h, p, &aiHint, &ai);
	if (retCode != 0) {
		GSETERROR(err,"Cannot resolve [%s]:%s (%s)", (h?h:"0.0.0.0"), (p?p:"NOPORT"), gai_strerror(retCode));
		return 0;
	}
	if (!ai) {
		GSETERROR(err,"Cannot resolve [%s]:%s (%s)", (h?h:"0.0.0.0"), (p?p:"NOPORT"), "Unknown error");
		return 0;
	}

	memcpy (sa, ai->ai_addr, ai->ai_addrlen);
	freeaddrinfo(ai);
	return 1;
}

gint
accept_make(ACCEPT_POOL *s, GError **err)
{
	struct accept_pool_s *ap=NULL;

	if (!s) {
		GSETERROR(err,"Invalid parameter");
		goto error_param;
	}

	ap = g_try_malloc0 (sizeof(struct accept_pool_s));
	if (!ap) {
		GSETERROR(err,"Memory allocation error");
		goto error_pool;
	}

	g_rec_mutex_init(&(ap->mut));

	ap->count = 0;
	ap->size = 2;
	ap->srv = g_try_malloc0 (ap->size * sizeof(gint));
	if (!ap->srv) {
		GSETERROR(err,"Memory allocation failure");
		goto error_array;
	} else {
		int i;
		for (i=0; i<ap->size ;i++)
			ap->srv[i]=-1;
	}
	*s = ap;

	return 1;

error_array:
	g_free(ap);
error_pool:
error_param:
	return 0;
}

static const char*
_get_family_name (int f)
{
	switch (f) {
		case PF_LOCAL: return "PF_LOCAL";
		case PF_INET: return "PF_INET";
		case PF_INET6: return "PF_INET6";
		case PF_UNSPEC: return "PF_UNSPEC";
	}
	return "?";
}

static gint
accept_add_any (ACCEPT_POOL ap, int srv, GError **err)
{
	gint rc = 0;
	if (!ap || srv<0)
	{
		GSETERROR (err, "Invalid parameter");
		return 0;
	}

	g_rec_mutex_lock (&(ap->mut));

	/*allocates an array if it is necessary*/
	if (!ap->srv) {
		GSETERROR(err, "AcceptPool not initialized (should not happen)");
		goto exitLabel;
	}

	/*make the arrays grows if it is too small*/
	if (ap->size <= ap->count) {
		gint *newSrv, newSize;
		newSize = ap->size + 2;
		newSrv = g_try_realloc (ap->srv, sizeof(gint) * newSize);
		if (!newSrv)
		{
			GSETERROR(err, "Memory allocation error (%s)", strerror(errno));
			goto exitLabel;
		}
		memset (newSrv+ap->size, 0x00, sizeof(gint) * 2);
		ap->size = newSize;
		ap->srv = newSrv;
	}

	ap->srv [ap->count++] = srv;

	rc = 1;
exitLabel:
	g_rec_mutex_unlock (&(ap->mut));
	return rc;
}

static gint
accept_add_inet (ACCEPT_POOL ap, const gchar *h, const gchar *p, GError **err)
{
	struct sockaddr_storage sa;
	gint srv = -1;

	if (!ap || !p)
	{
		GSETERROR (err, "Invalid parameter");
		goto errorLabel;
	}

	if (!h || !(*h))
		h = "0.0.0.0";

	if (!resolve (&sa, h, p, err))
	{
		GSETERROR(err,"Cannot resolve [%s]:%s", h, p);
		goto errorLabel;
	}

	/*create the server socket*/
	if (-1 == (srv = socket (FAMILY(&sa), SOCK_STREAM, 0)))
	{
		GSETERROR(err,"Cannot open a %s socket (%s)", _get_family_name(FAMILY(&sa)), strerror(errno));
		goto errorLabel;
	}

	if (!sock_set_reuseaddr(srv, TRUE)) {
		GSETERROR(err,"Cannot set SO_REUSEADDR on %d [%s]:%s (%s)", srv, h, p, strerror(errno));
		goto errorLabel;
	}

	fcntl(srv, F_SETFL, O_NONBLOCK|fcntl(srv, F_GETFL));

	if (-1 == bind (srv, (struct sockaddr*)(&sa), sizeof(struct sockaddr_in)))
	{
		GSETERROR(err,"Cannot bind %d on [%s]:%s (%s)", srv, h, p, strerror(errno));
		goto errorLabel;
	}

	if (-1 == listen (srv,AP_BACKLOG))
	{
		GSETERROR(err,"Cannot listen on %d [%s]:%s (%s)", srv, h, p, strerror(errno));
		goto errorLabel;
	}

	if (!accept_add_any(ap,srv,err))
	{
		GSETERROR(err,"Cannot monitor %s srv=%d", _get_family_name(FAMILY(&sa)), srv);
		goto errorLabel;
	}

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
accept_add (ACCEPT_POOL ap, const gchar *url, GError **err)
{
	if (!ap || !url || !(*url)) {
		GSETERROR(err,"Invalid parameter");
		return 0;
	}

		char *colon;
		if (!(colon=strrchr(url,':'))) {
			/*url supposed to be only a port*/
			return accept_add_inet (ap, NULL, url, err);
		}
		else {
			/*url supposed to be host:port*/
			/**@todo TODO manage ipv6 addresses format*/
			*colon = '\0';
			return accept_add_inet (ap, url, colon+1, err);
		}
}

gint
accept_do (ACCEPT_POOL ap, addr_info_t *cltaddr, GError **err)
{
	struct sockaddr_storage sa;
	socklen_t saSize;
	int clt;

	errno=0;

	if (!ap) {
		GSETERROR(err,"Invalid parameter");
		return -1;
	}

	if (!ap->srv || ap->count<=0) {
		GSETERROR(err, "Empty server socket pool");
		return -1;
	}

	memset(&sa, 0, sizeof(sa));
	saSize = sizeof(sa);
	clt = UNSAFE_accept_do (ap, (struct sockaddr*) &sa, &saSize, err);

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

