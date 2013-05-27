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

#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif

#ifndef LOG_DOMAIN
#define LOG_DOMAIN "metautils"
#endif

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "./metautils.h"
#include "./metacomm.h"

gsize
addr_info_to_string(const addr_info_t * ai, gchar * dst, gsize dstSize)
{
	memset(dst, 0, dstSize);
	grid_addrinfo_to_string(ai, dst, dstSize);
	return strlen(dst);
}

gboolean
addr_info_get_addr(const addr_info_t * ai, gchar * dst, gsize dstSize, guint16 *port, GError** error)
{
	union
	{
		struct sockaddr i;
		struct sockaddr_storage sas;
	} addr;
	gsize addrSize;
	gchar buf[NI_MAXHOST];

	if (!dst || !ai) {
		GSETERROR(error, "missing argument(s)");
		return FALSE;
	}

	addrSize = sizeof(addr);
	addrinfo_to_sockaddr(ai, &(addr.i), &addrSize);

	if (0 != getnameinfo(&(addr.i), addrSize, buf, NI_MAXHOST, NULL, 0, NI_NUMERICHOST)) {
		GSETERROR(error, "%s", strerror(errno));
		GSETERROR(error, "Failed to get hostname for addr");
		return FALSE;
	}

	if (ai->type == TADDR_V4)
		g_snprintf(dst, dstSize, "%*.*s", 1, NI_MAXHOST, buf);
	else
		g_snprintf(dst, dstSize, "[%*.*s]", 1, NI_MAXHOST, buf);

	*port = ntohs(ai->port);

	return TRUE;
}

void
addr_info_print_all(const gchar * domain, GSList * list, const gchar * header)
{
	GSList *l;
	gchar str_addr[256];

	for (l = list; l; l = l->next) {
		if (!l->data)
			continue;
		memset(str_addr, 0x00, sizeof(str_addr));
		addr_info_to_string((addr_info_t *) (l->data), str_addr, sizeof(str_addr));
		TRACE_DOMAIN(domain, "%s%s", header, str_addr);
	}
}


gint
addrinfo_to_sockaddr(const addr_info_t * ai, struct sockaddr *sa, gsize * saSize)
{
	struct sockaddr_in *sa4;
	struct sockaddr_in6 *sa6;

	if (!ai || !sa || !saSize || *saSize <= 6 /*family(2) + ipv4(4) */ )
		return 0;
	memset(sa, 0x00, *saSize);

	switch (ai->type) {
	case TADDR_V4:
		if (*saSize < sizeof(struct sockaddr_in))
			return 0;
		sa4 = (struct sockaddr_in *) sa;
		sa4->sin_family = AF_INET;
		sa4->sin_port = ai->port;
		sa4->sin_addr.s_addr = ai->addr.v4;
		*saSize = sizeof(struct sockaddr_in);
		break;
	case TADDR_V6:
		if (*saSize < sizeof(struct sockaddr_in6))
			return 0;
		sa6 = (struct sockaddr_in6 *) sa;
		sa6->sin6_family = AF_INET6;
		sa6->sin6_port = ai->port;
		memcpy(&(sa6->sin6_addr), &(ai->addr), sizeof(struct in6_addr));
		*saSize = sizeof(struct sockaddr_in6);
		break;
	default:
		return 0;
	}
	return 1;
}


gint
addrinfo_from_sockaddr(addr_info_t * ai, struct sockaddr * sa, gsize saSize)
{
	struct sockaddr_in *sa4;
	struct sockaddr_in6 *sa6;

	if (!ai || !sa || saSize <= 6 /*family(2) + ipv4(4) */ )
		return 0;
	memset(ai, 0x00, sizeof(addr_info_t));

	switch (sa->sa_family) {
	case AF_INET:
		if (saSize < sizeof(struct sockaddr_in))
			return 0;
		sa4 = (struct sockaddr_in *) sa;
		ai->type = TADDR_V4;
		ai->port = sa4->sin_port;
		ai->addr.v4 = sa4->sin_addr.s_addr;
		break;
	case AF_INET6:
		if (saSize < sizeof(struct sockaddr_in6))
			return 0;
		sa6 = (struct sockaddr_in6 *) sa;
		ai->type = TADDR_V6;
		ai->port = sa6->sin6_port;
		memcpy(&(ai->addr), &(sa6->sin6_addr), sizeof(struct in6_addr));
		break;
	default:
		return 0;
	}
	return 1;
}


gint
addrinfo_connect(const addr_info_t * a, gint ms, GError ** err)
{
	gchar dbgBuf[256];

	struct sockaddr_storage sas;
	gsize sasSize = sizeof(struct sockaddr_storage);
	int fd = -1, retCode = 0;

	addr_info_to_string(a, dbgBuf, sizeof(dbgBuf));

	if (!addrinfo_to_sockaddr(a, (struct sockaddr *) &sas, &sasSize)) {
		GSETERROR(err, "addr_info conversion error");
		return -1;
	}

	fd = socket(sas.ss_family, SOCK_STREAM, 0);
	if (fd < 0) {
		GSETERROR(err, "connect(%s) : socket error (%s)", dbgBuf, strerror(errno));
		return -1;
	}

	if (ms > 0) {
		sock_set_reuseaddr(fd, TRUE);
		sock_set_linger(fd, 1, 0);
		if (!sock_set_non_blocking(fd, TRUE)) {
			GSETERROR(err, "connect(%s) : non blocking mode impossible", dbgBuf);
			close(fd);
			return -1;
		}
	}

	retCode = connect(fd, (struct sockaddr *) &sas, sasSize);
	if (retCode == 0) {
		TRACE("connect(%s) fd=%i", dbgBuf, fd);
		return fd;
	}
	if (errno == EALREADY) {
		errno = 0;
		return fd;
	}
	if (ms <= 0) {
		GSETERROR(err, "connect(%s) : errno=%d (%s)", dbgBuf, ms, strerror(errno));
		close(fd);
		return -1;
	}
	if (errno != EINPROGRESS && errno != EINTR) {
		GSETERROR(err, "connect(%s) : errno=%d (%s)", dbgBuf, ms, strerror(errno));
		close(fd);
		return -1;
	}

	for (;;) {
		struct pollfd p;

		p.fd = fd;
		p.events = POLLOUT | POLLERR | POLLNVAL | POLLHUP;
		p.revents = 0;

		retCode = poll(&p, 1, ms);

		if (retCode == 0) {	/*timeout */
			GSETCODE(err, ERRCODE_CONN_TIMEOUT, "connect(%s) : timeout after %d ms", dbgBuf, ms);
			break;
		}
		if (retCode == -1) {
			if (errno == EINTR)
				continue;
			GSETERROR(err, "connect(%s) : poll error: errno=%d (%s)",
					dbgBuf, errno, strerror(errno));
			break;
		}
		if ((p.revents & POLLERR) || (p.revents & POLLHUP) || (p.revents & POLLNVAL)) {
			int e = sock_get_error(fd);
			GSETCODE(err, CODE_NETWORK_ERROR, "connect(%s) : socket error (poll:%04X errno=%d %s)",
					dbgBuf, p.revents, e, strerror(e));
			break;
		}
		if (p.revents & POLLOUT) {
			TRACE("connect(%s) fd=%d", dbgBuf, fd);
			return fd;
		}
		GSETERROR(err, "connect(%s) : poll error: unexpected flag %04X)", dbgBuf, p.revents);
		break;
	}
	/* executed only upon error */
	errno = 0;
	close(fd);
	return -1;
}


addr_info_t *
build_addr_info(const gchar * ip, int port, GError ** err)
{
	struct addrinfo *res = NULL, hint;
	addr_info_t *addr = NULL;
	int rc = 0;

	if (!ip || !*ip) {
		GSETERROR(err, "invalid address");
		return NULL;
	}

	if (port < 0 || port > 65535) {
		GSETERROR(err, "invalid port : %d", port);
		return NULL;
	}

	hint.ai_protocol = 0;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_family = PF_UNSPEC;
	hint.ai_flags = AI_NUMERICHOST;

	rc = getaddrinfo(ip, NULL, &hint, &res);
	if (rc) {
		GSETERROR(err, "resolution error : %s", gai_strerror(rc));
		return NULL;
	}


	addr = g_malloc0(sizeof(addr_info_t));

	if (res->ai_family == PF_INET) {
		struct sockaddr_in *i4;

		addr->type = TADDR_V4;
		i4 = (struct sockaddr_in *) (res->ai_addr);
		addr->addr.v4 = (guint32) i4->sin_addr.s_addr;
	}
	else if (res->ai_family == PF_INET6) {
		struct sockaddr_in6 *i6;

		addr->type = TADDR_V6;
		i6 = (struct sockaddr_in6 *) (res->ai_addr);
		memcpy(&(addr->addr.v6), &(i6->sin6_addr.s6_addr), 16);
	}

	addr->port = htons(port);

	freeaddrinfo(res);

	return addr;
}


void
addr_info_clean(gpointer p)
{
	if (p)
		g_free(p);
}

void
addr_info_gclean(gpointer d, gpointer u)
{
	(void) u;
	if (d)
		g_free(d);
}

gboolean
l4_address_split(const gchar * url, gchar ** host, gchar ** port)
{
	int len;
	gchar wrkUrl[512];

	if (!host || !port)
		return FALSE;

	g_strlcpy(wrkUrl, url, sizeof(wrkUrl));
	len = strlen(wrkUrl);

	if (*wrkUrl == '[') {	/*[IP]:PORT */
		gchar *last_semicolon;

		last_semicolon = g_strrstr(wrkUrl, ":");

		if (!last_semicolon || last_semicolon - wrkUrl >= len)
			return FALSE;

		*(last_semicolon - 1) = '\0';
		*port = g_strdup(last_semicolon + 1);
		*host = g_strdup(wrkUrl + 1);
	}
	else {
		gchar *last_semicolon;

		last_semicolon = g_strrstr(wrkUrl, ":");

		if (!last_semicolon || last_semicolon - wrkUrl >= len)
			return FALSE;

		*last_semicolon = '\0';
		*port = g_strdup(last_semicolon + 1);
		*host = g_strdup(wrkUrl);
	}
	return TRUE;
}

gboolean
l4_address_init_with_url(addr_info_t * dst, const gchar * url, GError ** err)
{
	addr_info_t *ai;
	gchar *str_host, *str_port;

	if (!dst || !url) {
		GSETERROR(err, "Invalid parameter (dst=%p url=%p)", dst, url);
		return FALSE;
	}

	str_port = str_host = NULL;
	if (!l4_address_split(url, &str_host, &str_port)) {
		GSETERROR(err, "Invalid URL format");
		return FALSE;
	}

	ai = build_addr_info(str_host, atoi(str_port), err);
	g_free(str_host);
	g_free(str_port);
	if (!ai) {
		GSETERROR(err, "Invalid URL address or port");
		return FALSE;
	}
	memcpy(dst, ai, sizeof(addr_info_t));
	g_free(ai);
	return TRUE;
}

gint
addr_info_compare(gconstpointer a, gconstpointer b)
{
	addr_info_t addrA, addrB;

	if (!a || !b)
		return 0;
	if (a == b)
		return TRUE;

	memset(&addrA, 0, sizeof(addr_info_t));
	memset(&addrB, 0, sizeof(addr_info_t));

	g_memmove(&addrA, a, sizeof(addr_info_t));
	g_memmove(&addrB, b, sizeof(addr_info_t));

	if (addrA.type != addrB.type)
		return (addrB.type > addrA.type) ? 1 : (addrB.type < addrA.type ? -1 : 0);

	if (addrA.port != addrB.port)
		return (addrB.port > addrA.port) ? 1 : (addrB.port < addrA.port ? -1 : 0);

	switch (addrA.type) {
		case TADDR_V4:
			return memcmp(&(addrA.addr), &(addrB.addr), sizeof(addrA.addr.v4));
		case TADDR_V6:
			return memcmp(&(addrA.addr), &(addrB.addr), sizeof(addrA.addr.v6));
		default:
			g_assert_not_reached();
			return 0;
	}
}

gboolean
addr_info_equal(gconstpointer a, gconstpointer b)
{
	addr_info_t addrA, addrB;

	if (!a || !b)
		return FALSE;
	if (a == b)
		return TRUE;
	g_memmove(&addrA, a, sizeof(addr_info_t));
	g_memmove(&addrB, b, sizeof(addr_info_t));

	if (addrA.type != addrB.type)
		return FALSE;

	if (addrA.port != addrB.port)
		return FALSE;

	switch (addrA.type) {
	case TADDR_V4:
		return 0 == memcmp(&(addrA.addr), &(addrB.addr), sizeof(addrA.addr.v4)) ? TRUE : FALSE;
	case TADDR_V6:
		return 0 == memcmp(&(addrA.addr), &(addrB.addr), sizeof(addrA.addr.v6)) ? TRUE : FALSE;
	default:
		FATAL("Invalid address type");
		return FALSE;
	}
}

guint
addr_info_hash(gconstpointer k)
{
	size_t i;
	guint8 *b;
	guint32 h = 5381;

	addr_info_t addr;

	g_memmove(&addr, k, sizeof(addr_info_t));

	/*forces a NULL's padding if the address if ipv4 */
	if (addr.type == TADDR_V4)
		memset(
		    ((guint8 *) & (addr.addr.v4)) + sizeof(addr.addr.v4),
		    0x00, sizeof(addr.addr.v6) - sizeof(addr.addr.v4));

	b = (guint8 *) & addr;

	for (i = 0; i < sizeof(addr); i++)
		h = ((h << 5) + h) ^ (guint32) (b[i]);

	return h;
}

addr_info_t *
addr_info_from_service_str(const gchar *service)
{
	gchar **t = NULL;
	gchar **addr_tok = NULL;
	GError *local_error = NULL;
	addr_info_t* addr = NULL;

	t = g_strsplit(service, "|", 3);
	if(g_strv_length(t) != 3) {
		goto end_label;
	}

	addr_tok = g_strsplit(t[2], ":", 2);
	if(g_strv_length(addr_tok) != 2) {
		goto end_label;
	}

	addr = build_addr_info(addr_tok[0], atoi(addr_tok[1]), &local_error);

end_label:

	if(local_error)
		g_clear_error(&local_error);
	if(addr_tok)
		g_strfreev(addr_tok);
	if(t)
		g_strfreev(t);
	return addr;
}
