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

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.resolv"
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <metatypes.h>
#include <metautils.h>

#include "./resolv.h"

void
grid_sockaddr_to_string(const struct sockaddr *s, gchar *dst, gsize dst_size)
{
	size_t len;
	uint16_t port = 0;

	/* now the address */
	switch (s->sa_family) {
		case AF_INET:
			port = ((struct sockaddr_in*)s)->sin_port;
			inet_ntop(AF_INET, &(((struct sockaddr_in*)s)->sin_addr), dst, dst_size);
			break;
		case AF_INET6:
			port = ((struct sockaddr_in6*)s)->sin6_port;
			inet_ntop(AF_INET6, &(((struct sockaddr_in6*)s)->sin6_addr), dst, dst_size);
			break;
		default:
			dst[0] = '?';
			dst[1] = 0;
			break;
	}

	/* the the port just after */
	len = strlen(dst);
	dst[len++] = ':';
	g_snprintf(dst+len, dst_size-len, "%hu", g_ntohs(port));
}

void
grid_addrinfo_to_string(const struct addr_info_s *a, gchar *dst, gsize dst_size)
{
	size_t len;

	/* now the address */
	switch (a->type) {
		case TADDR_V4:
			inet_ntop(AF_INET, &(a->addr.v4), dst, dst_size);
			break;
		case TADDR_V6:
			inet_ntop(AF_INET6, a->addr.v6, dst, dst_size);
			break;
		default:
			dst[0] = '?';
			dst[1] = 0;
			break;
	}

	/* the the port just after */
	len = strlen(dst);
	dst[len++] = ':';
	g_snprintf(dst+len, dst_size-len, "%hu", g_ntohs(a->port));
}

gboolean
grid_string_to_addrinfo(const gchar *start, const gchar *end, struct addr_info_s *a)
{
	const gchar *colon;
	gchar addr[64], port[32];

	if (!end)
		end = start + strlen(start);

	/* Find the ':' separator */
	for (colon=end; colon>=start && *colon != ':';colon--);
	if (colon<=start || colon>=(end-1) || *colon!=':') {
		errno = EINVAL;
		return FALSE;
	}

	/* After the ':', there is a port */
	memset(port, 0, sizeof(port));
	memcpy(port, colon+1, MIN((unsigned int)sizeof(port)-1, end-(colon+1)));

	memset(addr, 0, sizeof(addr));
	memcpy(addr, start, MIN((unsigned int)sizeof(addr)-1, colon-start));

	a->port = g_htons(g_ascii_strtoll(port, NULL, 10));
	a->type = TADDR_V4;
	return 0 < inet_pton(AF_INET, addr, &(a->addr.v4));
}

gboolean
grid_string_to_sockaddr(const gchar *src, const gchar *end,
		struct sockaddr *s, gsize *slen)
{
	struct addr_info_s ai;

	memset(&ai, 0, sizeof(struct addr_info_s));
	if (!grid_string_to_addrinfo(src, end, &ai))
		return FALSE;

	return 0 != addrinfo_to_sockaddr(&ai, s, slen);
}

