/*
OpenIO SDS metautils
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include "metautils.h"

gssize
grid_sockaddr_to_string(const struct sockaddr *s, gchar *dst, gsize dst_size)
{
	gchar tmp[STRLEN_ADDRINFO];
	uint16_t port = 0;

	if (NULL == s || NULL == dst || dst_size <= 0) {
		errno = EINVAL;
		return 0;
	}

	*dst = '\0';
	switch (s->sa_family) {
		case AF_INET:
			if (NULL == inet_ntop(AF_INET, &(((struct sockaddr_in*)s)->sin_addr),
					tmp, sizeof(tmp)))
				return 0;
			port = ((struct sockaddr_in*)s)->sin_port;
			return g_snprintf(dst, dst_size, "%s:%hu", tmp, g_ntohs(port));
		case AF_INET6:
			if (NULL == inet_ntop(AF_INET6, &(((struct sockaddr_in6*)s)->sin6_addr),
					tmp, sizeof(tmp)))
				return 0;
			port = ((struct sockaddr_in6*)s)->sin6_port;
			return g_snprintf(dst, dst_size, "[%s]:%hu", tmp, g_ntohs(port));
		default:
			return 0;
	}
}

gsize
grid_addrinfo_to_string(const struct addr_info_s *a, gchar *dst, gsize dst_size)
{
	gchar tmp[STRLEN_ADDRINFO];
	uint16_t port = 0;

	if (NULL == a || NULL == dst || dst_size <= 0) {
		errno = EINVAL;
		return 0;
	}

	*dst = '\0';
	port = a->port;

	switch (a->type) {
		case TADDR_V4:
			if (NULL == inet_ntop(AF_INET, &(a->addr.v4), tmp, sizeof(tmp)))
				return 0;
			return g_snprintf(dst, dst_size, "%s:%hu", tmp, g_ntohs(port));
		case TADDR_V6:
			if (NULL == inet_ntop(AF_INET6, a->addr.v6, tmp, sizeof(tmp)))
				return 0;
			return g_snprintf(dst, dst_size, "[%s]:%hu", tmp, g_ntohs(port));
		default:
			return 0;
	}
}

static gboolean
_port_parse (const char *start, guint16 *res)
{
	if (!g_ascii_isdigit(*start))
		return FALSE;

	gchar *sport_end = NULL;
	guint64 u64port = g_ascii_strtoull(start, &sport_end, 10);

	if (!u64port && errno == EINVAL)
		return FALSE;
	if (u64port >= G_MAXUINT16) {
		errno = ERANGE;
		return FALSE;
	}
	if (sport_end && *sport_end) {
		errno = EINVAL;
		return FALSE;
	}

	*res = u64port;
	return TRUE;
}

gboolean
grid_string_to_sockaddr(const gchar *start, struct sockaddr *s, gsize *slen)
{
	EXTRA_ASSERT (start != NULL);
	EXTRA_ASSERT (slen != NULL);

	if (!*start)
		return FALSE;

	gchar *addr = g_strdup (start);
	STRING_STACKIFY(addr);
	EXTRA_ASSERT(addr != NULL);

	if (*addr == '/') { // UNIX socket
		struct sockaddr_un *sun = (struct sockaddr_un*) s;
		*slen = sizeof(*sun);
		sun->sun_family = AF_UNIX;
		g_strlcpy(sun->sun_path, addr, sizeof(sun->sun_path));
		return TRUE;
	}

	// Find the ':' separator and fill the working buffers with each part
	gchar *colon = strrchr(addr, ':');
	if (!colon) return FALSE;
	*(colon++) = '\0';

	// Parse the port
	guint16 u16port = 0;
	if (!_port_parse(colon, &u16port))
		return 0;

	// And now, parse the address
	if (addr[0] == '[') {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6*) s;
		size_t l = strlen(addr);
		*slen = sizeof(struct sockaddr_in6);
		if (addr[l-1] == ']')
			addr[--l] = '\0';
		if (0 < inet_pton(AF_INET6, addr+1, &sin6->sin6_addr)) {
			sin6->sin6_family = AF_INET6;
			sin6->sin6_port = g_htons(u16port);
			return 1;
		}
	} else {
		struct sockaddr_in *sin = (struct sockaddr_in*) s;
		*slen = sizeof(struct sockaddr_in);
		if (0 < inet_pton(AF_INET, addr, &sin->sin_addr)) {
			sin->sin_family = AF_INET;
			sin->sin_port = g_htons(u16port);
			return 1;
		}
	}
	return 0;
}

gboolean
grid_string_to_addrinfo(const gchar *start, struct addr_info_s *a)
{
	struct sockaddr_storage sas;
	gsize sas_len = sizeof(sas);
	if (!grid_string_to_sockaddr(start, (struct sockaddr*)&sas, &sas_len))
		return FALSE;
	return addrinfo_from_sockaddr (a, (struct sockaddr*)&sas, sas_len);
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
		return 1;
	case TADDR_V6:
		if (*saSize < sizeof(struct sockaddr_in6))
			return 0;
		sa6 = (struct sockaddr_in6 *) sa;
		sa6->sin6_family = AF_INET6;
		sa6->sin6_port = ai->port;
		memcpy(&(sa6->sin6_addr), &(ai->addr), sizeof(struct in6_addr));
		*saSize = sizeof(struct sockaddr_in6);
		return 1;
	default:
		return 0;
	}
}

gint
addrinfo_from_sockaddr(addr_info_t * ai, struct sockaddr * sa, gsize saSize)
{
	struct sockaddr_in *sa4;
	struct sockaddr_in6 *sa6;

	if (!ai || !sa || saSize <= 6)
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
		return 1;
	case AF_INET6:
		if (saSize < sizeof(struct sockaddr_in6))
			return 0;
		sa6 = (struct sockaddr_in6 *) sa;
		ai->type = TADDR_V6;
		ai->port = sa6->sin6_port;
		memcpy(&(ai->addr), &(sa6->sin6_addr), sizeof(struct in6_addr));
		return 1;
	default:
		return 0;
	}
}

