#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.resolv"
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "metatypes.h"
#include "metautils_bits.h"
#include "metautils_errors.h"
#include "metautils_resolv.h"

gboolean
addr_info_get_addr(const addr_info_t * a, gchar *d, gsize dsize, guint16 *port)
{
	if (NULL == port || NULL == d || NULL == a)
		return FALSE;

	*port = ntohs(a->port);

	switch (a->type) {
		case TADDR_V4:
			return (NULL != inet_ntop(AF_INET, &(a->addr.v4), d, dsize));
		case TADDR_V6:
			return (NULL != inet_ntop(AF_INET6, a->addr.v6, d, dsize));
		default:
			return 0;
	}
}

gssize
grid_sockaddr_to_string(const struct sockaddr *s, gchar *dst, gsize dst_size)
{
	gchar tmp[256];
	uint16_t port = 0;

	if (NULL == s || NULL == dst || dst_size <= 0) {
		errno = EINVAL;
		return 0;
	}

	memset(dst, 0, dst_size);

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
	gchar tmp[256];
	uint16_t port = 0;

	if (NULL == a || NULL == dst || dst_size <= 0) {
		errno = EINVAL;
		return 0;
	}

	memset(dst, 0, dst_size);
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

static inline gboolean
_port_parse(const gchar *start, const gchar *end, guint16 *res)
{
	gchar *sport_end = NULL;
	guint64 u64port;

	if (start == end || !g_ascii_isdigit(start[0]))
		return FALSE;

	u64port = g_ascii_strtoull(start, &sport_end, 10);

	if (!u64port && errno == EINVAL)
		return FALSE;
	if (u64port >= G_MAXUINT16) {
		errno = ERANGE;
		return FALSE;
	}
	else if (sport_end != end) {
		errno = EINVAL;
		return FALSE;
	}

	*res = u64port;
	return TRUE;
}

gboolean
grid_string_to_addrinfo(const gchar *start, const gchar *end, struct addr_info_s *a)
{
	const gchar *colon;
	gchar addr[256];

	if (NULL == start || NULL == a) {
		errno = EINVAL;
		return FALSE;
	}

	if (!end)
		end = start + strlen(start);

	// Find the ':' separator and fill the working buffers with each part
	for (colon=end; colon>=start && *colon != ':';colon--);
	if (colon<=start || colon>=(end-1) || *colon!=':') {
		errno = EINVAL;
		return 0;
	}

	memset(addr, 0, sizeof(addr));
	memcpy(addr, start, FUNC_MIN(sizeof(addr)-1, colon-start));

	// Parse the port
	guint16 u16port = 0;
	if (!_port_parse(colon+1, end, &u16port)) {
		return 0;
	}
	a->port = g_htons(u16port);
	a->protocol = 0;

	// And now, parse the address
	if (addr[0] == '[') {
		size_t l = strlen(addr);
		if (addr[l-1] == ']')
			addr[--l] = '\0';
		if (0 < inet_pton(AF_INET6, addr+1, &(a->addr.v6))) {
			a->type = TADDR_V6;
			return 1;
		}
	}
	else {
		if (0 < inet_pton(AF_INET, addr, &(a->addr.v4))) {
			a->type = TADDR_V4;
			return 1;
		}
	}
	return 0;
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

gboolean
l4_address_init_with_url(addr_info_t * dst, const gchar * url, GError ** err)
{
	if (grid_string_to_addrinfo(url, NULL, dst))
		return TRUE;
	GSETCODE(err, 0, "AddrInfo parsing error");
	return FALSE;
}

addr_info_t *
build_addr_info(const gchar * ip, int port, GError ** err)
{
	if (NULL == ip || port < 0) {
		GSETCODE(err, EINVAL, "Invalid parameter");
		return NULL;
	}

	gchar buf[256];
	struct addr_info_s ai;

	if (NULL != strchr(ip, ':'))
		g_snprintf(buf, sizeof(buf), "[%s]:%d", ip, port);
	else
		g_snprintf(buf, sizeof(buf), "%s:%d", ip, port);

	if (!grid_string_to_addrinfo(buf, NULL, &ai)) {
		GSETCODE(err, EINVAL, "Impossible conversion");
		return NULL;
	}

	return g_memdup(&ai, sizeof(struct addr_info_s));
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

