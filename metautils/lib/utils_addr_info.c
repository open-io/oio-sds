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

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>

#include <core/oiolb.h>

#include "metautils.h"

static gboolean
_zeroed(const void *data, gsize data_size)
{
	if (data != NULL) {
		for (gsize i=0; i<data_size ;++i) {
			if (((guint8*)data)[i])
				return FALSE;
		}
	}
	return TRUE;
}

gboolean
metautils_addr_valid_for_bind(const struct addr_info_s *a)
{
	/* @todo TODO we should check the address is not broadcast (local
	 * or global), not multicast, not network address, etc. */
	return a->port != 0;
}

gboolean
metautils_addr_valid_for_connect(const struct addr_info_s *a)
{
	/* @todo TODO we should check the address is not broadcast (local
	 * or global), not multicast, not network address, etc. */
	return a->port != 0 && !_zeroed(&(a->addr), sizeof(a->addr));
}

gboolean
metautils_url_valid_for_connect(const gchar *url)
{
	if (NULL == url) {
		errno = EINVAL;
		return FALSE;
	}
	addr_info_t ai = {{0}};
	if (!grid_string_to_addrinfo(url, &ai))
		return FALSE;
	return metautils_addr_valid_for_connect(&ai);
}

gboolean
metautils_url_valid_for_bind(const gchar *url)
{
	if (NULL == url) {
		errno = EINVAL;
		return FALSE;
	}
	addr_info_t ai = {{0}};
	if (!grid_string_to_addrinfo(url, &ai))
		return FALSE;
	return metautils_addr_valid_for_bind(&ai);
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

	memcpy(&addrA, a, sizeof(addr_info_t));
	memcpy(&addrB, b, sizeof(addr_info_t));

	if (addrA.type != addrB.type)
		return CMP(addrB.type,addrA.type);

	if (addrA.port != addrB.port)
		return CMP(addrB.port,addrA.port);

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
	memcpy(&addrA, a, sizeof(addr_info_t));
	memcpy(&addrB, b, sizeof(addr_info_t));

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
		return FALSE;
	}
}

guint
addr_info_hash(gconstpointer k)
{
	addr_info_t addr;

	memcpy(&addr, k, sizeof(addr_info_t));
	/*forces a NULL's padding if the address if ipv4 */
	if (addr.type == TADDR_V4)
		memset(
			((guint8 *) & (addr.addr.v4)) + sizeof(addr.addr.v4),
			0x00, sizeof(addr.addr.v6) - sizeof(addr.addr.v4));

	return djb_hash_buf((guint8 *) &addr, sizeof(addr_info_t));
}

oio_location_t
location_from_addr_info(const struct addr_info_s *addr)
{
	oio_location_t out = 0;
	if (addr->type == TADDR_V4)
		out = ((oio_location_t)ntohl(addr->addr.v4)) << 16;
	else  // Network is big-endian, we keep the least significant bytes
		out = (oio_location_t)addr->addr.v6[15] << 16
			| (oio_location_t)addr->addr.v6[14] << 24
			| (oio_location_t)addr->addr.v6[13] << 32
			| (oio_location_t)addr->addr.v6[12] << 40
			| (oio_location_t)addr->addr.v6[11] << 48
			| (oio_location_t)addr->addr.v6[10] << 56;
	out |= (oio_location_t)ntohs(addr->port);
	return out;
}
