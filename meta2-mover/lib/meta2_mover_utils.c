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

#include "./meta2_mover_internals.h"
#include <grid_client.h>

struct xcid_s *
xcid_from_hexa(const gchar *h)
{
	struct xcid_s result;

	memset(&result, 0x00, sizeof(result));
	if (!container_id_hex2bin(h, strlen(h), &(result.cid), NULL))
		return NULL;
	container_id_to_string(result.cid, result.str, sizeof(result.str));
	return g_memdup(&result, sizeof(result));
}

void
xcid_free(struct xcid_s *scid)
{
	if (!scid)
		return;
	if (scid->location)
		gs_container_location_free(scid->location);
	g_free(scid);
}

GError*
xaddr_init_from_addr(struct xaddr_s *x, const addr_info_t *ai)
{
	g_assert(x != NULL);
	g_assert(ai != NULL);

	memset(x, 0x00, sizeof(*x));
	metacnx_clear(&(x->cnx));

	memcpy(&(x->addr), ai, sizeof(addr_info_t));
	addr_info_to_string(&(x->addr), x->str, sizeof(x->str)-1);
	metacnx_init_with_addr(&(x->cnx), &(x->addr), NULL);

	x->cnx.timeout.req = x->cnx.timeout.cnx = 90000;
	return NULL;
}

GError*
xaddr_init_from_url(struct xaddr_s *x, const gchar *url)
{
	g_assert(x != NULL);
	g_assert(url != NULL);

	memset(x, 0x00, sizeof(*x));
	metacnx_clear(&(x->cnx));

	l4_address_init_with_url(&(x->addr), url, NULL);
	addr_info_to_string(&(x->addr), x->str, sizeof(x->str)-1);
	metacnx_init_with_addr(&(x->cnx), &(x->addr), NULL);

	x->cnx.timeout.req = x->cnx.timeout.cnx = 90000;
	return NULL;
}

