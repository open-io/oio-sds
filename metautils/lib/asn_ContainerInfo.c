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
#define LOG_DOMAIN "metacomm.container_info.asn"
#endif

#include <errno.h>
#include <glib.h>

#include "./metatypes.h"
#include "./metautils.h"
#include "./metacomm.h"

#include "./asn_ContainerInfo.h"

gboolean
container_info_ASN2API(const ContainerInfo_t * asn, container_info_t * api)
{
	if (!api || !asn)
		return FALSE;

	memset(api, 0x00, sizeof(container_info_t));
	
	/* cid */
	g_memmove(api->id, asn->id.buf, asn->id.size);

	/* size */
	asn_INTEGER_to_int64(&(asn->size), &(api->size));

	return TRUE;
}


gboolean
container_info_API2ASN(const container_info_t * api, ContainerInfo_t * asn)
{
	if (!api || !asn)
		return FALSE;

	memset(asn, 0x00, sizeof(ContainerInfo_t));

        /* cID */
        OCTET_STRING_fromBuf(&(asn->id), (char *) api->id, sizeof(container_id_t));

	/*size */
	asn_int64_to_INTEGER(&(asn->size), api->size);

	return TRUE;
}


void
container_info_cleanASN(ContainerInfo_t * asn, gboolean only_content)
{
	if (!asn) {
		errno = EINVAL;
		return;
	}

	if (only_content)
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_ContainerInfo, asn);
	else
		ASN_STRUCT_FREE(asn_DEF_ContainerInfo, asn);

	errno = 0;
}
