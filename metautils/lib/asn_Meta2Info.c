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
#define LOG_DOMAIN "metacomm.meta2_info.asn"
#endif

#include <errno.h>
#include <glib.h>

#include "./metatypes.h"
#include "./metautils.h"
#include "./metacomm.h"

#include "asn_Meta2Info.h"
#include "asn_AddrInfo.h"
#include "asn_Score.h"


gboolean
meta2_info_ASN2API(const Meta2Info_t * asn, meta2_info_t * api)
{
	if (!api || !asn)
		return FALSE;

	score_ASN2API(&(asn->score), &(api->score));
	addr_info_ASN2API(&(asn->addr), &(api->addr));

	return TRUE;
}


gboolean
meta2_info_API2ASN(const meta2_info_t * api, Meta2Info_t * asn)
{
	if (!api || !asn)
		return FALSE;

	addr_info_API2ASN(&(api->addr), &(asn->addr));
	score_API2ASN(&(api->score), &(asn->score));

	return TRUE;
}


void
meta2_info_cleanASN(Meta2Info_t * asn, gboolean only_content)
{
	if (!asn) {
		errno = EINVAL;
		return;
	}

	if (only_content)
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Meta2Info, asn);
	else
		ASN_STRUCT_FREE(asn_DEF_Meta2Info, asn);

	errno = 0;
}
