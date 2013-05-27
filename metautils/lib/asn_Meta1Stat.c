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
#define LOG_DOMAIN "metacomm.meta1_stat.asn"
#endif

#include <errno.h>
#include <glib.h>

#include "metatypes.h"
#include "metautils.h"
#include "metacomm.h"

#include "Meta1Stat.h"
#include "asn_Meta1Stat.h"
#include "asn_Meta1Info.h"


gboolean
meta1_stat_ASN2API(const Meta1Stat_t * asn, meta1_stat_t * api)
{
	if (!api || !asn)
		return FALSE;

	asn_INTEGER_to_int8(&(asn->cpuIdle), &(api->cpu_idle));
	asn_INTEGER_to_int8(&(asn->reqIdle), &(api->req_idle));
	meta1_info_ASN2API(&(asn->info), &(api->info));

	return TRUE;
}


gboolean
meta1_stat_API2ASN(const meta1_stat_t * api, Meta1Stat_t * asn)
{
	if (!api || !asn)
		return FALSE;

	meta1_info_API2ASN(&(api->info), &(asn->info));
	asn_int8_to_INTEGER(&(asn->reqIdle), api->req_idle);
	asn_int8_to_INTEGER(&(asn->cpuIdle), api->cpu_idle);

	return TRUE;
}


void
meta1_stat_cleanASN(Meta1Stat_t * asn, gboolean only_content)
{
	if (!asn) {
		errno = EINVAL;
		return;
	}

	if (only_content)
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Meta1Stat, asn);
	else
		ASN_STRUCT_FREE(asn_DEF_Meta1Stat, asn);

	errno = 0;
}
