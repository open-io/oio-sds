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
# define LOG_DOMAIN "metacomm.meta2_info"
#endif

#include "./metautils_internals.h"
#include "./asn_Meta2Info.h"
#include "./Meta2Info.h"
#include "./Meta2InfoSequence.h"

static struct abstract_sequence_handler_s seq_descriptor = {
	sizeof(Meta2Info_t),
	sizeof(meta2_info_t),
	&asn_DEF_Meta2InfoSequence,
	(abstract_converter_f) meta2_info_ASN2API,
	(abstract_converter_f) meta2_info_API2ASN,
	(abstract_asn_cleaner_f) meta2_info_cleanASN,
	(abstract_api_cleaner_f) g_free,
	"meta2_info"
};

DEFINE_MARSHALLER_GBA(meta2_info_marshall_gba)
    DEFINE_MARSHALLER(meta2_info_marshall)
    DEFINE_UNMARSHALLER(meta2_info_unmarshall)
