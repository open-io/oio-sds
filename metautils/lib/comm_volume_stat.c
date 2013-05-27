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
# define LOG_DOMAIN "metacomm.volume_stat"
#endif

#include "./metautils_internals.h"
#include "./asn_VolumeStat.h"
#include "./VolumeStat.h"
#include "./VolumeStatSequence.h"

static struct abstract_sequence_handler_s seq_descriptor = {
	sizeof(VolumeStat_t),
	sizeof(volume_stat_t),
	&asn_DEF_VolumeStatSequence,
	(abstract_converter_f) volume_stat_ASN2API,
	(abstract_converter_f) volume_stat_API2ASN,
	(abstract_asn_cleaner_f) volume_stat_cleanASN,
	(abstract_api_cleaner_f) g_free,
	"volume_stat"
};

DEFINE_MARSHALLER_GBA(volume_stat_marshall_gba)
DEFINE_MARSHALLER(volume_stat_marshall)
DEFINE_UNMARSHALLER(volume_stat_unmarshall)

