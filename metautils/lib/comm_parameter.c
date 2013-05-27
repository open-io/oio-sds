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
#define LOG_DOMAIN "metacomm.parameter"
#endif

#include "./metautils_internals.h"
#include "./Parameter.h"
#include "./ParameterSequence.h"
#include "./asn_Parameter.h"

static struct abstract_sequence_handler_s seq_descriptor = {
	sizeof(Parameter_t),
	sizeof(key_value_pair_t),
	&asn_DEF_ParameterSequence,
	(abstract_converter_f) key_value_pair_ASN2API,
	(abstract_converter_f) key_value_pair_API2ASN,
	(abstract_asn_cleaner_f) key_value_pair_cleanASN,
	(abstract_api_cleaner_f) key_value_pair_clean,
	"key_value_pair"
};

DEFINE_MARSHALLER_GBA(key_value_pairs_marshall_gba);
DEFINE_MARSHALLER(key_value_pairs_marshall);
DEFINE_UNMARSHALLER(key_value_pairs_unmarshall);
DEFINE_BODY_MANAGER(key_value_pairs_concat, key_value_pairs_unmarshall);

