/*
OpenIO SDS metautils
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "metacomm.parameter"
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

