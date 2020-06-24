/*
OpenIO SDS metautils
Copyright (C) 2016-2020 OpenIO SAS, as part of OpenIO SDS

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
#ifndef OIO_SDS_metautils_lib_codec_h
#define OIO_SDS_metautils_lib_codec_h

/* size [in bytes] asn1c can require on the stack. Use 0 for as many bytes
 * as necessary (with the risk of stack smashing). */
#define ASN1C_MAX_STACK 0

#include <metautils/asn1c/asn_codecs.h>
#include <metautils/asn1c/asn_SET_OF.h>
#include <metautils/asn1c/asn_SEQUENCE_OF.h>
#include <metautils/asn1c/RowFieldValue.h>
#include <metautils/asn1c/RowField.h>
#include <metautils/asn1c/RowFieldSequence.h>
#include <metautils/asn1c/Row.h>
#include <metautils/asn1c/RowSet.h>
#include <metautils/asn1c/RowName.h>
#include <metautils/asn1c/TableHeader.h>
#include <metautils/asn1c/Table.h>
#include <metautils/asn1c/TableSequence.h>
#include <metautils/asn1c/M2V2Bean.h>
#include <metautils/asn1c/M2V2BeanSequence.h>
#include <metautils/asn1c/M2V2Alias.h>
#include <metautils/asn1c/M2V2ContentHeader.h>
#include <metautils/asn1c/M2V2Property.h>
#include <metautils/asn1c/AddrInfo.h>
#include <metautils/asn1c/Meta0Info.h>
#include <metautils/asn1c/Meta0InfoSequence.h>
#include <metautils/asn1c/NamespaceInfo.h>
#include <metautils/asn1c/Score.h>
#include <metautils/asn1c/ServiceTag.h>
#include <metautils/asn1c/ServiceInfo.h>
#include <metautils/asn1c/ServiceInfoSequence.h>
#include <metautils/asn1c/Parameter.h>
#include <metautils/asn1c/ParameterSequence.h>
#include <metautils/asn1c/Message.h>
#include <metautils/asn1c/der_encoder.h>
#include <metautils/asn1c/ber_decoder.h>

/* Give a pretty prefixed name to the ugly unprefixed macros from asn1c */
#define ASN1C_CALLOC(N,S)  CALLOC(N,S)
#define ASN1C_MALLOC(S)    MALLOC(S)
#define ASN1C_FREE(P)      FREEMEM(P)
#define ASN1C_REALLOC(P,S) REALLOC(P,S)

#include <stdint.h>

int metautils_asn_INTEGER_to_int64(const INTEGER_t *st, int64_t *pv);
int metautils_asn_INTEGER_to_int32(const INTEGER_t *st, int32_t *pv);

int metautils_asn_INTEGER_to_uint16(const INTEGER_t *st, uint16_t *pv);

int metautils_asn_int64_to_INTEGER(INTEGER_t *st, int64_t v);
int metautils_asn_int32_to_INTEGER(INTEGER_t *st, int32_t v);

int metautils_asn_uint32_to_INTEGER(INTEGER_t *st, uint32_t v);
int metautils_asn_uint16_to_INTEGER(INTEGER_t *st, uint16_t v);

#endif  /* OIO_SDS_metautils_lib_codec_h */
