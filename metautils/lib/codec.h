/*
OpenIO SDS metautils
Copyright (C) 2016-2017 OpenIO, as part of OpenIO SDS

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

#endif  /* OIO_SDS_metautils_lib_codec_h */
