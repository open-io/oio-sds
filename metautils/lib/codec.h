/*
OpenIO SDS metautils
Copyright (C) 2016 OpenIO, original work as part of OpenIO Software Defined Storage

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

#include <metautils/lib/asn_codecs.h>
#include <metautils/lib/asn_SET_OF.h>
#include <metautils/lib/asn_SEQUENCE_OF.h>

#include <metautils/lib/RowFieldValue.h>
#include <metautils/lib/RowField.h>
#include <metautils/lib/RowFieldSequence.h>
#include <metautils/lib/Row.h>
#include <metautils/lib/RowSet.h>
#include <metautils/lib/RowName.h>
#include <metautils/lib/TableHeader.h>
#include <metautils/lib/Table.h>
#include <metautils/lib/TableSequence.h>

#include <metautils/lib/M2V2Bean.h>
#include <metautils/lib/M2V2BeanSequence.h>
#include <metautils/lib/M2V2Alias.h>
#include <metautils/lib/M2V2ContentHeader.h>
#include <metautils/lib/M2V2Property.h>

#include <metautils/lib/AddrInfo.h>
#include <metautils/lib/Meta0Info.h>
#include <metautils/lib/Meta0InfoSequence.h>
#include <metautils/lib/NamespaceInfo.h>
#include <metautils/lib/Score.h>
#include <metautils/lib/ServiceTag.h>
#include <metautils/lib/ServiceInfo.h>
#include <metautils/lib/ServiceInfoSequence.h>

#include <metautils/lib/Parameter.h>
#include <metautils/lib/ParameterSequence.h>
#include <metautils/lib/Message.h>

#include <metautils/lib/der_encoder.h>
#include <metautils/lib/ber_decoder.h>

#endif  /* OIO_SDS_metautils_lib_codec_h */
