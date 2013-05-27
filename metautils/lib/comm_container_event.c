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
# define LOG_DOMAIN "metacomm.container_event"
#endif

#include "./metautils_internals.h"
#include "./ContainerEvent.h"
#include "./ContainerEventSequence.h"
#include "./asn_ContainerEvent.h"

static struct abstract_sequence_handler_s seq_descriptor = {
	sizeof(ContainerEvent_t),
	sizeof(container_event_t),
	&asn_DEF_ContainerEventSequence,
	(abstract_converter_f) container_event_ASN2API,
	(abstract_converter_f) container_event_API2ASN,
	(abstract_asn_cleaner_f) container_event_cleanASN,
	(abstract_api_cleaner_f) container_event_clean,
	"container_event"
};

DEFINE_MARSHALLER_GBA(container_event_marshall_gba);
DEFINE_MARSHALLER(container_event_marshall);
DEFINE_UNMARSHALLER(container_event_unmarshall);
DEFINE_BODY_MANAGER(container_event_concat, container_event_unmarshall);

