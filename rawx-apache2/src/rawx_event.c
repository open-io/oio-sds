/*
OpenIO SDS rawx-apache2
Copyright (C) 2016-2019 OpenIO SAS, as part of OpenIO SDS

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
#include <stdlib.h>
#include <assert.h>

#include <glib.h>

#include <events/oio_events_queue.h>
#include <core/internals.h>
#include <metautils/lib/metautils_macros.h>
#include "rawx_event.h"

struct oio_events_queue_s *q_created = NULL;
struct oio_events_queue_s *q_deleted = NULL;

GError *
rawx_event_init (const char *url)
{
#define INIT(Out,Tube) \
if (!err) { \
	err = oio_events_queue_factory__create(url, (Tube), &(Out)); \
	g_assert((err != NULL) ^ ((Out) != NULL)); \
	if (!err) \
		err = oio_events_queue__start((Out)); \
}
	if (!url)
		return NULL;
	GError *err = NULL;
	INIT(q_created, "oio");
	INIT(q_deleted, "oio");
	return err;
}

#define CLEAN(N) if (N) { oio_events_queue__destroy(N); N = NULL; }

void
rawx_event_destroy (void)
{
	CLEAN(q_created);
	CLEAN(q_deleted);
}

GError *
rawx_event_send(
		enum rawx_event_type_e type,
		const char *request_id,
		GString *data_json)
{
	const char *event_type = rawx_event_type_name(type);

	struct oio_events_queue_s *q = NULL;
	switch (type) {
		case OIO_RET_CREATED:
			q = q_created;
			break;
		case OIO_RET_DELETED:
			q = q_deleted;
			break;
		default:
			return NEWERROR(500, "BUG: Unexpected event type");
	}

	if (q != NULL) {
		GString *json = oio_event__create_with_id(
				event_type, NULL, request_id);
		g_string_append_printf(json, ",\"data\":%.*s}",
				(int) data_json->len, data_json->str);
		oio_events_queue__send (q, g_string_free (json, FALSE));
	}

	g_string_free (data_json, TRUE);
	return NULL;
}
