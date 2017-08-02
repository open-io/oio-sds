/*
OpenIO SDS event queue
Copyright (C) 2016-2017 OpenIO SAS, as part of OpenIO SDS

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

#include <string.h>

#include <glib.h>

#include <core/oio_core.h>
#include <core/url_ext.h>
#include <metautils/lib/metautils_resolv.h>

#include "oio_events_queue.h"
#include "oio_events_queue_internals.h"
#include "oio_events_queue_zmq.h"
#include "oio_events_queue_beanstalkd.h"

#define EVTQ_CALL(self,F) VTABLE_CALL(self,struct oio_events_queue_abstract_s*,F)

void
oio_events_queue__destroy (struct oio_events_queue_s *self)
{
	EVTQ_CALL(self,destroy)(self);
}

void
oio_events_queue__send (struct oio_events_queue_s *self, gchar *msg)
{
	EXTRA_ASSERT (msg != NULL);
	EVTQ_CALL(self,send)(self,msg);
}

void
oio_events_queue__send_overwritable(struct oio_events_queue_s *self,
		gchar *key, gchar *msg)
{
	EXTRA_ASSERT (msg != NULL);
	if (VTABLE_HAS(self,struct oio_events_queue_abstract_s*,send_overwritable)
			&& key && *key) {
		EVTQ_CALL(self,send_overwritable)(self,key,msg);
	} else {
		EVTQ_CALL(self,send)(self,msg);
		g_free(key);  // safe if key is NULL
	}
}

gboolean
oio_events_queue__is_stalled (struct oio_events_queue_s *self)
{
	EVTQ_CALL(self,is_stalled)(self);
}

GError *
oio_events_queue__run (struct oio_events_queue_s *self,
		gboolean (*running) (gboolean pending))
{
	EVTQ_CALL(self,run)(self,running);
}

static const char *
_has_prefix (const char *cfg, const char *prefix)
{
	if (g_str_has_prefix (cfg, prefix))
		return cfg + strlen(prefix);
	return NULL;
}

GError *
oio_events_queue_factory__create (const char *cfg, struct oio_events_queue_s **out)
{
	EXTRA_ASSERT (cfg != NULL);
	EXTRA_ASSERT (out != NULL);
	*out = NULL;

	const char *tmp;

	if (NULL != (tmp = _has_prefix (cfg, "beanstalk://")))
		return oio_events_queue_factory__create_beanstalkd (tmp, out);

	if (NULL != (tmp = _has_prefix (cfg, "ipc://"))
			|| NULL != (tmp = _has_prefix (cfg, "tcp://"))
			|| NULL != (tmp = _has_prefix (cfg, "inproc://")))
		return oio_events_queue_factory__create_zmq (cfg, out);

	return BADREQ("implementation not recognized");
}

GError *
oio_events_queue_factory__check_config (const char *cfg)
{
	const char *tmp;
	if (!cfg)
		return BADREQ("NULL configuration");
	if (!*cfg)
		return BADREQ("Empty configuration");

	if (NULL != (tmp = _has_prefix (cfg, "beanstalk://"))) {
		if (!metautils_url_valid_for_connect (tmp))
			return BADREQ("Invalid beanstalkd URL");
		return NULL;
	}

	if (NULL != (tmp = _has_prefix (cfg, "inproc://")))
		return NULL;
	if (NULL != (tmp = _has_prefix (cfg, "ipc://")))
		return NULL;

	if (NULL != (tmp = _has_prefix (cfg, "tcp://"))) {
		if (!metautils_url_valid_for_connect (tmp))
			return BADREQ("Invalid zmq/tcp URL");
		return NULL;
	}

	return BADREQ("implementation not recognized");
}

void
oio_event__init (GString *gs, const char *type, struct oio_url_s *url)
{
	oio_str_gstring_append_json_pair (gs, "event", type);
	g_string_append_printf (gs, ",\"when\":%"G_GINT64_FORMAT, oio_ext_real_time());
	if (!url)
		g_string_append_static (gs, ",\"url\":null");
	else {
		g_string_append_static (gs, ",\"url\":{");
		oio_url_to_json (gs, url);
		g_string_append_c (gs, '}');
	}
}

GString*
oio_event__create (const char *type, struct oio_url_s *url)
{
	GString *gs = g_string_sized_new(512);
	g_string_append_c (gs, '{');
	oio_event__init (gs, type, url);
	return gs;
}
