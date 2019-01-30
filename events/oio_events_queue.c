/*
OpenIO SDS event queue
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

#include <string.h>

#include <glib.h>

#include <core/oio_core.h>
#include <core/url_ext.h>
#include <metautils/lib/metautils_resolv.h>

#include "oio_events_queue.h"
#include "oio_events_queue_internals.h"
#include "oio_events_queue_fanout.h"
#include "oio_events_queue_beanstalkd.h"

#define EVTQ_CALL(self,F) VTABLE_CALL(self,struct oio_events_queue_abstract_s*,F)

void
oio_events_queue__destroy (struct oio_events_queue_s *self)
{
	if (!self) return;
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

gint64
oio_events_queue__get_health(struct oio_events_queue_s *self)
{
	if (VTABLE_HAS(self,struct oio_events_queue_abstract_s*,get_health)) {
		EVTQ_CALL(self,get_health)(self);
	}
	return 100;
}

void
oio_events_queue__set_buffering (struct oio_events_queue_s *self,
		gint64 delay)
{
	EVTQ_CALL(self,set_buffering)(self,delay);
}

GError *
oio_events_queue__start (struct oio_events_queue_s *self)
{
	EVTQ_CALL(self,start)(self);
}

static const char *
_has_prefix (const char *cfg, const char *prefix)
{
	if (g_str_has_prefix (cfg, prefix))
		return cfg + strlen(prefix);
	return NULL;
}

static GError *
_parse_and_create_multi(const char *cfg, const char *tube,
		struct oio_events_queue_s **out)
{
	gchar **tokens = g_strsplit(cfg, OIO_CSV_SEP2, -1);
	if (!tokens)
		return SYSERR("internal error");

	GError *err = NULL;
	GPtrArray *sub_queuev = g_ptr_array_new();

	for (gchar **token = tokens; *token && !err ;++token) {
		struct oio_events_queue_s *sub = NULL;
		if (!(err = oio_events_queue_factory__create(*token, tube, &sub)))
			g_ptr_array_add(sub_queuev, sub);
	}

	if (!err) {
		if (sub_queuev->len <= 0) {
			err = BADREQ("empty connection string");
		} else {
			err = oio_events_queue_factory__create_fanout(
					(struct oio_events_queue_s **)sub_queuev->pdata,
					sub_queuev->len, out);
		}
	}

	if (err) {
		g_ptr_array_set_free_func(sub_queuev,
				(GDestroyNotify)oio_events_queue__destroy);
		g_ptr_array_free(sub_queuev, TRUE);
	} else {
		g_ptr_array_free(sub_queuev, FALSE);
	}

	g_strfreev(tokens);
	return err;
}

GError *
oio_events_queue_factory__create (const char *cfg, const char *tube,
		struct oio_events_queue_s **out)
{
	EXTRA_ASSERT (cfg != NULL);
	EXTRA_ASSERT (tube != NULL);
	EXTRA_ASSERT (out != NULL);
	*out = NULL;

	if (NULL != strchr(cfg, OIO_CSV_SEP2_C)) {
		// Sharding over several endpoints
		return _parse_and_create_multi(cfg, tube, out);
	} else {
		const char *tmp;

		if (NULL != (tmp = _has_prefix (cfg, "beanstalk://")))
			return oio_events_queue_factory__create_beanstalkd(tmp, tube, out);

		return BADREQ("implementation not recognized");
	}
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
oio_event__create(const char *type, struct oio_url_s *url)
{
	return oio_event__create_with_id(type, url, NULL);
}

GString*
oio_event__create_with_id(const char *type, struct oio_url_s *url,
		const char *request_id)
{
	GString *gs = g_string_sized_new(512);
	g_string_append_c (gs, '{');
	oio_event__init (gs, type, url);
	if (request_id && *request_id) {
		g_string_append_c(gs, ',');
		oio_str_gstring_append_json_pair(gs, EVENT_FIELD_REQUEST_ID, request_id);
	}
	const gchar *user_agent = oio_ext_get_user_agent();
	if (user_agent != NULL) {
		g_string_append_c(gs, ',');
		oio_str_gstring_append_json_pair(gs, EVENT_FIELD_ORIGIN, user_agent);
	}
	return gs;
}
