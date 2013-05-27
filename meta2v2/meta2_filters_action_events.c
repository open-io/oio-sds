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

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.meta2.disp"
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <attr/xattr.h>

#include <metatypes.h>
#include <metautils.h>
#include <metacomm.h>
#include <hc_url.h>

#include <glib.h>

#include <transport_gridd.h>

#include "../server/gridd_dispatcher_filters.h"
#include "../cluster/events/gridcluster_events.h"
#include "../cluster/lib/gridcluster.h"

#include "./meta2_macros.h"
#include "./meta2_filter_context.h"
#include "./meta2_filters.h"
#include "./meta2_backend_internals.h"
#include "./meta2_bean.h"
#include "./meta2v2_remote.h"
#include "./generic.h"
#include "./autogen.h"

#define TRACE_FILTER() GRID_TRACE2("%s", __FUNCTION__)


static GError*
_field_add_v1(gridcluster_event_t *event, meta2_raw_content_t *v1)
{
	GByteArray *gba;

	if (!(gba = meta2_maintenance_marshall_content(v1, NULL)))
		return NEWERROR(500, "V1 serialisation error");

	gridcluster_event_add_buffer(event, META2_EVTFIELD_RAWCONTENT,
			gba->data, gba->len);
	g_byte_array_free(gba, TRUE);
	return NULL;
}

static GError*
_field_add_v2(gridcluster_event_t *event, meta2_raw_content_v2_t *v2)
{
	GSList singleton = {.data=NULL,.next=NULL};
	GByteArray *gba = NULL;

	singleton.data = v2;
	if (!(gba = meta2_raw_content_v2_marshall_gba(&singleton, NULL)))
		return NEWERROR(500, "V2 serialisation error");

	gridcluster_event_add_buffer(event, META2_EVTFIELD_RAWCONTENT_V2,
			gba->data, gba->len);
	g_byte_array_free(gba, TRUE);
	return NULL;
}

static gint64
get_id64(struct meta2_backend_s *m2b)
{
	gint64 res;

	g_mutex_lock(m2b->event.lock);
	res = m2b->event.seq ++;
	g_mutex_unlock(m2b->event.lock);

	return res;
}

static gchar *
ueid_generate(struct meta2_backend_s *m2b, gchar *d, gsize dsize)
{
	struct timeval tv;
	gchar hostname[256];

	memset(hostname, 0, sizeof(hostname));
	gethostname(hostname, sizeof(hostname)-1);

	gettimeofday(&tv, NULL);

	g_snprintf(d, dsize, "%.*s_%lu_%lu_%d_%"G_GUINT64_FORMAT,
		(int) sizeof(hostname), hostname,
		tv.tv_sec, tv.tv_usec, getpid(), get_id64(m2b));

	return d;
}

static gridcluster_event_t *
_build_event(struct meta2_backend_s *m2b, const gchar *str_type,
		struct hc_url_s *url)
{
	gchar str_ueid[512];
	gridcluster_event_t *event;

	g_assert(m2b != NULL);
	g_assert(str_type != NULL);
	g_assert(url != NULL);
	g_assert(*str_type != '\0');

	event = gridcluster_create_event();
	if (!event) {
		errno = ENOMEM;
		return NULL;
	}

	gridcluster_event_set_type(event, str_type);

	ueid_generate(m2b, str_ueid, sizeof(str_ueid));
	gridcluster_event_add_string(event, "UEID", str_ueid);

	/* mandatory fields */
	gridcluster_event_add_string(event, META2_EVTFIELD_CID,
			hc_url_get(url, HCURL_HEXID));
	gridcluster_event_add_string(event, META2_EVTFIELD_CPATH,
			hc_url_get(url, HCURL_PATH));

	/* optional fields */
	if (hc_url_has(url, HCURL_REFERENCE)) {
		gridcluster_event_add_string(event, META2_EVTFIELD_CNAME,
				hc_url_get(url, HCURL_REFERENCE));
	}
	if (hc_url_has(url, HCURL_NS)) {
		gridcluster_event_add_string(event, META2_EVTFIELD_NAMESPACE,
				hc_url_get(url, HCURL_NS));
	}
	if (m2b->event.agregate) {
		gchar *aggrname = g_strconcat(hc_url_get(url, HCURL_HEXID),
				",", hc_url_get(url, HCURL_PATH), ",CHANGE", NULL);
		gridcluster_event_add_string(event, "AGGRNAME", aggrname);
		g_free(aggrname);
	}

	/* additional fields */
	gridcluster_event_add_string(event, META2_EVTFIELD_URL,
			hc_url_get(url, HCURL_WHOLE));

	return event;
}

static void
purify_basename(gchar *s)
{
	gchar c;

	if (!s)
		return;
	for (; (c = *s) ; s++) {
		if (!g_ascii_isprint(c) || g_ascii_isspace(c) || c==G_DIR_SEPARATOR || c=='.')
			*s = '_';
	}
}

static gchar*
event_get_string_field(gridcluster_event_t *event, const gchar *name)
{
	GByteArray *gba;

	if (!(gba = g_hash_table_lookup(event, name)))
		return NULL;
	return g_strndup((gchar*)gba->data, gba->len);
}


static GError*
event_write(struct meta2_backend_s *m2b, gridcluster_event_t *evt)
{
	gchar tmppath[1024], dirname[1024], abspath[1024];
	GError *err = NULL;
	time_t now = time(0);
	int fd;

	gchar *str_ueid = event_get_string_field(evt, "UEID");
	gchar *str_aggrname = event_get_string_field(evt, "AGGRNAME");
	gchar *str_cid  = event_get_string_field(evt, "CID");
	purify_basename(str_aggrname);

	/* Compute the hashed directory path */
	g_snprintf(dirname, sizeof(dirname), "%s%c%lu%c%lu",
			m2b->event.dir,
			G_DIR_SEPARATOR, (now / 86400) * 86400,
			G_DIR_SEPARATOR, (now / 300)   * 300);

	g_snprintf(abspath, sizeof(abspath), "%s%c%s", dirname, G_DIR_SEPARATOR,
			(str_aggrname ? str_aggrname : str_ueid));

retry:
	g_snprintf(tmppath, sizeof(tmppath), "%s%cevent-XXXXXX",
			dirname, G_DIR_SEPARATOR);

	//GRID_WARN("dirname=%s abspath=%s tmppath=%s", dirname, abspath, tmppath);
	if (0 > (fd = g_mkstemp(tmppath))) {
		if (errno == ENOENT) {
			while (!err && 0 != g_mkdir_with_parents(dirname, 0755)) {
				if (errno != EEXIST)
					err = NEWERROR(500, "Event error (mkdir) : errno=%d (%s)",
							errno, strerror(errno));
				/* g_mkdir_with_parents() poorly manages concurency, so we try
				 * as long as we got race conditions clues. */
			}
			goto retry;
		}
		err = NEWERROR(500, "Event write error (mkstemp) : errno=%d (%s)",
				errno, strerror(errno));
	}
	else {

		/* change file attribute */
		if (0 != fchmod(fd, 0644))
			err = NEWERROR(500, "Event error (chmod) : errno=%d (%s)",
					errno, strerror(errno));

		/* Set the file content */
		if (!err) {
			GByteArray *gba;

			if (!(gba = gridcluster_encode_event(evt, NULL)))
				err = NEWERROR(500, "Event error (encoding)");
			else {
				write(fd, gba->data, gba->len);
				g_byte_array_free(gba, TRUE);
			}
		}

		/* set extended attributes (XATTR) */
		if (!err) {
			gchar str_now[64], str_seq[64];
			bzero(str_now, sizeof(str_now));
			bzero(str_seq, sizeof(str_seq));
			g_snprintf(str_now, sizeof(str_now), "%ld", now);
			g_snprintf(str_seq, sizeof(str_seq), "%"G_GINT64_FORMAT, get_id64(m2b));
			if ((-1 == fsetxattr(fd, "user.grid.agent.incoming-time", str_now, strlen(str_now), 0))
					|| (-1 == fsetxattr(fd, "user.grid.agent.incoming-sequence", str_seq, strlen(str_seq), 0))
					|| (-1 == fsetxattr(fd, "user.grid.agent.incoming-container", str_cid, strlen(str_cid), 0)))
			{
				err = NEWERROR(500, "Event error (setxattr) : errno=%d (%s)",
						errno, strerror(errno));
			}
		}

		/* rename the file */
		if (!err) {
			if (0 != rename(tmppath, abspath)) {
				err = NEWERROR(500, "Event error (rename) : errno=%d (%s)",
						errno, strerror(errno));
				(void) unlink(tmppath);
			}
		}

		close(fd);
		fd = -1;
	}

	if (str_aggrname)
		g_free(str_aggrname);
	if (str_ueid)
		g_free(str_ueid);
	if (str_cid)
		g_free(str_cid);
	return err;
}

static GError*
touch_v2_content(struct meta2_backend_s *m2b, struct hc_url_s *url,
		struct meta2_raw_content_v2_s *v2)
{
	GError *err = NULL;
	gridcluster_event_t *event = NULL;

	event = _build_event(m2b, "meta2.CONTENT.put", url);

	if (v2) {
		meta2_raw_content_t *v1;

		if (NULL != (err = _field_add_v2(event, v2)))
			goto error;

		if (!(v1 = meta2_raw_content_v2_get_v1(v2, NULL)))
			WARN("V2 to V1 mapping error");
		else {
			err = _field_add_v1(event, v1);
			meta2_maintenance_destroy_content(v1);
			if (err)
				goto error;
		}
	}

	if (m2b->event.dir)
		err = event_write(m2b, event);

error:
	g_hash_table_destroy(event);
	return err;
}

static GError *
touch_ALIAS_beans(struct meta2_backend_s *m2b, struct hc_url_s *url,
		GSList *beans)
{
	GError *err = NULL;
	struct meta2_raw_content_v2_s *v2;

	v2 = raw_content_v2_from_m2v2_beans(hc_url_get_id(url), beans);
	if (!v2)
		err = NEWERROR(500, "Conversion error");
	else {
		err = touch_v2_content(m2b, url, v2);
		meta2_raw_content_v2_clean(v2);
	}

	return err;
}

static GError *
touch_ALIAS(struct meta2_backend_s *m2b, struct hc_url_s *url,
		struct bean_ALIASES_s *alias)
{
	GError *err = NULL;

	hc_url_set(url, HCURL_PATH, ALIASES_get_alias(alias)->str);
	GPtrArray *tmp = g_ptr_array_new();
	if (tmp->len > 0) {
		g_ptr_array_add(tmp, NULL);
		GSList *bl = metautils_array_to_list(tmp->pdata);
		if (bl) {
			err = touch_ALIAS_beans(m2b, url, bl);
			g_slist_free(bl);
		}
	}
	_bean_cleanv2(tmp);
	return err;
}

int
meta2_filter_action_touch_content_v1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *err = NULL;
	struct meta2_backend_s *m2b;
	struct hc_url_s *url;

	TRACE_FILTER();
	(void) reply;
	m2b = meta2_filter_ctx_get_backend(ctx);
	url = meta2_filter_ctx_get_url(ctx);

	GSList *beans = NULL;
	do {
		GPtrArray *tmp = g_ptr_array_new();
		err = meta2_backend_get_alias(m2b, url, 0, _bean_buffer_cb, tmp);
		beans = metautils_gpa_to_list(tmp);
		g_ptr_array_free(tmp, TRUE);
	} while (0);

	if (err) {
		_bean_cleanl2(beans);
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	err = touch_ALIAS_beans(m2b, url, beans);
	_bean_cleanl2(beans);

	if (!err) {
		reply->send_reply(200, "OK");
		return FILTER_OK;
	}
	else {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}
}

int
meta2_filter_action_touch_container_v1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *err = NULL;
	struct meta2_backend_s *m2b;
	struct hc_url_s *url;

	TRACE_FILTER();
	(void) reply;
	m2b = meta2_filter_ctx_get_backend(ctx);
	url = meta2_filter_ctx_get_url(ctx);

	GPtrArray *aliases = g_ptr_array_new();
	err = meta2_backend_list_aliases(m2b, url, 0, _bean_buffer_cb, aliases);
	if (err != NULL) {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	guint u;
	for (u=0; !err && u < aliases->len ;u++) {
		struct bean_ALIASES_s *alias = aliases->pdata[u];
		err = touch_ALIAS(m2b, url, alias);
	}

	_bean_cleanv2(aliases);

	if (!err) {
		reply->send_reply(200, "0K");
		return FILTER_OK;
	}

	meta2_filter_ctx_set_error(ctx, err);
	return FILTER_KO;
}

