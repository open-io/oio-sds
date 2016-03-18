/*
OpenIO SDS cluster
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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
#include <string.h>
#include <strings.h>
#include <math.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include "./conscience.h"
#include "./conscience_srv.h"
#include "./conscience_srvtype.h"

struct service_tag_s *
conscience_srv_get_tag(struct conscience_srv_s *service,
    const gchar * name)
{
	return service ? service_info_get_tag(service->tags,name) : NULL;
}

struct service_tag_s *
conscience_srv_ensure_tag(struct conscience_srv_s *service,
    const gchar * name)
{
	return service && name ? service_info_ensure_tag(service->tags,name) : NULL;
}

void
conscience_srv_remove_tag(struct conscience_srv_s *service,
    const char *name)
{
	if (service && name)
		service_info_remove_tag(service->tags,name);
}

/* ------------------------------------------------------------------------- */

void
conscience_srv_destroy(struct conscience_srv_s *service)
{
	if (!service)
		return;

	/*free the tags */
	if (service->tags) {
		while (service->tags->len > 0) {
			struct service_tag_s *tag = g_ptr_array_index(service->tags,0);
			service_tag_destroy(tag);
			g_ptr_array_remove_index_fast(service->tags, 0);
		}
		g_ptr_array_free(service->tags, TRUE);
	}

	if (service->app_data_type==SAD_PTR) {
		if (service->app_data.pointer.value && service->app_data.pointer.cleaner)
			service->app_data.pointer.cleaner(service->app_data.pointer.value);
	}

	/*remove from the ring */
	service_ring_remove(service);

	/*cleans the structure */
	memset(service, 0x00, sizeof(struct conscience_srv_s));
	g_free(service);
}

score_t*
conscience_srv_compute_score(struct conscience_srv_s
    *service, GError ** err)
{
	gint32 current;
	struct conscience_s *conscience;
	struct conscience_srvtype_s *srvtype;
	gdouble d;

	char *getField(char *b, char *f) {
		char str_name[128];
		struct service_tag_s *pTag;

		if (!f) {
			DEBUG("[%s/%s/] NULL tag wanted", conscience->ns_info.name, srvtype->type_name);
			return NULL;
		}
		g_snprintf(str_name,sizeof(str_name),"%s.%s", b, f);
		pTag = conscience_srv_get_tag(service, str_name);
		if (!pTag) {
			DEBUG("[%s/%s/] Undefined tag wanted : %s", conscience->ns_info.name, srvtype->type_name, f);
			return NULL;
		}
		switch (pTag->type) {
		case STVT_I64:
			return g_strdup_printf("%"G_GINT64_FORMAT, pTag->value.i);
		case STVT_REAL:
			return g_strdup_printf("%f", pTag->value.r);
		case STVT_BOOL:
			return g_strdup_printf("%d", pTag->value.b ? 1 : 0);
		case STVT_STR:
			return g_strdup(pTag->value.s);
		case STVT_BUF:
			return g_strdup(pTag->value.buf);
		}
		DEBUG("[%s/%s/] invalid tag value! : %s", conscience->ns_info.name, srvtype->type_name, f);
		return NULL;
	}
	char *getStat(char *f) {
		return getField("stat", f);
	}
	char *getTag(char *f) {
		return getField("tag", f);
	}
	accessor_f *getAcc(char *b)
	{
		if (!b)
			return NULL;
		if (!g_ascii_strcasecmp(b, "stat"))
			return getStat;
		if (!g_ascii_strcasecmp(b, "tag"))
			return getTag;
		DEBUG("[%s/%s/] invalid tag domain : [%s]", conscience->ns_info.name, srvtype->type_name, b);
		return NULL;
	}

	/*some sanity checks */
	if (!service) {
		GSETCODE(err, CODE_INTERNAL_ERROR, "Invalid parameter (no service)");
		return NULL;
	}

	if (service->locked)
		return &(service->score);

	srvtype = service->srvtype;
	if (!srvtype || !srvtype->score_expr) {
		GSETCODE(err, CODE_INTERNAL_ERROR, "Invalid parameter (service type misconfigured)");
		return NULL;
	}

	/*compute the score ... now! */
	conscience = srvtype->conscience;
	d = 0.0;
	if (expr_evaluate(&d, srvtype->score_expr, getAcc)) {
		GSETERROR(err, "Failed to evaluate the expression");
		return NULL;
	}

	/*some sanity checks */
	d = floor(d);
	if (isnan(d))
		d = 0.0;
	current = floor(d);

	if (service->score.value>=0) {
		if (srvtype->score_variation_bound>0) {
			gint32 max = service->score.value + srvtype->score_variation_bound;
			current = MIN(current,max);
		}
	}

	service->score.value = CLAMP(current,0,100);
	return &(service->score);
}

void
conscience_srv_lock_score( struct conscience_srv_s *srv, gint s )
{
	if (!srv)
		return;
	srv->score.value = s;
	srv->score.timestamp = oio_ext_monotonic_seconds ();
	srv->locked = TRUE;
}

void
conscience_srv_fill_srvinfo(struct service_info_s *dst,
    struct conscience_srv_s *src)
{
	if (!dst || !src)
		return;

	conscience_srv_fill_srvinfo_header(dst, src);
	dst->tags = service_info_copy_tags(src->tags);
}

void
conscience_srv_fill_srvinfo_header(struct service_info_s *dst,
		struct conscience_srv_s *src)
{
	const gchar *ns_name;

	if (!dst || !src)
		return;

	EXTRA_ASSERT(src->srvtype != NULL);
	EXTRA_ASSERT(sizeof(dst->type) == sizeof(src->srvtype->type_name));

	memset(dst->type, 0x00, sizeof(dst->type));
	memset(dst->ns_name, 0x00, sizeof(dst->ns_name));

	memcpy(&(dst->addr), &(src->id.addr), sizeof(addr_info_t));
	memcpy(&(dst->score), &(src->score), sizeof(score_t));
	memcpy(dst->type, src->srvtype->type_name, sizeof(dst->type));
	ns_name = conscience_get_nsname(src->srvtype->conscience);
	if (ns_name)
		g_strlcpy(dst->ns_name, ns_name, sizeof(dst->ns_name)-1);
}

