/*
OpenIO SDS sqliterepo
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

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

#include <fnmatch.h>

#include <metautils/lib/metautils.h>

#include "sqliterepo.h"
#include "sqlite_utils.h"
#include "internals.h"
#include "upgrade.h"

struct sqlx_upgrade_step_s
{
	gchar *pre;
	gchar *post;
	sqlx_upgrade_cb *cb;
	gpointer cb_data;
};

struct sqlx_upgrader_s
{
	GArray *steps;
};

struct sqlx_upgrader_s*
sqlx_upgrader_create(void)
{
	struct sqlx_upgrader_s *su = g_malloc0(sizeof(*su));
	su->steps = g_array_new(0, TRUE, sizeof(struct sqlx_upgrade_step_s));
	return su;
}

void
sqlx_upgrader_destroy(struct sqlx_upgrader_s *su)
{
	if (!su)
		return;
	if (su->steps) {
		while (su->steps->len) {
			struct sqlx_upgrade_step_s *step = &g_array_index(su->steps,
					struct sqlx_upgrade_step_s, 0);
			if (step->pre)
				g_free(step->pre);
			if (step->post)
				g_free(step->post);
			g_array_remove_index_fast(su->steps, 0);
		}
		g_array_free(su->steps, TRUE);
	}
	g_free(su);
}

void
sqlx_upgrader_register(struct sqlx_upgrader_s *su,
		const gchar *p0, const gchar *p1,
		sqlx_upgrade_cb cb, gpointer cb_data)
{
	struct sqlx_upgrade_step_s step = {0};

	EXTRA_ASSERT(su != NULL);
	EXTRA_ASSERT(su->steps != NULL);
	EXTRA_ASSERT(p1 != NULL);
	EXTRA_ASSERT(cb != NULL);

	step.pre = p0 ? g_strdup(p0) : NULL;
	step.post = g_strdup(p1);
	step.cb = cb;
	step.cb_data = cb_data;

	g_array_append_vals(su->steps, &step, 1);
}

GError*
sqlx_upgrade_do(struct sqlx_upgrader_s *su, struct sqlx_sqlite3_s *sq3)
{
	GRID_TRACE2("%s", __FUNCTION__);
	EXTRA_ASSERT(su != NULL);
	EXTRA_ASSERT(su->steps != NULL);
	EXTRA_ASSERT(sq3 != NULL);
	EXTRA_ASSERT(sq3->db != NULL);

	guint i, max;
	gchar *version = sqlx_admin_get_str(sq3, "schema_version");

	for (i=0,max=su->steps->len; i<max ;i++) {
		struct sqlx_upgrade_step_s *step = &g_array_index(su->steps,
				struct sqlx_upgrade_step_s, i);
		GRID_DEBUG("version = %s, step->pre? %s", version, step->pre);
		if ((!version && step->pre) || (version && step->pre &&
				!fnmatch(step->pre, version, 0)))
		{
			GRID_TRACE("Runnig upgrade step");
			GError *err = step->cb(sq3, step->cb_data);
			if (!err) {
				oio_str_replace(&version, step->post);
				sqlx_admin_set_str(sq3, "schema_version", version);
			}
			else {
				g_prefix_error(&err, "Conversion error from [%s] to [%s]", version, step->post);
				oio_str_clean(&version);
				return err;
			}
		}
	}

	oio_str_clean(&version);
	return NULL;
}

