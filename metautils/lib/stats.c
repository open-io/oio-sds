/*
OpenIO SDS metautils
Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS

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

#include <metautils/lib/metautils.h>
#include <metautils/lib/common_variables.h>

static GArray *stats = NULL;  /* <struct server_stat_s> */
static GMutex lock_stats = {};

void __attribute__ ((constructor)) _stats_init(void);
void __attribute__ ((destructor)) _stats_fini (void);

#define ARRAY() \
	g_array_sized_new(FALSE, FALSE, sizeof(struct stat_record_s), 128)

void
_stats_init(void)
{
	stats = ARRAY();
	g_assert(stats != NULL);
	g_mutex_init(&lock_stats);
}

void
_stats_fini(void)
{
	g_mutex_clear(&lock_stats);
	if (stats)
		g_array_free (stats, TRUE);
}

static void
_stretch(const GQuark k)
{
	while (stats->len <= k) {  /* lazy stretch */
		struct stat_record_s st = {.value=0, .which=0};
		g_array_append_vals(stats, &st, 1);
	}
}

static void
_on_stat(gboolean increment, const GQuark k, const gint64 v)
{
	if (k <= 0)
		return;
	_stretch(k);
	struct stat_record_s *ss = &g_array_index(stats, struct stat_record_s, k);
	ss->which = k;
	ss->value = (increment ? ss->value : 0) + v;
}

void
oio_stats_set(
		GQuark k1, guint64 v1, GQuark k2, guint64 v2,
		GQuark k3, guint64 v3, GQuark k4, guint64 v4)
{
	g_mutex_lock (&lock_stats);
	_on_stat(FALSE, k1, v1);
	_on_stat(FALSE, k2, v2);
	_on_stat(FALSE, k3, v3);
	_on_stat(FALSE, k4, v4);
	g_mutex_unlock (&lock_stats);
}

void
oio_stats_add(
		GQuark k1, guint64 v1, GQuark k2, guint64 v2,
		GQuark k3, guint64 v3, GQuark k4, guint64 v4)
{
	g_mutex_lock (&lock_stats);
	_on_stat(TRUE, k1, v1);
	_on_stat(TRUE, k2, v2);
	_on_stat(TRUE, k3, v3);
	_on_stat(TRUE, k4, v4);
	g_mutex_unlock (&lock_stats);
}

GArray*
network_server_stat_getall (void)
{
	GArray *out = ARRAY();
	g_mutex_lock (&lock_stats);
	for (guint i=0; i<stats->len ;++i) {
		struct stat_record_s *ss = &g_array_index(stats, struct stat_record_s, i);
		if (ss->which != 0)
			g_array_append_vals (out, ss, 1);
	}
	g_mutex_unlock (&lock_stats);
	return out;
}
