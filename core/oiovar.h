/*
OpenIO SDS core library
Copyright (C) 2015-2017 OpenIO, original work as part of OpenIO SDS

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

#ifndef OIO_SDS__core__var_h
# define OIO_SDS__core__var_h 1
#include <glib.h>

struct oio_cfg_handle_s;

void oio_var_register_gboolean(gboolean *p, gboolean def,
		const char *n, const char *descr);

void oio_var_register_guint(guint *p, guint def,
		const char *n, const char *descr,
		guint min, guint max);

void oio_var_register_guint32(guint32 *p, guint32 def,
		const char *n, const char *descr,
		guint32 min, guint32 max);

void oio_var_register_guint64(guint64 *p, guint64 def,
		const char *n, const char *descr,
		guint64 min, guint64 max);

void oio_var_register_gint(gint *p, gint def,
		const char *n, const char *descr,
		gint min, gint max);

void oio_var_register_gint32(gint32 *p, gint32 def,
		const char *n, const char *descr,
		gint32 min, gint32 max);

void oio_var_register_gint64(gint64 *p, gint64 def,
		const char *n, const char *descr,
		gint64 min, gint64 max);

void oio_var_register_gdouble(gdouble *p, gdouble def,
		const char *n, const char *descr,
		gdouble min, gdouble max);

void oio_var_register_time_t(time_t *p, time_t def,
		const char *n, const char *descr,
		time_t min, time_t max);

/**
 * Try to feed all the registered configuration variables with the content
 * of the given configuration, for the given namespace.
 */
void oio_var_value_all_with_config(struct oio_cfg_handle_s *cfg, const char *ns);

/**
 * Feed a named value and return if it matches a variable already declared.
 */
gboolean oio_var_value_one_with_option(const char *name, const char *value);

/**
 *
 */
void oio_var_list_all(void (*hook) (const char *k, const char *v));


#define OIO_VAR_DEFINE_BOOL(Name,Default,Config,Description) \
	gboolean Name __attribute__ ((visibility ("protected"))) = Default; \
	static void __attribute__ ((constructor)) __declare_gboolean_##Name (void) { \
		oio_var_register_gboolean(&Name, Default, Config, Description); \
	}

#define OIO_VAR_DEFINE_CONFIG(Type,Name,Default,Config,Description,Min,Max) \
	Type Name __attribute__ ((visibility ("protected"))) = Default; \
	static void __attribute__ ((constructor)) __declare_##Type##_##Name (void) { \
		oio_var_register_##Type(&Name, Default, Config, Description, Min, Max); \
	}

#define OIO_VAR_DEFINE_EPOCH(Name,Default,Config,Description,Min,Max) \
	OIO_VAR_DEFINE_CONFIG(time_t,Name,Default,Config,Description,0,-1)

#define OIO_VAR_DEFINE_MONOTONIC_TIME(Name,Default,Config,Description,Min,Max) \
	OIO_VAR_DEFINE_CONFIG(gint64,Name,Default,Config,Description,0,G_TIME_SPAN_DAY)

#endif /* OIO_SDS__core__var_h */
