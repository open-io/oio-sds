/*
OpenIO SDS core library
Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS

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
#define OIO_SDS__core__var_h 1
#include <glib.h>
#include <core/oiocfg.h>

enum oio_var_kind_e {
	OIO_VARKIND_time = 0,
	OIO_VARKIND_size = 1,
	OIO_VARKIND_epoch = 2,
};

/**
 * Notify the "manager of the variables" that a deprecated name exists for
 * the given variable. A variables named `name`must exist, and no alias
 * named `alias`must exist.
 *
 * @param name a non-NULL pointer to a valid string
 * @param alias a non-NULL pointer ot a valid string
 */
void oio_var_register_alias(const char *name, const char *alias);

void oio_var_register_string(gchar *p,
		const char *n, const char *descr,
		const gchar *def, gsize limit);

void oio_var_register_gboolean(gboolean *p,
		const char *n, const char *descr,
		gboolean def);

void oio_var_register_guint(guint *p,
		enum oio_var_kind_e kind, const char *n, const char *descr,
		guint def, guint min, guint max);

void oio_var_register_guint32(guint32 *p,
		enum oio_var_kind_e kind, const char *n, const char *descr,
		guint32 def, guint32 min, guint32 max);

void oio_var_register_guint64(guint64 *p,
		enum oio_var_kind_e kind, const char *n, const char *descr,
		guint64 def, guint64 min, guint64 max);

void oio_var_register_gint(gint *p,
		enum oio_var_kind_e kind, const char *n, const char *descr,
		gint def, gint min, gint max);

void oio_var_register_gint32(gint32 *p,
		enum oio_var_kind_e kind, const char *n, const char *descr,
		gint32 def, gint32 min, gint32 max);

void oio_var_register_gint64(gint64 *p,
		enum oio_var_kind_e kind, const char *n, const char *descr,
		gint64 def, gint64 min, gint64 max);

void oio_var_register_gdouble(gdouble *p,
		enum oio_var_kind_e kind, const char *n, const char *descr,
		gdouble def, gdouble min, gdouble max);

void oio_var_register_time_t(time_t *p,
		enum oio_var_kind_e kind, const char *n, const char *descr,
		time_t def, time_t min, time_t max);

/**
 * Try to feed all the registered configuration variables with the content
 * of the given configuration, for the given namespace.
 */
void oio_var_value_all_with_config(struct oio_cfg_handle_s *cfg, const char *ns);

/**
 * Feed a named value and return if it matches a variable already declared.
 * The variable is marked as readonly, and the previous value is replaced.
 */
gboolean oio_var_fix_one(const char *name, const char *value);

/**
 * Feed a named value and return if it matches a variable already declared.
 * If the variable was marked readonly, this is not an error and TRUE will
 * be returned, and the value will be left untouched.
 */
gboolean oio_var_value_one(const char *name, const char *value);

/**
 * Feed the central configuration with all the variables found in the given
 * files, for the given namespace. If `sys` is TRUE then the system files will
 * be read. Then all the files in `files` will subsequently update (overwrite)
 * the central values.
 *
 * @return TRUE if the NS was known, FALSE if not configured locally
 */
gboolean oio_var_value_with_files(const char *ns, gboolean sys, GSList *files);

/**
 * Iterate over all the registered variables and call the hook for each
 * of them.
 */
void oio_var_list_all(void (*hook) (const char *k, const char *v));
void oio_var_list_all_ext(void (*hook) (const char *k, const char *v, void *u),
		void *udata);

/**
 * Wraps oio_var_list_all() to build a simple JSON object, where each key
 * is the name of the variable and each corresponding value the textual
 * representation of the value.
 */
GString* oio_var_list_as_json(void);

/**
 * Set all the variables to their default value
 */
void oio_var_reset_all(void);

gchar* oio_var_get_string(const char *v);

#endif /* OIO_SDS__core__var_h */
