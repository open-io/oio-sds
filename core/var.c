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

#include <string.h>

#include <core/oiovar.h>
#include <core/oiolog.h>
#include <core/oiostr.h>
#include <core/oiocfg.h>
#include <core/internals.h>

enum oio_var_type_e {
	OIO_VARTYPE_gboolean,
	OIO_VARTYPE_guint,
	OIO_VARTYPE_guint32,
	OIO_VARTYPE_guint64,
	OIO_VARTYPE_gint,
	OIO_VARTYPE_gint32,
	OIO_VARTYPE_gint64,
	OIO_VARTYPE_gdouble,
	OIO_VARTYPE_time_t,
};

union oio_var_pointer_u {
	gboolean *b;
	guint *u;
	guint32 *u32;
	guint64 *u64;
	gint *i;
	gint32 *i32;
	gint64 *i64;
	gdouble *d;
	time_t *t;
};

union oio_var_default_u {
	gboolean b;
	guint u;
	guint32 u32;
	guint64 u64;
	gint i;
	gint32 i32;
	gint64 i64;
	gdouble d;
	time_t t;
};

struct oio_var_record_s {
	enum oio_var_type_e type;
	const char *name;
	const char *description;
	/* actual pointer to the variable */
	union oio_var_pointer_u ptr;
	/* default value when not specified */
	union oio_var_default_u def;
	union oio_var_default_u min;
	union oio_var_default_u max;
	/* value at the registration */
	union oio_var_default_u reg;
};

static volatile guint var_init = 0;
static GMutex var_lock = {0};
static GSList *var_records = NULL;

void _oio_var_constructor (void);

void __attribute__ ((constructor)) _oio_var_constructor (void) {
	if (g_atomic_int_compare_and_exchange(&var_init, 0, 1)) {
		g_mutex_init(&var_lock);
	}
}

static void
_register_record(const struct oio_var_record_s *rec)
{
	_oio_var_constructor();
	g_assert(g_atomic_int_get(&var_init) == 1);
	g_mutex_lock(&var_lock);
	var_records = g_slist_append(var_records, g_memdup(rec, sizeof(*rec)));
	g_mutex_unlock(&var_lock);
}

#define DEFINE_REGISTRATION_FUNC(Type,Field) \
void oio_var_register_##Type( \
		Type *p, Type def, \
		const char *n, const char *d, \
		Type min, Type max) { \
	struct oio_var_record_s rec = {0}; \
	rec.type = OIO_VARTYPE_##Type; \
	rec.name = n; \
	rec.description = d; \
	rec.ptr.Field = p; \
	rec.reg.Field = *(rec.ptr.Field); \
	rec.def.Field = def; \
	rec.min.Field = min; \
	rec.max.Field = max; \
	_register_record(&rec); \
}

void
oio_var_register_gboolean(gboolean *p, gboolean def, const char *n, const char *d)
{
	struct oio_var_record_s rec = {0};
	rec.type = OIO_VARTYPE_gboolean;
	rec.name = n;
	rec.description = d;
	rec.ptr.b = p;
	rec.reg.b = *(rec.ptr.b);
	rec.def.b = def;
	_register_record(&rec);
}

DEFINE_REGISTRATION_FUNC(guint,u);
DEFINE_REGISTRATION_FUNC(guint32,u32);
DEFINE_REGISTRATION_FUNC(guint64,u64);
DEFINE_REGISTRATION_FUNC(gint,i);
DEFINE_REGISTRATION_FUNC(gint32,i32);
DEFINE_REGISTRATION_FUNC(gint64,i64);
DEFINE_REGISTRATION_FUNC(gdouble,d);
DEFINE_REGISTRATION_FUNC(time_t,t);

static void
_record_set(struct oio_var_record_s *rec, union oio_var_default_u v)
{
	switch (rec->type) {
		case OIO_VARTYPE_gboolean:
			*(rec->ptr.b) = v.b;
			return;
		case OIO_VARTYPE_guint:
			*(rec->ptr.u) = CLAMP(v.u, rec->min.u, rec->max.u);
			return;
		case OIO_VARTYPE_guint32:
			*(rec->ptr.u32) = CLAMP(v.u32, rec->min.u32, rec->max.u32);
			return;
		case OIO_VARTYPE_guint64:
			*(rec->ptr.u64) = CLAMP(v.u64, rec->min.u64, rec->max.u64);
			return;
		case OIO_VARTYPE_gint:
			*(rec->ptr.i) = CLAMP(v.i, rec->min.i, rec->max.i);
			return;
		case OIO_VARTYPE_gint32:
			*(rec->ptr.i32) = CLAMP(v.i32, rec->min.i32, rec->max.i32);
			return;
		case OIO_VARTYPE_gint64:
			*(rec->ptr.i64) = CLAMP(v.i64, rec->min.i64, rec->max.i64);
			return;
		case OIO_VARTYPE_gdouble:
			*(rec->ptr.d) = CLAMP(v.d, rec->min.d, rec->max.d);
			return;
		case OIO_VARTYPE_time_t:
			*(rec->ptr.t) = CLAMP(v.t, rec->min.t, rec->max.t);
			return;
	}
	g_assert_not_reached();
}

static void
_record_set_to_value(struct oio_var_record_s *rec, const char *value)
{
	gint64 i64;
	guint64 u64;
	gchar *end = NULL;
	union oio_var_default_u v = rec->def;

	switch (rec->type) {
		case OIO_VARTYPE_gboolean:
			v.b = oio_str_parse_bool(value, rec->def.b);
			break;
		case OIO_VARTYPE_guint:
			u64 = g_ascii_strtoull(value, &end, 10);
			if (!end || !*end)
				v.u = MIN(u64, G_MAXUINT);
			break;
		case OIO_VARTYPE_guint32:
			u64 = g_ascii_strtoull(value, &end, 10);
			if (!end || !*end)
				v.u32 = MIN(u64, G_MAXUINT32);
			break;
		case OIO_VARTYPE_guint64:
			u64 = g_ascii_strtoull(value, &end, 10);
			if (!end || !*end)
				v.u64 = u64;
			break;
		case OIO_VARTYPE_gint:
			i64 = g_ascii_strtoll(value, &end, 10);
			if (!end || !*end)
				v.i = CLAMP(i64, G_MININT, G_MAXINT);
			break;
		case OIO_VARTYPE_gint32:
			i64 = g_ascii_strtoll(value, &end, 10);
			if (!end || !*end)
				v.i32 = CLAMP(i64, G_MININT32, G_MAXINT32);
			break;
		case OIO_VARTYPE_gint64:
			i64 = g_ascii_strtoll(value, &end, 10);
			if (!end || !*end)
				v.i64 = i64;
			break;
		case OIO_VARTYPE_gdouble:
			v.d = g_ascii_strtod(value, NULL);
			break;
		case OIO_VARTYPE_time_t:
			u64 = g_ascii_strtoull(value, &end, 10);
			if (!end || !*end)
				v.t = u64;
			break;
		default:
			g_assert_not_reached();
			break;
	}

	return _record_set(rec, v);
}

void
oio_var_value_all_with_config(struct oio_cfg_handle_s *cfg, const char *ns)
{
	g_mutex_lock(&var_lock);
	for (GSList *l=var_records; l ;l=l->next) {
		if (!l->data)
			continue;
		struct oio_var_record_s *rec = l->data;
		gchar *value = oio_cfg_handle_get(cfg, ns, rec->name);
		if (value) {
			_record_set_to_value(rec, value);
			g_free(value);
		}
	}
	g_mutex_unlock(&var_lock);
}

gboolean
oio_var_value_one_with_option(const char *name, const char *value)
{
	gboolean rc = FALSE;
	if (name && value && var_init) {
		g_mutex_lock(&var_lock);
		for (GSList *l=var_records; l ;l=l->next) {
			if (!l->data)
				continue;
			struct oio_var_record_s *rec = l->data;
			if (!strcmp(rec->name, name)) {
				_record_set_to_value(rec, value);
				rc = TRUE;
				break;
			}
		}
		g_mutex_unlock(&var_lock);
	}
	return rc;
}

void
oio_var_list_all(void (*hook) (const char *k, const char *v))
{
	gint64 i64;

	if (!hook)
		return;

	g_mutex_lock(&var_lock);
	for (GSList *l=var_records; l ;l=l->next) {
		if (!l->data)
			continue;
		struct oio_var_record_s *rec = l->data;
		gchar tmp[256];
		switch (rec->type) {
			case OIO_VARTYPE_gboolean:
				g_strlcpy(tmp, *(rec->ptr.b)?"on":"off", sizeof(tmp));
				break;
			case OIO_VARTYPE_guint:
				g_snprintf(tmp, sizeof(tmp), "%u", *(rec->ptr.u));
				break;
			case OIO_VARTYPE_guint32:
				g_snprintf(tmp, sizeof(tmp), "%"G_GUINT32_FORMAT, *(rec->ptr.u32));
				break;
			case OIO_VARTYPE_guint64:
				g_snprintf(tmp, sizeof(tmp), "%"G_GUINT64_FORMAT, *(rec->ptr.u64));
				break;
			case OIO_VARTYPE_gint:
				g_snprintf(tmp, sizeof(tmp), "%i", *(rec->ptr.i));
				break;
			case OIO_VARTYPE_gint32:
				g_snprintf(tmp, sizeof(tmp), "%"G_GINT32_FORMAT, *(rec->ptr.i32));
				break;
			case OIO_VARTYPE_gint64:
				g_snprintf(tmp, sizeof(tmp), "%"G_GINT64_FORMAT, *(rec->ptr.i64));
				break;
			case OIO_VARTYPE_gdouble:
				g_snprintf(tmp, sizeof(tmp), "%f", *(rec->ptr.d));
				break;
			case OIO_VARTYPE_time_t:
				i64 = *(rec->ptr.t);
				g_snprintf(tmp, sizeof(tmp), "%"G_GINT64_FORMAT, i64);
				break;
		}
		(*hook)(rec->name, tmp);
	}
	g_mutex_unlock(&var_lock);
}

GString*
oio_var_list_as_json(void)
{
	GString *gstr = g_string_sized_new (4096);
	void _hook (const char *k, const char *v) {
		if (gstr->len > 1)
			g_string_append_c(gstr, ',');
		oio_str_gstring_append_json_pair(gstr, k, v);
	}
	g_string_append_c (gstr, '{');
	oio_var_list_all(_hook);
	g_string_append_c (gstr, '}');

	return gstr;
}
