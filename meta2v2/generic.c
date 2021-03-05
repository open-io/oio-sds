/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS

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

#include <glib.h>

#include <metautils/lib/metautils.h>
#include <meta2v2/generic.h>

/* GVariant utils ---------------------------------------------------------- */

static gchar random_chars[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789"
	",?;.:!*$%#+-[](){}/\\";

static GString *
_gstr_assign(GString *base, GString *gstr)
{
	if (!base)
		base = g_string_sized_new(gstr ? gstr->len : 8);
	if (base != gstr) {
		g_string_set_size(base, 0);
		g_string_append_len(base, gstr->str, gstr->len);
	}
	return base;
}

static void
_gstr_randomize(GString *gstr)
{
	g_string_set_size(gstr, oio_ext_rand_int_range(1, 17));
	oio_str_randomize(gstr->str, gstr->len, random_chars);
}

static void
_gba_randomize(GByteArray *gba)
{
	g_byte_array_set_size(gba, oio_ext_rand_int_range(1, 19));
	oio_buf_randomize (gba->data, gba->len);
}

static GByteArray *
_gba_assign(GByteArray *base, GByteArray *gba)
{
	if (!base && gba) {
		base = g_byte_array_sized_new(gba ? gba->len : 8);
	} else if (base && !gba) {
		g_byte_array_free(base, TRUE);
		base = NULL;
	}
	if (base != gba) {
		g_byte_array_set_size(base, 0);
		g_byte_array_append(base, gba->data, gba->len);
	}
	return base;
}

/* -------------------------------------------------------------------------- */

void
_bean_clean(gpointer bean)
{
	size_t offset_fields;
	const struct field_descriptor_s *fd;

	if (!bean)
		return;

	offset_fields = DESCR(bean)->offset_fields;
	for (fd=DESCR(bean)->fields; fd->type ;fd++) {
		gpointer pf = ((guint8*)bean) + offset_fields + fd->offset;
		if (!*((gpointer*)pf))
			continue;
		switch (fd->type) {
			case FT_BOOL:
			case FT_INT:
			case FT_REAL:
				break;
			case FT_TEXT:
				g_string_free(GSTR(pf), TRUE);
				break;
			case FT_BLOB:
				g_byte_array_free(*((GByteArray**)pf), TRUE);
				break;
			default:
				g_assert_not_reached();
				break;
		}
	}

	memset(bean, 0, DESCR(bean)->struct_size);
	g_free(bean);
}

void
_bean_cleanv(gpointer *beanv)
{
	gpointer *pb;

	if (!beanv)
		return;
	for (pb = beanv; *pb ;pb++) {
		_bean_clean(*pb);
		*pb = NULL;
	}
	g_free(beanv);
}

void
_bean_cleanv2(GPtrArray *v)
{
	if (!v)
		return;
	while (v->len) {
		gpointer p = v->pdata[0];
		v->pdata[0] = NULL;
		g_ptr_array_remove_index_fast(v, 0);
		if (p)
			_bean_clean(p);
	}
	g_ptr_array_free(v, TRUE);
}

void
_bean_cleanl2(GSList *v)
{
	GSList *l;

	if (!v)
		return;
	for (l=v; l ;l=l->next) {
		_bean_clean(l->data);
		l->data = NULL;
	}
	g_slist_free(v);
}

/* -------------------------------------------------------------------------- */


void
_bean_buffer_cb(gpointer gpa, gpointer bean)
{
	EXTRA_ASSERT(gpa != NULL);
	EXTRA_ASSERT(bean != NULL);
	g_ptr_array_add((GPtrArray*)gpa, bean);
}

void
_bean_list_cb(gpointer plist, gpointer bean)
{
	EXTRA_ASSERT(plist != NULL);
	EXTRA_ASSERT(bean != NULL);
	*((GSList**)plist) = g_slist_prepend (*((GSList**)plist), bean);
}

/* -------------------------------------------------------------------------- */

GString*
_bean_debug(GString *gstr, gpointer bean)
{
	if (!gstr)
		gstr = g_string_sized_new(256);

	g_string_append_printf(gstr, "<%s:%p>(", DESCR(bean)->name, bean);

	const struct field_descriptor_s *fd;
	for (fd=DESCR(bean)->fields; fd->type ;fd++) {
		register gpointer pf = FIELD(bean, fd->position);
		EXTRA_ASSERT(pf != NULL);

		switch (fd->type) {
			case FT_BOOL:
				g_string_append_printf(gstr, "%s:%d, ",
						fd->name, *((gboolean*)pf));
				continue;
			case FT_INT:
				g_string_append_printf(gstr, "%s:%"G_GINT64_FORMAT", ",
						fd->name, *((gint64*)pf));
				continue;
			case FT_REAL:
				g_string_append_printf(gstr, "%s:%f, ",
						fd->name, *((gdouble*)pf));
				continue;
			case FT_TEXT:
				if (!*((gpointer*)pf))
					g_string_append_printf(gstr, "%s:NULL, ", fd->name);
				else
					g_string_append_printf(gstr, "%s:\"%s\", ",
							fd->name, GSTR(pf)->str);
				continue;
			case FT_BLOB:
				if (!*((gpointer*)pf))
					g_string_append_printf(gstr, "%s:NULL, ", fd->name);
				else {
					g_string_append_printf(gstr, "%s:0x\"", fd->name);
					metautils_gba_to_hexgstr(gstr, GBA(pf));
					g_string_append_static(gstr, "\", ");
				}
				continue;
			default:
				g_assert_not_reached();
				break;
		}
	}
	g_string_append_c(gstr, ')');

	return gstr;
}

void
_bean_debugl2 (const char *tag, GSList *beans)
{
	if (!GRID_DEBUG_ENABLED())
		return;
	GString *gs = g_string_sized_new(512);
	for (; beans ;beans=beans->next) {
		g_string_set_size (gs, 0);
		gs = _bean_debug (gs, beans->data);
		GRID_DEBUG ("%s %s", tag, gs->str);
	}
	g_string_free (gs, TRUE);
}

void
_bean_randomize(gpointer bean, gboolean avoid_pk)
{
	GRand *r = oio_ext_local_prng ();
	const struct field_descriptor_s *fd;

	EXTRA_ASSERT(bean != NULL);
	HDR(bean)->flags = BEAN_FLAG_DIRTY | (avoid_pk?0:BEAN_FLAG_TRANSIENT);

	for (fd = DESCR(bean)->fields; fd->type != FT_NONE; fd++) {
		register gpointer pf = FIELD(bean, fd->position);
		EXTRA_ASSERT(pf != NULL);

		if (fd->pk && avoid_pk)
			continue;

		switch (fd->type) {
			case FT_BOOL:
				*((gboolean*)pf) = g_rand_boolean(r);
				break;
			case FT_INT:
				*((gint64*)pf) = g_rand_int(r);
				break;
			case FT_REAL:
				*((gdouble*)pf) = g_rand_double(r);
				break;
			case FT_TEXT:
				_gstr_randomize(GSTR(pf));
				break;
			case FT_BLOB:
				_gba_randomize(GBA(pf));
				break;
			default:
				g_assert_not_reached();
				break;
		}
	}
}

const gchar *
_bean_get_typename(gpointer bean)
{
	EXTRA_ASSERT(bean != NULL);
	return DESCR(bean)->name;
}

gchar **
_bean_get_FK_names(gpointer bean)
{
	EXTRA_ASSERT(bean != NULL);
	return DESCR(bean)->fk_names;
}

gpointer
_bean_create(const struct bean_descriptor_s *descr)
{
	const struct field_descriptor_s *fd;
	gpointer result;

	EXTRA_ASSERT(descr != NULL);
	result = g_malloc0(descr->struct_size);
	HDR(result)->descr = descr;
	HDR(result)->flags = BEAN_FLAG_TRANSIENT|BEAN_FLAG_DIRTY;

	for (fd=descr->fields; fd->type ;fd++) {
		register gpointer pf = FIELD(result, fd->position);
		EXTRA_ASSERT(pf != NULL);

		switch (fd->type) {
			case FT_BOOL:
			case FT_INT:
			case FT_REAL:
				break;
			case FT_TEXT:
				GSTR(pf) = g_string_sized_new(8);
				break;
			case FT_BLOB:
				GBA(pf) = g_byte_array_sized_new(8);
				break;
			default:
				g_assert_not_reached();
				break;
		}
	}

	return result;
}

gpointer
_bean_create_child(gpointer bean, const gchar *fkname)
{
	const struct fk_descriptor_s *fk;
	const struct bean_descriptor_s *src_descr, *dst_descr;

	EXTRA_ASSERT(bean != NULL);
	EXTRA_ASSERT(fkname != NULL);
	src_descr = DESCR(bean);

	inline gpointer _build(struct fk_field_s *f0, struct fk_field_s *f1) {
		gpointer res = _bean_create(dst_descr);
		for (; f0->i >= 0 && f1->i >=0 ;f0++,f1++) {
			register gpointer pf0, pf1;

			const struct field_descriptor_s *fd0 = src_descr->fields + f0->i;
#ifdef HAVE_EXTRA_ASSERT
			const struct field_descriptor_s *fd1 = dst_descr->fields + f1->i;
			EXTRA_ASSERT(fd0->type == fd1->type);
#endif

			pf0 = FIELD(bean, f0->i);
			pf1 = FIELD(res, f1->i);
			switch (fd0->type) {
				case FT_BOOL:
					*((gboolean*)pf1) = *((gboolean*)pf0);
					break;
				case FT_INT:
					*((gint64*)pf1) = *((gint64*)pf0);
					break;
				case FT_REAL:
					*((gdouble*)pf1) = *((gdouble*)pf0);
					break;
				case FT_TEXT:
					GSTR(pf1) = _gstr_assign(GSTR(pf1), GSTR(pf0));
					break;
				case FT_BLOB:
					GBA(pf1) = _gba_assign(GBA(pf1), GBA(pf0));
					break;
				default:
					g_assert_not_reached();
					break;
			}
		}
		return res;
	}

	for (fk=DESCR(bean)->fk; fk->src ;fk++) {
		if (!strcmp(fk->name, fkname)) {
			EXTRA_ASSERT(DESCR(bean) == fk->src || DESCR(bean) == fk->dst);
			if (DESCR(bean) == fk->src) {
				dst_descr = fk->dst;
				return _build(fk->src_fields, fk->dst_fields);
			}
			if (DESCR(bean) == fk->dst) {
				dst_descr = fk->src;
				return _build(fk->dst_fields, fk->src_fields);
			}
		}
	}

	g_assert_not_reached();
	return NULL;
}

void
_bean_set_field_value(gpointer bean, guint pos, gpointer pv)
{
	const struct field_descriptor_s *fd;
	register gpointer pf;

	_bean_set_field(bean, pos);
	pf = FIELD(bean, pos);
	fd = DESCR(bean)->fields + pos;
	HDR(bean)->flags |= BEAN_FLAG_DIRTY;

	switch (fd->type) {
		case FT_BOOL:
			*((gboolean*)pf) = *((gboolean*)pv);
			return;
		case FT_INT:
			*((gint64*)pf) = *((gint64*)pv);
			return;
		case FT_REAL:
			*((gdouble*)pf) = *((gdouble*)pv);
			return;
		case FT_TEXT:
			GSTR(pf) = _gstr_assign(GSTR(pf), GSTR(pv));
			return;
		case FT_BLOB:
			GBA(pf) = _gba_assign(GBA(pf), GBA(pv));
			return;
		default:
			g_assert_not_reached();
			return;
	}
}

gpointer
_bean_dup(gpointer bean)
{
	const struct field_descriptor_s *fd;
	EXTRA_ASSERT(bean != NULL);
	gpointer copy = _bean_create(DESCR(bean));
	for (fd=DESCR(bean)->fields; fd->type ;fd++) {
		if (_bean_has_field(bean, fd->position)) {
			_bean_set_field_value(copy, fd->position,
					FIELD(bean, fd->position));
		}
	}
	return copy;
}

gint
_bean_compare_kind (gconstpointer b0, gconstpointer b1)
{
	if (!b0 && !b1) return 0;
	if (!b0) return 1;
	if (!b1) return -1;
	return DESCR(b0)->order - DESCR(b1)->order;
}

