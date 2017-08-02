/*
OpenIO SDS server
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

#ifndef OIO_SDS__server__slab_h
# define OIO_SDS__server__slab_h 1

# include <glib.h>
# include <string.h>
# include <sys/types.h>

enum data_slab_type_e {
	STYPE_BUFFER=1,
	STYPE_BUFFER_STATIC,
	STYPE_GBYTES,
	STYPE_EOF
};

struct data_slab_s
{
	enum data_slab_type_e type;
	union {
		GBytes *gbytes;
		struct {
			guint start;
			guint end;
			guint alloc;
			guint8 *buff;
		} buffer;
	} data;
	struct data_slab_s *next;
};

struct data_slab_sequence_s
{
	struct data_slab_s *first;
	struct data_slab_s *last;
};

/* Single-slab feature ------------------------------------------------------ */

void data_slab_free(struct data_slab_s *ds);

gboolean data_slab_has_data(struct data_slab_s *ds);

gboolean data_slab_send(struct data_slab_s *ds, int fd);

/*! Set p_size to the maximum value expected, it will be modified
 * with the value really returned. Do not free (*p_data), it is
 * associated to the slab and will be discarded with the slab.
 * @see data_slab_sequence_consume()
 */
gboolean data_slab_consume(struct data_slab_s *ds, guint8 **p_data,
		gsize *p_size);

gsize data_slab_size(struct data_slab_s *ds);

/* Slab-sequence features --------------------------------------------------- */

void data_slab_sequence_clean_data(struct data_slab_sequence_s *dss);

gboolean data_slab_sequence_ready_for_data(struct data_slab_sequence_s *dss);

gboolean data_slab_sequence_has_data(struct data_slab_sequence_s *dss);

gboolean data_slab_sequence_send(struct data_slab_sequence_s *dss, int fd);

void data_slab_sequence_append(struct data_slab_sequence_s *dss,
		struct data_slab_s *ds);

struct data_slab_s* data_slab_sequence_shift(
		struct data_slab_sequence_s *dss);

void data_slab_sequence_unshift(struct data_slab_sequence_s *dss,
		struct data_slab_s *ds);

/* Slab constructors -------------------------------------------------------- */

struct data_slab_s * data_slab_make_empty(gsize alloc);

struct data_slab_s * data_slab_make_eof(void);

struct data_slab_s * data_slab_make_gbytes(GBytes *gb);

struct data_slab_s *
data_slab_make_buffer2(guint8 *buff, gboolean tobefreed, gsize start,
		gsize end, gsize alloc);

static inline struct data_slab_s *
data_slab_make_buffer(guint8 *buff, gsize bs)
{
	return data_slab_make_buffer2(buff, TRUE, 0, bs, bs);
}

static inline struct data_slab_s *
data_slab_make_gstr(GString *gstr)
{
	guint l = gstr->len;
	return data_slab_make_buffer2((guint8*)g_string_free(gstr, FALSE), TRUE, 0, l, l);
}

static inline struct data_slab_s *
data_slab_make_gba(GByteArray *gba)
{
	guint l = gba->len;
	return data_slab_make_buffer2(g_byte_array_free(gba, FALSE), TRUE, 0, l, l);
}

static inline struct data_slab_s *
data_slab_make_static_string(const gchar *s)
{
	gsize l = strlen(s);
	return data_slab_make_buffer2((guint8*)s, FALSE, 0, l, l);
}

#endif /*OIO_SDS__server__slab_h*/
