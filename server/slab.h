/*
OpenIO SDS server
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

struct data_slab_s
{
	enum {
		STYPE_BUFFER=1,
		STYPE_BUFFER_STATIC,
		STYPE_FILE,
		STYPE_PATH,
		STYPE_EOF
	} type;
	union {
		struct {
			guint start;
			guint end;
			guint alloc;
			guint8 *buff;
		} buffer;
		struct {
			off_t start;
			off_t end;
			int fd;
		} file;
		struct {
			gchar *path;
			enum {
				FLAG_UNLINK = 0x0001,
				FLAG_OFFSET = 0x0002,
				FLAG_END  =   0x0004
			} flags;
			off_t start;
			off_t end;
			int fd;
		} path;
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

void data_slab_trace(const gchar *tag, struct data_slab_s *ds);

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

void data_slab_sequence_trace(struct data_slab_sequence_s *dss);

gsize data_slab_sequence_size(struct data_slab_sequence_s *dss);

/* Slab constructors -------------------------------------------------------- */

struct data_slab_s * data_slab_make_empty(gsize alloc);

struct data_slab_s * data_slab_make_eof(void);

struct data_slab_s * data_slab_make_file(int fd, off_t start, off_t end);

struct data_slab_s * data_slab_make_path2(const gchar *path,
		off_t start, off_t end);

struct data_slab_s * data_slab_make_path(const gchar *path, gboolean must_unlink);

struct data_slab_s * data_slab_make_tempfile(const gchar *path);

struct data_slab_s *
data_slab_make_buffer2(guint8 *buff, gboolean tobefreed, gsize start,
		gsize end, gsize alloc);

static inline struct data_slab_s *
data_slab_make_static_buffer(guint8 *buff, gsize bs)
{
	return data_slab_make_buffer2(buff, FALSE, 0, bs, bs);
}

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
data_slab_make_string(const gchar *s)
{
	gsize l = strlen(s);
	return data_slab_make_buffer2((guint8*)g_strndup(s, l), TRUE, 0, l, l);
}

static inline struct data_slab_s *
data_slab_make_static_string(const gchar *s)
{
	gsize l = strlen(s);
	return data_slab_make_buffer2((guint8*)s, FALSE, 0, l, l);
}

#endif /*OIO_SDS__server__slab_h*/
