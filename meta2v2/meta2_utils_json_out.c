/*
OpenIO SDS meta2v2
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

#include <glib.h>

#include <metautils/lib/metautils.h>

#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>

#include <meta2v2/meta2_utils_json.h>

static void
encode_alias (GString *g, gpointer bean)
{
	OIO_JSON_append_gstr (g, "name", ALIASES_get_alias(bean));
	g_string_append_c(g, ',');
	OIO_JSON_append_int(g, "version", ALIASES_get_version(bean));
	g_string_append_c(g, ',');
	OIO_JSON_append_int (g, "ctime", ALIASES_get_ctime(bean));
	g_string_append_c(g, ',');
	OIO_JSON_append_int (g, "mtime", ALIASES_get_mtime(bean));
	g_string_append_c(g, ',');
	OIO_JSON_append_bool(g, "deleted", ALIASES_get_deleted(bean));
	g_string_append_c(g, ',');
	OIO_JSON_append_gba(g, "header", ALIASES_get_content(bean));
}

static void
encode_header (GString *g, gpointer bean)
{
	OIO_JSON_append_gba(g, "id", CONTENTS_HEADERS_get_id(bean));
	g_string_append_c(g, ',');
	OIO_JSON_append_gba(g, "hash", CONTENTS_HEADERS_get_hash(bean));
	g_string_append_c(g, ',');
	OIO_JSON_append_int(g, "size", CONTENTS_HEADERS_get_size(bean));
	g_string_append_c(g, ',');
	OIO_JSON_append_gstr(g, "policy", CONTENTS_HEADERS_get_policy(bean));
	g_string_append_c(g, ',');
	OIO_JSON_append_gstr(g, "chunk-method", CONTENTS_HEADERS_get_chunk_method(bean));
	g_string_append_c(g, ',');
	OIO_JSON_append_gstr(g, "mime-type", CONTENTS_HEADERS_get_mime_type(bean));
}

static void
encode_chunk (GString *g, gpointer bean)
{
	OIO_JSON_append_gstr(g, "id", CHUNKS_get_id(bean));
	g_string_append_c(g, ',');
	OIO_JSON_append_gstr(g, "pos", CHUNKS_get_position(bean));
	g_string_append_c(g, ',');
	OIO_JSON_append_gba(g, "hash", CHUNKS_get_hash(bean));
	g_string_append_c(g, ',');
	OIO_JSON_append_int(g, "size", CHUNKS_get_size(bean));
}

static void
encode_property (GString *g, gpointer bean)
{
	OIO_JSON_append_gstr(g, "alias", PROPERTIES_get_alias(bean));
	g_string_append_c(g, ',');
	OIO_JSON_append_int(g, "version", PROPERTIES_get_version(bean));
	g_string_append_c(g, ',');
	OIO_JSON_append_gstr(g, "key", PROPERTIES_get_key(bean));
	g_string_append_c(g, ',');
	OIO_JSON_append_gba(g, "value", PROPERTIES_get_value(bean));
}

static void
encode_bean (GString *g, gpointer bean)
{
	if (DESCR(bean) == &descr_struct_CHUNKS)
		return encode_chunk (g, bean);
	if (DESCR(bean) == &descr_struct_CONTENTS_HEADERS)
		return encode_header (g, bean);
	if (DESCR(bean) == &descr_struct_ALIASES)
		return encode_alias (g, bean);
	if (DESCR(bean) == &descr_struct_PROPERTIES)
		return encode_property (g, bean);
	g_assert_not_reached ();
}

//------------------------------------------------------------------------------

static void
_json_BEAN_only(GString *gstr, GSList *l, gconstpointer selector,
		gboolean extend, void (*encoder)(GString*,gpointer))
{
	gboolean first = TRUE;

	for (; l ;l=l->next) {
		if (selector && DESCR(l->data) != selector)
			continue;
		if (!first)
			g_string_append_c(gstr, ',');
		first = FALSE;
		g_string_append_c (gstr, '{');
		if (extend) {
			OIO_JSON_append_str (gstr, "type", DESCR(l->data)->name);
			g_string_append_c (gstr, ',');
		}
		encoder(gstr, l->data);
		g_string_append_c (gstr, '}');
	}
}

void
meta2_json_alias_only(GString *gstr, GSList *l, gboolean extend)
{
	_json_BEAN_only(gstr, l, &descr_struct_ALIASES, extend, encode_alias);
}

void
meta2_json_headers_only(GString *gstr, GSList *l, gboolean extend)
{
	_json_BEAN_only(gstr, l, &descr_struct_CONTENTS_HEADERS, extend, encode_header);
}

void
meta2_json_chunks_only(GString *gstr, GSList *l, gboolean extend)
{
	_json_BEAN_only(gstr, l, &descr_struct_CHUNKS, extend, encode_chunk);
}

void
meta2_json_dump_all_xbeans(GString *gstr, GSList *beans)
{
	_json_BEAN_only (gstr, beans, NULL, TRUE, encode_bean);
}

void
meta2_json_dump_all_beans(GString *gstr, GSList *beans)
{
	g_string_append_static(gstr, "\"aliases\":[");
	meta2_json_alias_only(gstr, beans, FALSE);
	g_string_append_static(gstr, "],\"headers\":[");
	meta2_json_headers_only(gstr, beans, FALSE);
	g_string_append_static(gstr, "],\"chunks\":[");
	meta2_json_chunks_only(gstr, beans, FALSE);
	g_string_append_c(gstr, ']');
}

