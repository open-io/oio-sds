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
	g_string_append_printf(g,
			"\"name\":\"%s\","
			"\"ver\":%"G_GINT64_FORMAT","
			"\"ctime\":%"G_GINT64_FORMAT","
			"\"header\":\"",
			ALIAS_get_alias(bean)->str,
			ALIAS_get_version(bean),
			ALIAS_get_ctime(bean));
	metautils_gba_to_hexgstr(g, ALIAS_get_content(bean));
	g_string_append_c(g, '"');
}

static void
encode_content (GString *g, gpointer bean)
{
	g_string_append(g, "\"id\":\"");
	metautils_gba_to_hexgstr(g, CONTENT_get_id(bean));
	g_string_append_printf(g, "\",\"hash\":\"");
	metautils_gba_to_hexgstr(g, CONTENT_get_hash(bean));
	g_string_append_printf(g, "\",\"size\":%"G_GINT64_FORMAT, CONTENT_get_size(bean));
	g_string_append_printf(g, ",\"ctime\":\"%"G_GINT64_FORMAT"\"", CONTENT_get_ctime(bean));
	g_string_append_printf(g, ",\"policy\":\"%s\"", CONTENT_get_policy(bean)->str);
	g_string_append_printf(g, ",\"mime-type\":\"%s\"", CONTENT_get_mime_type(bean)->str);
	g_string_append_printf(g, ",\"chunk_method\":\"%s\"", CONTENT_get_chunk_method(bean)->str);
}

static void
encode_chunk (GString *g, gpointer bean)
{
	g_string_append_printf(g, "\"id\":\"%s\",\"hash\":\"", CHUNK_get_id(bean)->str);
	metautils_gba_to_hexgstr(g, CHUNK_get_hash(bean));
	g_string_append_printf(g, "\",\"size\":%"G_GINT64_FORMAT",\"content\":\"", CHUNK_get_size(bean));
	metautils_gba_to_hexgstr(g, CHUNK_get_content(bean));
	g_string_append_printf(g, "\",\"pos\":\"%s\"", CHUNK_get_position(bean)->str);
	g_string_append_printf(g, ",\"ctime\":\"%"G_GINT64_FORMAT"\"", CHUNK_get_ctime(bean));
}

static void
encode_property (GString *g, gpointer bean)
{
	g_string_append_printf(g, "\"alias\":\"%s\",", PROPERTY_get_alias(bean)->str);
	g_string_append_printf(g, "\"version\":%"G_GINT64_FORMAT",", PROPERTY_get_version(bean));
	g_string_append_printf(g, "\"key\":\"%s\",", PROPERTY_get_key(bean)->str);
	g_string_append_printf(g, "\"value\":\"%.*s\"",
			PROPERTY_get_value(bean)->len,
			(gchar*) PROPERTY_get_value(bean)->data);
}

static void
encode_bean (GString *g, gpointer bean)
{
	if (DESCR(bean) == &descr_struct_CHUNK)
		return encode_chunk (g, bean);
	if (DESCR(bean) == &descr_struct_CONTENT)
		return encode_content (g, bean);
	if (DESCR(bean) == &descr_struct_ALIAS)
		return encode_alias (g, bean);
	if (DESCR(bean) == &descr_struct_PROPERTY)
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
		if (extend)
			g_string_append_printf (gstr, "\"type\":\"%s\",",
					DESCR(l->data)->name);
		encoder(gstr, l->data);
		g_string_append_c (gstr, '}');
	}
}

void
meta2_json_alias_only(GString *gstr, GSList *l, gboolean extend)
{
	_json_BEAN_only(gstr, l, &descr_struct_ALIAS, extend, encode_alias);
}

void
meta2_json_contents_only(GString *gstr, GSList *l, gboolean extend)
{
	_json_BEAN_only(gstr, l, &descr_struct_CONTENT, extend, encode_content);
}

void
meta2_json_chunks_only(GString *gstr, GSList *l, gboolean extend)
{
	_json_BEAN_only(gstr, l, &descr_struct_CHUNK, extend, encode_chunk);
}

void
meta2_json_dump_all_xbeans(GString *gstr, GSList *beans)
{
	_json_BEAN_only (gstr, beans, NULL, TRUE, encode_bean);
}

void
meta2_json_dump_all_beans(GString *gstr, GSList *beans)
{
	g_string_append(gstr, "\"aliases\":[");
	meta2_json_alias_only(gstr, beans, FALSE);

	g_string_append(gstr, "],\"contents\":[");
	meta2_json_contents_only(gstr, beans, FALSE);
	g_string_append(gstr, "],\"chunks\":[");
	meta2_json_chunks_only(gstr, beans, FALSE);
	g_string_append(gstr, "]");
}

