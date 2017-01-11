/*
OpenIO SDS metautils
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015-2016 OpenIO, as part of OpenIO Software Defined Storage

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

#include "metautils.h"

#include <json.h>

static void
clean_tag_value(struct service_tag_s *tag)
{
	if (tag->type == STVT_STR && tag->value.s)
		g_free(tag->value.s);
}

void
service_tag_set_value_i64(struct service_tag_s *tag, gint64 i)
{
	if (!tag)
		return;
	clean_tag_value(tag);
	tag->type = STVT_I64;
	tag->value.i = i;
}

gboolean
service_tag_get_value_i64(struct service_tag_s *tag, gint64* i, GError** error)
{
	if (tag == NULL) {
		GSETERROR(error, "Argument tag is NULL");
		return FALSE;
	}

	if (i == NULL) {
		GSETERROR(error, "Argument i is NULL");
		return FALSE;
	}

	if (tag->type != STVT_I64) {
		GSETERROR(error, "Tag is not of type I64");
		return FALSE;
	}

	memcpy(i, &(tag->value.i), sizeof(gint64));

	return TRUE;
}

void
service_tag_set_value_float(struct service_tag_s *tag, gdouble r)
{
	if (!tag)
		return;
	clean_tag_value(tag);
	tag->type = STVT_REAL;
	tag->value.r = r;
}

gboolean
service_tag_get_value_float(struct service_tag_s *tag, gdouble *r, GError** error)
{
	if (tag == NULL) {
		GSETERROR(error, "Argument tag is NULL");
		return FALSE;
	}

	if (r == NULL) {
		GSETERROR(error, "Argument r is NULL");
		return FALSE;
	}

	if (tag->type != STVT_REAL) {
		GSETERROR(error, "Tag is not of type REAL");
		return FALSE;
	}

	memcpy(r, &(tag->value.r), sizeof(double));

	return TRUE;
}

void
service_tag_set_value_boolean(struct service_tag_s *tag, gboolean b)
{
	if (!tag)
		return;
	clean_tag_value(tag);
	tag->type = STVT_BOOL;
	tag->value.b = b;
}

gboolean
service_tag_get_value_boolean(struct service_tag_s *tag, gboolean *b, GError **error)
{
	if (tag == NULL) {
		GSETERROR(error, "Argument tag is NULL");
		return FALSE;
	}

	if (b == NULL) {
		GSETERROR(error, "Argument b is NULL");
		return FALSE;
	}

	if (tag->type != STVT_BOOL) {
		GSETERROR(error, "Tag is not of type BOOL");
		return FALSE;
	}

	memcpy(b, &(tag->value.b), sizeof(gboolean));

	return TRUE;
}

void
service_tag_set_value_string(struct service_tag_s *tag, const gchar *s)
{
	gsize str_length;

	if (!tag || !s)
		return;
	clean_tag_value(tag);

	str_length = strlen(s);

	if (str_length < sizeof(tag->value.buf)) {
		tag->type = STVT_BUF;
		g_strlcpy(tag->value.buf, s, sizeof(tag->value.buf));
	}
	else {
		tag->type = STVT_STR;
		tag->value.s = g_strndup(s, str_length);
	}
}

gboolean
service_tag_get_value_string(struct service_tag_s *tag, gchar * s, gsize s_size, GError **error)
{
	if (tag == NULL) {
		GSETERROR(error, "Argument tag is NULL");
		return FALSE;
	}

	if (s == NULL) {
		GSETERROR(error, "Argument s is NULL");
		return FALSE;
	}

	if (tag->type == STVT_BUF) {
		g_strlcpy(s, tag->value.buf, s_size);
	}
	else if (tag->type ==  STVT_STR) {
		g_strlcpy(s, tag->value.s, s_size);
	}
	else {
		GSETERROR(error, "Tag is not of type BUF or STR");
		return FALSE;
	}

	return TRUE;
}

void
service_tag_copy(struct service_tag_s *dst, struct service_tag_s *src)
{
	if (!dst || !src)
		return;

	g_strlcpy(dst->name, src->name, sizeof(dst->name));

	switch (src->type) {
	case STVT_I64:
		service_tag_set_value_i64(dst, src->value.i);
		return;
	case STVT_REAL:
		service_tag_set_value_float(dst, src->value.r);
		return;
	case STVT_BOOL:
		service_tag_set_value_boolean(dst, src->value.b);
		return;
	case STVT_STR:
		service_tag_set_value_string(dst, src->value.s);
		return;
	case STVT_BUF:
		service_tag_set_value_string(dst, src->value.buf);
		return;
	}
}

struct service_tag_s *
service_tag_dup(struct service_tag_s *src)
{
	struct service_tag_s *result;

	if (!src)
		return NULL;

	result = g_malloc0(sizeof(struct service_tag_s));
	service_tag_copy(result, src);
	return result;
}

GPtrArray *
service_info_copy_tags(GPtrArray * original)
{
	int i, max;
	GPtrArray *copied;

	if (!original)
		return NULL;
	copied = g_ptr_array_new();
	for (i = 0, max = original->len; i < max; i++) {
		struct service_tag_s *tag, *tag_dup;

		tag = g_ptr_array_index(original, i);
		if (tag) {
			tag_dup = service_tag_dup(tag);
			g_ptr_array_add(copied, tag_dup);
		}
	}
	return copied;
}

void
service_tag_destroy(struct service_tag_s *tag)
{
	if (!tag)
		return;
	clean_tag_value(tag);
	g_free(tag);
}

gsize
service_tag_to_string(const struct service_tag_s *tag, gchar * dst, gsize dst_size)
{
	if (!dst || dst_size <= 0)
		return 0;
	*dst = '\0';
	if (!tag)
		return 0;

	switch (tag->type) {
	case STVT_I64:
		return g_snprintf(dst, dst_size, "%"G_GINT64_FORMAT, tag->value.i);
	case STVT_REAL:
		return g_snprintf(dst, dst_size, "%lf", tag->value.r);
	case STVT_BOOL:
		return g_snprintf(dst, dst_size, "%s", tag->value.b ? "true" : "false");
	case STVT_STR:
		return g_snprintf(dst, dst_size, "%s", tag->value.s);
	case STVT_BUF:
		return g_snprintf(dst, dst_size, "%.*s", (int)sizeof(tag->value.buf), tag->value.buf);
	}
	return 0;
}

void
service_info_clean(struct service_info_s *si)
{
	if (!si)
		return;
	if (si->tags) {
		GPtrArray *pa = si->tags;

		while (pa->len > 0) {
			struct service_tag_s *tag;

			tag = g_ptr_array_index(pa, 0);
			g_ptr_array_remove_index_fast(pa, 0);
			service_tag_destroy(tag);
		}
		g_ptr_array_free(pa, TRUE);
	}
	g_free(si);
}

void
service_info_cleanv(struct service_info_s **siv, gboolean content_only)
{
	if (!siv)
		return;
	if (content_only) {
		for (; *siv ;++siv)
			service_info_clean(*siv);
	}
	else {
		service_info_cleanv(siv, TRUE);
		g_free(siv);
	}
}

void
service_info_gclean(gpointer p1, gpointer p2)
{
	(void) p2;
	if (p1)
		service_info_clean((struct service_info_s *) p1);
}

struct service_info_s *
service_info_dup(const struct service_info_s *si)
{
	struct service_info_s *copy;

	if (!si)
		return NULL;
	copy = g_memdup(si, sizeof(struct service_info_s));
	if (!copy)
		return NULL;
	copy->tags = service_info_copy_tags(si->tags);
	return copy;
}

gint
service_info_sort_by_score(gconstpointer a, gconstpointer b)
{
	if (!a && b)
		return 1;
	if (a && !b)
		return -1;
	if (a == b)
		return 0;
	const struct service_info_s *si_a = a, *si_b = b;
	return si_b->score.value - si_a->score.value;
}

gboolean
service_info_equal(const struct service_info_s * si1, const struct service_info_s * si2)
{
	if (si1 == si2)
		return TRUE;
	if (si1 == NULL || si2 == NULL)
		return FALSE;

	return addr_info_equal(&(si1->addr), &(si2->addr))
		&& !strcmp(si1->ns_name, si2->ns_name) && !strcmp(si1->type, si2->type);
}

struct service_tag_s *
service_info_get_tag(GPtrArray * a, const gchar * name)
{
	if (!a || !name || !a->len)
		return NULL;

	for (guint i=0; i<a->len ;i++) {
		struct service_tag_s *pSrv = g_ptr_array_index(a, i);
		if (!pSrv)
			return NULL;
		if (!strcmp(pSrv->name, name))
			return pSrv;
	}
	return NULL;
}

struct service_tag_s *
service_info_ensure_tag(GPtrArray * a, const gchar * name)
{
	struct service_tag_s *srvtag;

	if (!a || !name)
		return NULL;
	srvtag = service_info_get_tag(a, name);
	if (!srvtag) {
		srvtag = g_malloc0(sizeof(struct service_tag_s));
		g_strlcpy(srvtag->name, name, sizeof(srvtag->name));
		g_ptr_array_add(a, srvtag);
		srvtag->type = STVT_BOOL;
		srvtag->value.b = FALSE;
	}

	return srvtag;
}

void
service_info_remove_tag(GPtrArray * a, const gchar * name)
{
	if (!a || !name || a->len <= 0)
		return;

	const guint max = a->len;
	for (guint i = 0; i < max; i++) {
		struct service_tag_s *pSrv = g_ptr_array_index(a, i);
		if (!pSrv)
			continue;
		if (!strcmp(pSrv->name, name)) {
			service_tag_destroy(pSrv);
			g_ptr_array_remove_index_fast(a, i);
			return;
		}
	}
}

void
service_info_swap(struct service_info_s *si0, struct service_info_s *si1)
{
	struct service_info_s tmp;
	EXTRA_ASSERT(si0 != NULL);
	EXTRA_ASSERT(si1 != NULL);
	memcpy(&tmp, si0, sizeof(struct service_info_s));
	memcpy(si0, si1, sizeof(struct service_info_s));
	memcpy(si1, &tmp, sizeof(struct service_info_s));
}

const gchar *
service_info_get_tag_value(const struct service_info_s *si,
		const gchar *name, const gchar *def)
{
	struct service_tag_s *tag;

	if (!si || !si->tags)
		return def;
	if (!(tag = service_info_get_tag(si->tags, name)))
		return def;
	if (tag->type == STVT_STR)
		return tag->value.s;
	if (tag->type == STVT_BUF)
		return tag->value.buf;
	return def;
}

const gchar *
service_info_get_rawx_location(const struct service_info_s *si, const gchar *d)
{
	return service_info_get_tag_value(si, NAME_TAGNAME_RAWX_LOC, d);
}

const gchar *
service_info_get_rawx_volume(const struct service_info_s *si, const gchar *d)
{
	return service_info_get_tag_value(si, NAME_TAGNAME_RAWX_VOL, d);
}

void
oio_parse_service_key(const char *key, gchar **ns, gchar **type, gchar **id)
{
	char **toks = g_strsplit(key, "|", -1);
	if (ns && toks[0])
		*ns = toks[0];
	else
		g_free(toks[0]);

	if (type && toks[1])
		*type = toks[1];
	else
		g_free(toks[1]);

	if (id && toks[2])
		*id = toks[2];
	else
		g_free(toks[2]);

	g_free(toks);
}

void oio_parse_chunk_url(const gchar *url,
		gchar **type, gchar **netloc, gchar **id)
{
	gchar *_type = NULL;
	if (g_str_has_prefix(url, "http://")) {
		_type = NAME_SRVTYPE_RAWX;
		const char * start = url + sizeof("http://") - 1;
		const char * first_slash = strchr(start, '/');
		if (first_slash) {
			if (netloc)
				*netloc = g_strndup(start, first_slash - start);
			if (id)
				*id = g_strdup(first_slash + 1);
		}
	} else if (g_str_has_prefix(url, "b2/") || g_str_has_prefix(url, "b2:")) {
		_type = "b2";
		if (id)
			*id = g_strdup(url + 3);
	} else if (g_str_has_prefix(url, "k/")) {
		_type = "k";
		if (netloc)
			*netloc = g_strdup(url + 2);
	}

	if (type)
		*type = g_strdup(_type);
}

gchar *
oio_make_service_key(const char *ns_name, const char *type, const char *id)
{
	return g_strdup_printf("%s|%s|%s", ns_name, type, id);
}

gchar *
service_info_key (const struct service_info_s *si)
{
	gchar addr[STRLEN_ADDRINFO];
	const char *explicit = service_info_get_tag_value(si, "tag.id", NULL);
	if (explicit)
		return oio_make_service_key(si->ns_name, si->type, explicit);
	grid_addrinfo_to_string(&si->addr, addr, sizeof(struct addr_info_s));
	return oio_make_service_key(si->ns_name, si->type, addr);
}

void
service_info_to_lb_item(const struct service_info_s *si,
		struct oio_lb_item_s *item)
{
	g_assert_nonnull(si);
	g_assert_nonnull(item);
	/* Take location from:
	 * - tag.loc as a hexadecimal number or
	 * - tag.log as a hash dot-separated string or
	 * - IP address and port */
	const gchar *loc_str = service_info_get_tag_value(si, "tag.loc", NULL);
	if (!loc_str) {
		item->location = location_from_addr_info(&(si->addr));
	} else if (!g_str_has_prefix(loc_str, "0x") ||
			!(item->location = g_ascii_strtoull(loc_str, NULL, 16))) {
		item->location = location_from_dotted_string(loc_str);
	}
	item->weight = CLAMP(si->score.value, 0, 100);
	gchar *key = service_info_key(si);
	g_strlcpy(item->id, key, LIMIT_LENGTH_SRVID);
	g_free(key);
}

//------------------------------------------------------------------------------

static void
_append_one_tag(GString* gstr, struct service_tag_s *tag)
{
	oio_str_gstring_append_json_quote(gstr, tag->name);
	g_string_append_c(gstr, ':');
	switch (tag->type) {
		case STVT_I64:
			g_string_append_printf(gstr, "%"G_GINT64_FORMAT, tag->value.i);
			return;
		case STVT_REAL:
			g_string_append_printf(gstr, "%f", tag->value.r);
			return;
		case STVT_BOOL:
			if (tag->value.b)
				g_string_append_static(gstr, "true");
			else
				g_string_append_static(gstr, "false");
			return;
		case STVT_STR:
			oio_str_gstring_append_json_quote(gstr, tag->value.s);
			return;
		case STVT_BUF:
			oio_str_gstring_append_json_quote(gstr, tag->value.buf);
			return;
	}
}

static void
_append_all_tags(GString *gstr, GPtrArray *tags)
{
	if (!tags || !tags->len)
		return;

	guint i, max;
	for (i=0,max=tags->len; i<max; ++i) {
		if (i)
			g_string_append_c(gstr, ',');
		_append_one_tag(gstr, tags->pdata[i]);
	}
}

void
service_info_encode_json(GString *gstr, const struct service_info_s *si, gboolean full)
{
	if (!si)
		return;
	gchar straddr[STRLEN_ADDRINFO];
	grid_addrinfo_to_string(&(si->addr), straddr, sizeof(straddr));
	g_string_append_c(gstr, '{');
	OIO_JSON_append_str(gstr, "addr", straddr);
	g_string_append_c(gstr, ',');
	OIO_JSON_append_int(gstr, "score", si->score.value);
	if (full) {
		g_string_append_c(gstr, ',');
		OIO_JSON_append_str(gstr, "ns", si->ns_name);
		g_string_append_c(gstr, ',');
		OIO_JSON_append_str(gstr, "type", si->type);
	}
	g_string_append_static(gstr, ",\"tags\":{");
	_append_all_tags(gstr, si->tags);
	g_string_append_static(gstr, "}}");
}

static struct service_tag_s *
_srvtag_load_json (const gchar *name, struct json_object *obj)
{
	struct service_tag_s *tag = g_malloc0(sizeof(struct service_tag_s));
	g_strlcpy(tag->name, name, sizeof(tag->name));
	if (json_object_is_type(obj, json_type_int)) {
		service_tag_set_value_i64(tag, json_object_get_int64(obj));
	} else if (json_object_is_type(obj, json_type_string)) {
		service_tag_set_value_string(tag, json_object_get_string(obj));
	} else if (json_object_is_type(obj, json_type_double)) {
		service_tag_set_value_float(tag, json_object_get_double(obj));
	} else if (json_object_is_type(obj, json_type_boolean)) {
		service_tag_set_value_boolean(tag, json_object_get_boolean(obj));
	} else {
		service_tag_set_value_boolean(tag, FALSE);
	}
	return tag;
}

GError*
service_info_load_json_object(struct json_object *obj,
		struct service_info_s **out, gboolean permissive)
{
	EXTRA_ASSERT(out != NULL); *out = NULL;

	struct json_object *ns, *type, *url, *score, *tags;
	struct oio_ext_json_mapping_s mapping[] = {
		{"ns",    &ns,    json_type_string, !permissive},
		{"type",  &type,  json_type_string, !permissive},
		{"addr",  &url,   json_type_string, 1},
		{"score", &score, json_type_int,    !permissive},
		{"tags",  &tags,  json_type_object, 0},
		{NULL, NULL, 0, 0}
	};
	GError *err = oio_ext_extract_json (obj, mapping);
	if (err) return err;

	struct addr_info_s addr;
	if (!grid_string_to_addrinfo(json_object_get_string(url), &addr))
		return NEWERROR(CODE_BAD_REQUEST, "Invalid address");

	struct service_info_s *si = g_malloc0(sizeof(struct service_info_s));
	if (ns)
		g_strlcpy(si->ns_name, json_object_get_string(ns), sizeof(si->ns_name));
	memcpy (&si->addr, &addr, sizeof(struct addr_info_s));
	if (type)
		g_strlcpy(si->type, json_object_get_string(type), sizeof(si->type));
	if (score)
		si->score.value = json_object_get_int(score);

	if (tags) { json_object_object_foreach(tags,key,val) {
		if (!g_str_has_prefix(key, "tag.") && !g_str_has_prefix(key, "stat."))
			continue;
		struct service_tag_s *tag = _srvtag_load_json(key, val);
		if (tag) {
			if (!si->tags)
				si->tags = g_ptr_array_new();
			g_ptr_array_add(si->tags, tag);
		}
	} }
	*out = si;
	return NULL;
}

GError*
service_info_load_json(const gchar *encoded, struct service_info_s **out,
		gboolean permissive)
{
	struct json_tokener *tok = json_tokener_new();
	struct json_object *obj = json_tokener_parse_ex(tok,
			encoded, strlen(encoded));
	json_tokener_free(tok);
	GError *err = service_info_load_json_object(obj, out, permissive);
	json_object_put(obj);
	return err;
}

gchar*
get_rawx_location(service_info_t* rawx)
{
	const gchar *loc = service_info_get_rawx_location(rawx, NULL);
	return loc && *loc ? g_strdup(loc) : NULL;
}

guint
distance_between_location(const gchar *loc1, const gchar *loc2)
{
	/* The arrays of tokens. */
	gchar **split_loc1, **split_loc2;
	/* Used to iterate over the arrays of tokens. */
	gchar **iter_tok1, **iter_tok2;
	/* The current tokens. */
	gchar *cur_tok1, *cur_tok2;
	/* Stores the greatest number of tokens in both location names. */
	guint num_tok = 0U;
	/* Number of the current token. */
	guint cur_iter = 0U;
	/* TRUE if a different token was found. */
	gboolean found_diff = FALSE;
	/* Distance between 2 tokens. */
	guint token_dist;

	if ((!loc1 || !*loc1) && (!loc2 || !*loc2))
		return 1U;

	split_loc1 = g_strsplit(loc1, ".", 0);
	split_loc2 = g_strsplit(loc2, ".", 0);

	iter_tok1 = split_loc1;
	iter_tok2 = split_loc2;

	cur_tok2 = *iter_tok2;

	while ((cur_tok1 = *iter_tok1++)) {
		num_tok++;
		if (cur_tok2 && (cur_tok2 = *iter_tok2++) && !found_diff) {
			cur_iter++;
			/* if both tokens are equal, continue */
			/* else set the found_diff flag to TRUE, keep the value of cur_iter and continue to set num_tok */
			if (g_strcmp0(cur_tok1, cur_tok2))
				found_diff = TRUE;
		}
	}

	/* if loc2 has more tokens than loc1, increase num_tok to this value */
	if (cur_tok2) {
		while (*iter_tok2++)
			num_tok++;
	}

	/* Frees the arrays of tokens. */
	g_strfreev(split_loc1);
	g_strfreev(split_loc2);

	token_dist = num_tok - cur_iter + 1;

	/* If the token distance is 1 and the last tokens are equal (ie both locations are equal) -> return 0. */
	/* If the token distance is 1 and the last tokens are different -> return 1. */
	/* If the token distance is > 1, then return 2^(token_dist). */
	return token_dist > 1U ? 1U << (token_dist - 1U) : (found_diff ? 1U : 0U);
}

guint
distance_between_services(struct service_info_s *s0, struct service_info_s *s1)
{
	return distance_between_location(
			service_info_get_rawx_location(s0, ""),
			service_info_get_rawx_location(s1, ""));
}
