/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <metatypes.h>
#include <metautils.h>
#include <metacomm.h>

static void test_headers(void);
static void test_chunks(void);
static void test_properties(void);
static void test_contents_v2(void);

static GByteArray* gba_add_str(const gchar *str);
static meta2_raw_content_v2_t* create_v2_content(void);

/* ------------------------------------------------------------------------- */

GByteArray*
gba_add_str(const gchar *str)
{
	GByteArray *gba;

	gba = g_byte_array_new();
	g_byte_array_append(gba, (guint8*)str, strlen(str)+1);
	return gba;
}

static meta2_raw_content_v2_t*
create_v2_content(void)
{
	int i;
	GSList *l;
	meta2_raw_content_v2_t *content;

	content = g_malloc0(sizeof(*content));
	g_snprintf(content->header.path, sizeof(content->header.path), "content_path_%d", rand());
	content->header.nb_chunks = 5;
	content->header.metadata = gba_add_str("user metadata");
	content->header.system_metadata = gba_add_str("system metadata");

	for (i=0; i<5 ;i++) {
		meta2_raw_chunk_t *chunk;
		gchar str[32];
		
		g_snprintf(str, sizeof(str), "chunk %i metadata", i);
		chunk = g_malloc0(sizeof(*chunk));
		chunk->position = i;
		chunk->size = rand();
		chunk->metadata = gba_add_str(str);
		content->raw_chunks = g_slist_prepend(content->raw_chunks, chunk);
	}

	for (i=0; i<5 ;i++) {
		meta2_property_t *prop;
		gchar str[32];
		
		g_snprintf(str, sizeof(str), "prop_value %i", i);
		prop = g_malloc0(sizeof(*prop));
		prop->name = g_strdup_printf("prop_name %i", i);
		prop->value = gba_add_str(str);
		content->properties = g_slist_prepend(content->properties, prop);
	}

	for (l=content->raw_chunks; l ;l=l->next) {
		meta2_raw_chunk_t *chunk = l->data;
		content->header.size += chunk->size;
	}

	return content;
}

/* ------------------------------------------------------------------------- */

void
test_headers(void)
{
	GError *err;
	meta2_raw_content_header_t *src, *dst;
	GSList *list_src, *list_dst;
	gchar *src_descr, *dst_descr;
	GByteArray *gba;
	int rc;
	gsize len;


	src = g_malloc0(sizeof(*src));
	src->metadata = gba_add_str("user metadata");
	src->system_metadata = gba_add_str("system metadata");
	list_src = g_slist_prepend(NULL, src);
	dst = NULL;
	list_dst = NULL;
	err = NULL;

	src_descr = meta2_raw_content_header_to_string(src);
	g_printerr("SRC : %s\n", src_descr);

	gba = meta2_raw_content_header_marshall_gba(list_src, &err);
	g_printerr("marshall: gba=%p code=%d message=%s\n", gba, gerror_get_code(err), gerror_get_message(err));
	g_assert(gba != NULL && err == NULL);
	len = gba->len;
	rc = meta2_raw_content_header_unmarshall(&list_dst, gba->data, &len, &err);
	g_printerr("unmarshall: rc=%d errno=%d code=%d message=%s\n", rc, errno, gerror_get_code(err), gerror_get_message(err));
	g_assert(rc != 0);
	g_assert(err == NULL);
	g_assert(len == gba->len);
	g_assert(list_dst != NULL);
	g_assert(g_slist_length(list_dst) == g_slist_length(list_src));
	dst = list_dst->data;
	dst_descr = meta2_raw_content_header_to_string(dst);
	g_printerr("DST : %s\n", dst_descr);
	g_assert(0 == meta2_raw_content_header_cmp(src, dst));

	g_byte_array_free(gba, TRUE);
	g_slist_foreach(list_dst, meta2_raw_content_header_gclean, NULL);
	g_slist_foreach(list_src, meta2_raw_content_header_gclean, NULL);
	g_slist_free(list_dst);
	g_slist_free(list_src);
	g_free(src_descr);
	g_free(dst_descr);
}

void
test_chunks(void)
{
	GError *err;
	meta2_raw_chunk_t *src, *dst;
	GSList *list_src, *list_dst;
	gchar *src_descr, *dst_descr;
	GByteArray *gba;
	int rc;
	gsize len;

	src = g_malloc0(sizeof(*src));
	src->metadata = gba_add_str("chunk metadata");
	list_src = g_slist_prepend(NULL, src);
	dst = NULL;
	list_dst = NULL;
	err = NULL;

	src_descr = meta2_raw_chunk_to_string(src);
	g_printerr("SRC : %s\n", src_descr);

	gba = meta2_raw_chunk_marshall_gba(list_src, &err);
	g_printerr("marshall: gba=%p code=%d message=%s\n", gba, gerror_get_code(err), gerror_get_message(err));
	g_assert(gba != NULL && err == NULL);
	len = gba->len;
	rc = meta2_raw_chunk_unmarshall(&list_dst, gba->data, &len, &err);
	g_printerr("unmarshall: rc=%d errno=%d code=%d message=%s\n", rc, errno, gerror_get_code(err), gerror_get_message(err));
	g_assert(rc != 0);
	g_assert(err == NULL);
	g_assert(len == gba->len);
	g_assert(list_dst != NULL);
	g_assert(g_slist_length(list_dst) == g_slist_length(list_src));
	dst = list_dst->data;
	dst_descr = meta2_raw_chunk_to_string(dst);
	g_printerr("DST : %s\n", dst_descr);
	g_assert(0 == meta2_raw_chunk_cmp(src, dst));

	g_byte_array_free(gba, TRUE);
	g_slist_foreach(list_dst, meta2_raw_chunk_gclean, NULL);
	g_slist_foreach(list_src, meta2_raw_chunk_gclean, NULL);
	g_slist_free(list_dst);
	g_slist_free(list_src);
	g_free(src_descr);
	g_free(dst_descr);
}

void
test_properties(void)
{
	GError *err;
	meta2_property_t *src, *dst;
	GSList *list_src, *list_dst;
	gchar *src_descr, *dst_descr;
	GByteArray *gba;
	int rc;
	gsize len;

	src = g_malloc0(sizeof(*src));
	src->name = g_strdup("property name");
	src->value = gba_add_str("property value");
	list_src = g_slist_prepend(NULL, src);
	dst = NULL;
	list_dst = NULL;
	err = NULL;

	src_descr = meta2_property_to_string(src);
	g_printerr("SRC : %s\n", src_descr);

	gba = meta2_property_marshall_gba(list_src, &err);
	g_printerr("marshall: gba=%p code=%d message=%s\n", gba, gerror_get_code(err), gerror_get_message(err));
	g_assert(gba != NULL && err == NULL);
	len = gba->len;
	rc = meta2_property_unmarshall(&list_dst, gba->data, &len, &err);
	g_printerr("unmarshall: rc=%d errno=%d code=%d message=%s\n", rc, errno, gerror_get_code(err), gerror_get_message(err));
	g_assert(rc != 0);
	g_assert(err == NULL);
	g_assert(len == gba->len);
	g_assert(list_dst != NULL);
	g_assert(g_slist_length(list_dst) == g_slist_length(list_src));
	dst = list_dst->data;
	dst_descr = meta2_property_to_string(dst);
	g_printerr("DST : %s\n", dst_descr);
	g_assert(0 == meta2_property_cmp(src, dst));

	g_byte_array_free(gba, TRUE);
	g_slist_foreach(list_dst, meta2_property_gclean, NULL);
	g_slist_foreach(list_src, meta2_property_gclean, NULL);
	g_slist_free(list_dst);
	g_slist_free(list_src);
	g_free(src_descr);
	g_free(dst_descr);
}

void
test_contents_v2(void)
{
	GError *err;
	meta2_raw_content_v2_t *src, *dst;
	GSList *list_src, *list_dst;
	gchar *src_descr, *dst_descr;
	GByteArray *gba;
	int rc;
	gsize len;

	src = create_v2_content();
	list_src = g_slist_prepend(NULL, src);
	dst = NULL;
	list_dst = NULL;
	err = NULL;

	src_descr = meta2_raw_content_v2_to_string(src);
	g_printerr("SRC : %s\n", src_descr);
	
	gba = meta2_raw_content_v2_marshall_gba(list_src, &err);
	g_printerr("marshall: gba=%p code=%d message=%s\n", gba, gerror_get_code(err), gerror_get_message(err));
	g_assert(gba != NULL && err == NULL);
	len = gba->len;
	rc = meta2_raw_content_v2_unmarshall(&list_dst, gba->data, &len, &err);
	g_printerr("unmarshall: rc=%d errno=%d code=%d message=%s\n", rc, errno, gerror_get_code(err), gerror_get_message(err));
	g_assert(rc != 0);
	g_assert(err == NULL);
	g_assert(len == gba->len);
	g_assert(list_dst != NULL);
	g_assert(g_slist_length(list_dst) == g_slist_length(list_src));
	dst = list_dst->data;
	dst_descr = meta2_raw_content_v2_to_string(dst);
	g_printerr("DST : %s\n", dst_descr);

	g_byte_array_free(gba, TRUE);
	g_slist_foreach(list_dst, meta2_raw_content_v2_gclean, NULL);
	g_slist_foreach(list_src, meta2_raw_content_v2_gclean, NULL);
	g_slist_free(list_dst);
	g_slist_free(list_src);
	g_free(src_descr);
	g_free(dst_descr);
}

/* ------------------------------------------------------------------------- */

int
main(int argc, char **args)
{
	(void) argc;
	(void) args;

	srand(time(0));
	log4c_init();

	test_headers();
	g_printerr("headers OK\n");

	test_properties();
	g_printerr("properties OK\n");

	test_chunks();
	g_printerr("chunks OK\n");

	test_contents_v2();
	g_printerr("contents_v2 OK\n");

	return 0;
}

