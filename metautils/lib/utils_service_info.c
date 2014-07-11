#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "metautils"
#endif

#include "metautils.h"

static void
clean_tag_value(struct service_tag_s *tag)
{
	if (tag->type == STVT_STR && tag->value.s)
		g_free(tag->value.s);
	else if (tag->type == STVT_MACRO) {
		if (tag->value.macro.type) {
			g_free(tag->value.macro.type);
			tag->value.macro.type = NULL;
		}
		if (tag->value.macro.param) {
			g_free(tag->value.macro.param);
			tag->value.macro.param = NULL;
		}
	}
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
service_tag_set_value_macro(struct service_tag_s *tag, const gchar * type, const gchar * param)
{
	if (!tag || !type)
		return;
	clean_tag_value(tag);
	tag->type = STVT_MACRO;
	tag->value.macro.type = g_strdup(type);
	if (param)
		tag->value.macro.param = g_strdup(param);
}

gboolean
service_tag_get_value_macro(struct service_tag_s *tag, gchar * type, gsize type_size, gchar* param, gsize param_size, GError** error)
{
	if (tag == NULL) {
		GSETERROR(error, "Argument tag is NULL");
		return FALSE;
	}

	if (type == NULL) {
		GSETERROR(error, "Argument type is NULL");
		return FALSE;
	}

	if (param == NULL) {
		GSETERROR(error, "Argument param is NULL");
		return FALSE;
	}

	if (tag->type != STVT_MACRO) {
		GSETERROR(error, "Tag is not of type MACRO");
		return FALSE;
	}

	g_strlcpy(type, tag->value.macro.type, type_size);
	g_strlcpy(param, tag->value.macro.param, param_size);

	return TRUE;
}

void
service_tag_copy(struct service_tag_s *dst, struct service_tag_s *src)
{
	if (!dst || !src)
		return;

	/*copy the name */
	memset(dst->name, 0x00, LIMIT_LENGTH_TAGNAME);
	g_strlcpy(dst->name, src->name, LIMIT_LENGTH_TAGNAME);

	/*copy the value */
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
	case STVT_MACRO:
		service_tag_set_value_macro(dst, src->value.macro.type, src->value.macro.param);
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
	memset(tag, 0x00, sizeof(struct service_tag_s));
	g_free(tag);
}

gsize
service_tag_to_string(const struct service_tag_s *tag, gchar * dst, gsize dst_size)
{
	register int s;

	if (!dst)
		return 0;
	if (dst_size <= 0)
		return 0;
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
		s = sizeof(tag->value.buf);
		return g_snprintf(dst, dst_size, "%.*s", s, tag->value.buf);
	case STVT_MACRO:
		if (tag->value.macro.param && *(tag->value.macro.param))
			return g_snprintf(dst, dst_size, "${%s}", tag->value.macro.type);
		else
			return g_snprintf(dst, dst_size, "${%s.%s}", tag->value.macro.type, tag->value.macro.param);
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
	memset(si, 0x00, sizeof(struct service_info_s));
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
	const struct service_info_s *si_a, *si_b;

	if (!a && b)
		return 1;
	if (a && !b)
		return -1;
	if (a == b)
		return 0;
	si_a = a;
	si_b = b;
	return si_b->score.value - si_a->score.value;
}

gboolean
service_info_equal(const struct service_info_s * si1, const struct service_info_s * si2)
{
	gchar str_addr1[64], str_addr2[64];

	memset(str_addr1, '\0', sizeof(str_addr1));
	memset(str_addr2, '\0', sizeof(str_addr2));

	if (si1 == si2)
		return TRUE;

	if (si1 == NULL || si2 == NULL)
		return FALSE;

	if (!addr_info_equal(&(si1->addr), &(si2->addr))) {
		addr_info_to_string(&(si1->addr), str_addr1, sizeof(str_addr1));
		addr_info_to_string(&(si2->addr), str_addr2, sizeof(str_addr2));
		DEBUG("service_info addr don't match ([%s] / [%s])", str_addr1, str_addr2);
		return FALSE;
	}

	if (0 != strcmp(si1->ns_name, si2->ns_name)) {
		DEBUG("service_info ns_name don't match ([%s] / [%s])", si1->ns_name, si2->ns_name);
		return FALSE;
	}

	if (0 != strcmp(si1->type, si2->type)) {
		DEBUG("service_info type don't match ([%s] / [%s])", si1->type, si2->type);
		return FALSE;
	}

	return TRUE;
}

// for test <NS part> from a complete VNS name only
gboolean
service_info_equal_v2(const struct service_info_s * si1, const struct service_info_s * si2)
{
	const gchar *sep = NULL;

    if (si1 == si2)
       return TRUE;

    if (si1 == NULL || si2 == NULL)
       return FALSE;

	// for compare NS part from VNS name, 
	if (NULL != (sep = strchr(si2->ns_name, '.'))) {
		gboolean result = FALSE;
		struct service_info_s *si2_tmp = service_info_dup(si2);
		g_strlcpy(si2_tmp->ns_name, si2->ns_name, sep - si2->ns_name+1);
        //VNS part not used here: = g_strdup(sep+1);
		result = service_info_equal(si1, si2_tmp);
		service_info_clean(si2_tmp);
		return result;
	}

	return service_info_equal(si1, si2);
}


meta0_info_t *
service_info_convert_to_m0info(struct service_info_s * srv)
{
	if (!srv)
		return NULL;
	meta0_info_t *mi = g_malloc0(sizeof(meta0_info_t));
	memcpy(&(mi->addr), &(srv->addr), sizeof(addr_info_t));
	return mi;
}

struct service_tag_s *
service_info_get_tag(GPtrArray * a, const gchar * name)
{
	gsize len;
	register guint i, max;

	if (!a || !name || !a->len)
		return NULL;

	len = MIN(strlen(name) + 1, LIMIT_LENGTH_TAGNAME);

	for (i = 0, max = a->len; i < max; i++) {
		struct service_tag_s *pSrv;

		pSrv = g_ptr_array_index(a, i);
		if (!pSrv)
			return NULL;
		if (!g_ascii_strncasecmp(pSrv->name, name, len))
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
	gsize len;
	register guint i, max;

	if (!a || !name || a->len <= 0)
		return;

	len = MIN(strlen(name) + 1, LIMIT_LENGTH_TAGNAME);

	for (i = 0, max = a->len; i < max; i++) {
		struct service_tag_s *pSrv;

		pSrv = g_ptr_array_index(a, i);
		if (!pSrv)
			continue;
		if (!g_ascii_strncasecmp(pSrv->name, name, len)) {
			service_tag_destroy(pSrv);
			g_ptr_array_remove_index_fast(a, i);
			return;
		}
	}
}

gboolean
service_info_set_address(struct service_info_s * si, const gchar * host, int port, GError ** error)
{
	addr_info_t *addr;

	if (!si || !host || port < 0 || port > 65535) {
		GSETERROR(error, "Invalid parameter si=%p host=%p port=%i", si, host, port);
		return FALSE;
	}

	addr = build_addr_info(host, port, error);
	if (!addr) {
		GSETERROR(error, "Invalid address");
		return FALSE;
	}

	memcpy(&(si->addr), addr, sizeof(addr_info_t));

	g_free(addr);

	return TRUE;
}

GSList*
service_info_extract_nsname(GSList *services, gboolean copy)
{
	struct service_info_s *si;
	GHashTable *ht;
	GHashTableIter iter;
	GSList *l, *result;
	gpointer k, v;

	ht = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
	for (l=services; l ;l=l->next) {
		si = l->data;
		g_hash_table_insert(ht, si->ns_name, si->ns_name);
	}

	result = NULL;
	g_hash_table_iter_init(&iter, ht);
	while (g_hash_table_iter_next(&iter, &k, &v))
		result = g_slist_prepend(result, copy ? g_strndup(k, LIMIT_LENGTH_NSNAME) : k);

	g_hash_table_destroy(ht);
	return result;
}

gchar *
service_info_to_string(const service_info_t *si)
{
	guint count = 0;
	gchar **strv = NULL;

	void concat(gchar *s) {
		count = count + 1;
		strv = g_realloc(strv, (count+1) * sizeof(gchar*));
		strv[count-1] = s;
		strv[count] = NULL;
	}

	if (!si)
		return g_strdup("NULL");

	strv = g_malloc0((count+1) * sizeof(gchar*));

	/* header string */
	concat(g_strdup_printf("%s|%s", si->ns_name, si->type));
	do {
		gchar str_addr[STRLEN_ADDRINFO];
		addr_info_to_string(&(si->addr), str_addr, sizeof(str_addr));
		concat(g_strdup(str_addr));
	} while (0);
	concat(g_strdup_printf("score=%d", si->score.value));

	/* tags list */
	if (si->tags) {
		int i, max;
		struct service_tag_s *tag;
		gchar str_tag[1024];
		for (i=0, max=si->tags->len; i<max ;i++) {
			tag = g_ptr_array_index((si->tags), i);
			bzero(str_tag, sizeof(str_tag));
			service_tag_to_string(tag, str_tag, sizeof(str_tag));
			concat(g_strdup(str_tag));
		}
	}

	gchar *result = g_strjoinv("|",strv);
	g_strfreev(strv);
	return result;
}

void
service_info_swap(struct service_info_s *si0, struct service_info_s *si1)
{
	struct service_info_s tmp;
	g_assert(si0 != NULL);
	g_assert(si1 != NULL);
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

const gchar *
service_info_get_stgclass(const struct service_info_s *si, const gchar *d)
{
	return service_info_get_tag_value(si, NAME_TAGNAME_RAWX_STGCLASS, d);
}

