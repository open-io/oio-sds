#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metautils.tools"
#endif

#include <ctype.h>
#include <openssl/sha.h>

#include "metautils.h"
#include "metautils_internals.h"

static gchar b2h[][2] =
{
	{'0','0'}, {'0','1'}, {'0','2'}, {'0','3'}, {'0','4'}, {'0','5'}, {'0','6'}, {'0','7'},
	{'0','8'}, {'0','9'}, {'0','A'}, {'0','B'}, {'0','C'}, {'0','D'}, {'0','E'}, {'0','F'},
	{'1','0'}, {'1','1'}, {'1','2'}, {'1','3'}, {'1','4'}, {'1','5'}, {'1','6'}, {'1','7'},
	{'1','8'}, {'1','9'}, {'1','A'}, {'1','B'}, {'1','C'}, {'1','D'}, {'1','E'}, {'1','F'},
	{'2','0'}, {'2','1'}, {'2','2'}, {'2','3'}, {'2','4'}, {'2','5'}, {'2','6'}, {'2','7'},
	{'2','8'}, {'2','9'}, {'2','A'}, {'2','B'}, {'2','C'}, {'2','D'}, {'2','E'}, {'2','F'},
	{'3','0'}, {'3','1'}, {'3','2'}, {'3','3'}, {'3','4'}, {'3','5'}, {'3','6'}, {'3','7'},
	{'3','8'}, {'3','9'}, {'3','A'}, {'3','B'}, {'3','C'}, {'3','D'}, {'3','E'}, {'3','F'},
	{'4','0'}, {'4','1'}, {'4','2'}, {'4','3'}, {'4','4'}, {'4','5'}, {'4','6'}, {'4','7'},
	{'4','8'}, {'4','9'}, {'4','A'}, {'4','B'}, {'4','C'}, {'4','D'}, {'4','E'}, {'4','F'},
	{'5','0'}, {'5','1'}, {'5','2'}, {'5','3'}, {'5','4'}, {'5','5'}, {'5','6'}, {'5','7'},
	{'5','8'}, {'5','9'}, {'5','A'}, {'5','B'}, {'5','C'}, {'5','D'}, {'5','E'}, {'5','F'},
	{'6','0'}, {'6','1'}, {'6','2'}, {'6','3'}, {'6','4'}, {'6','5'}, {'6','6'}, {'6','7'},
	{'6','8'}, {'6','9'}, {'6','A'}, {'6','B'}, {'6','C'}, {'6','D'}, {'6','E'}, {'6','F'},
	{'7','0'}, {'7','1'}, {'7','2'}, {'7','3'}, {'7','4'}, {'7','5'}, {'7','6'}, {'7','7'},
	{'7','8'}, {'7','9'}, {'7','A'}, {'7','B'}, {'7','C'}, {'7','D'}, {'7','E'}, {'7','F'},
	{'8','0'}, {'8','1'}, {'8','2'}, {'8','3'}, {'8','4'}, {'8','5'}, {'8','6'}, {'8','7'},
	{'8','8'}, {'8','9'}, {'8','A'}, {'8','B'}, {'8','C'}, {'8','D'}, {'8','E'}, {'8','F'},
	{'9','0'}, {'9','1'}, {'9','2'}, {'9','3'}, {'9','4'}, {'9','5'}, {'9','6'}, {'9','7'},
	{'9','8'}, {'9','9'}, {'9','A'}, {'9','B'}, {'9','C'}, {'9','D'}, {'9','E'}, {'9','F'},
	{'A','0'}, {'A','1'}, {'A','2'}, {'A','3'}, {'A','4'}, {'A','5'}, {'A','6'}, {'A','7'},
	{'A','8'}, {'A','9'}, {'A','A'}, {'A','B'}, {'A','C'}, {'A','D'}, {'A','E'}, {'A','F'},
	{'B','0'}, {'B','1'}, {'B','2'}, {'B','3'}, {'B','4'}, {'B','5'}, {'B','6'}, {'B','7'},
	{'B','8'}, {'B','9'}, {'B','A'}, {'B','B'}, {'B','C'}, {'B','D'}, {'B','E'}, {'B','F'},
	{'C','0'}, {'C','1'}, {'C','2'}, {'C','3'}, {'C','4'}, {'C','5'}, {'C','6'}, {'C','7'},
	{'C','8'}, {'C','9'}, {'C','A'}, {'C','B'}, {'C','C'}, {'C','D'}, {'C','E'}, {'C','F'},
	{'D','0'}, {'D','1'}, {'D','2'}, {'D','3'}, {'D','4'}, {'D','5'}, {'D','6'}, {'D','7'},
	{'D','8'}, {'D','9'}, {'D','A'}, {'D','B'}, {'D','C'}, {'D','D'}, {'D','E'}, {'D','F'},
	{'E','0'}, {'E','1'}, {'E','2'}, {'E','3'}, {'E','4'}, {'E','5'}, {'E','6'}, {'E','7'},
	{'E','8'}, {'E','9'}, {'E','A'}, {'E','B'}, {'E','C'}, {'E','D'}, {'E','E'}, {'E','F'},
	{'F','0'}, {'F','1'}, {'F','2'}, {'F','3'}, {'F','4'}, {'F','5'}, {'F','6'}, {'F','7'},
	{'F','8'}, {'F','9'}, {'F','A'}, {'F','B'}, {'F','C'}, {'F','D'}, {'F','E'}, {'F','F'}
};

static gchar hexa[] =
{
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

/* ------------------------------------------------------------------------- */

static gsize
_buffer2str(const guint8 *s, size_t sS, char *d, size_t dS)
{
	gsize i, j;

	if (!s || !sS || !d || !dS)
		return 0;

	for (i=j=0; i<sS && j<(dS-1) ;i++) {
		register const gchar *h = b2h[((guint8*)s)[i]];
		d[j++] = h[0];
		d[j++] = h[1];
	}

	d[(j<dS ? j : dS-1)] = 0;

	return j;
}

void
buffer2str(const void *s, size_t sS, char *d, size_t dS)
{
	(void) _buffer2str(s, sS, d, dS);
}

gsize
container_id_to_string(const container_id_t id, gchar * dst, gsize dstsize)
{
	return _buffer2str(id, sizeof(container_id_t), dst, dstsize);
}

void
name_to_id(const gchar * name, gsize nameLen, hash_sha256_t * id)
{
	SHA256((unsigned char *) name, nameLen, (unsigned char *) id);
}

void
name_to_id_v2(const gchar * name, gsize nameLen, const gchar *vns, hash_sha256_t * id)
{
	if (!vns || !strchr(vns,'.')) {
		/* old school client */
		name_to_id(name, nameLen, id);
		return;
	}

	gchar *full_name = g_strconcat(vns, "/", name, NULL);

	SHA256((unsigned char *) full_name, strlen(full_name), (unsigned char *) id);

	if(full_name)
		g_free(full_name);
}

void
meta1_name2hash(container_id_t cid, const gchar *ns, const gchar *cname)
{
	gsize s;
	GChecksum *sum = NULL;

	sum = g_checksum_new(G_CHECKSUM_SHA256);

	if (ns && strchr(ns, '.')) {
		g_checksum_update(sum, (guint8*)ns, strlen(ns));
		g_checksum_update(sum, (guint8*)"/", 1);
	}
	if (cname)
		g_checksum_update(sum, (guint8*)cname, strlen(cname));

	memset(cid, 0, sizeof(container_id_t));
	s = sizeof(container_id_t);
	g_checksum_get_digest(sum, (guint8*)cid, &s);
	g_checksum_free(sum);
}


static gboolean
_hex2bin(const guint8 *s, gsize sS, guint8 *d, register gsize dS, GError** error)
{
	if (!s || !d) {
		GSETERROR(error, "src or dst is null");
		return FALSE;
	}

	if (sS < dS * 2) {
		GSETERROR(error, "hexadecimal form too short");
		return FALSE;
	}

	while ((dS--) > 0) {
		register int i0, i1;

		i0 = hexa[*(s++)];
		i1 = hexa[*(s++)];

		if (i0<0 || i1<0) {
			GSETERROR(error, "Invalid hex");
			return FALSE;
		}

		*(d++) = (i0 & 0x0F) << 4 | (i1 & 0x0F);
	}

	return TRUE;
}

gboolean
hex2bin(const gchar *s, void *d, gsize dS, GError** error)
{
	return _hex2bin((guint8*)s, (s?strlen(s):0), (guint8*)d, dS, error);
}

gboolean
container_id_hex2bin(const gchar *s, gsize sS, container_id_t *d,
		GError ** error)
{
	return _hex2bin((guint8*)s, sS, (guint8*)d, 32, error);
}

guint
container_id_hash(gconstpointer k)
{
	const guint *b;
	guint max, i, h;

	if (!k)
		return 0;
	b = k;
	max = sizeof(container_id_t) / sizeof(guint);
	h = 0;
	for (i = 0; i < max; i++)
		h = h ^ b[i];
	return h;
}

gboolean
container_id_equal(gconstpointer k1, gconstpointer k2)
{
	return k1 && k2 && ((k1 == k2)
	    || (0 == memcmp(k1, k2, sizeof(container_id_t))));
}

void
g_free1(gpointer p1, gpointer p2)
{
	(void) p2;
	if (p1)
		g_free(p1);
}

void
g_free2(gpointer p1, gpointer p2)
{
	(void) p1;
	if (p2)
		g_free(p2);
}

/* ----------------------------------------------------------------------------------- */

gboolean
convert_chunk_text_to_raw(const struct chunk_textinfo_s* text_chunk, struct meta2_raw_chunk_s* raw_chunk, GError** error)
{
	if (text_chunk == NULL) {
		GSETERROR(error, "text_chunk is null");
		return FALSE;
	}

	memset(raw_chunk, 0, sizeof(struct meta2_raw_chunk_s));

	if (text_chunk->id != NULL
		&& !hex2bin(text_chunk->id, &(raw_chunk->id.id), sizeof(hash_sha256_t), error)) {
			GSETERROR(error, "Failed to convert chunk id from hex to bin");
			return FALSE;
	}

	if (text_chunk->hash != NULL
		&& !hex2bin(text_chunk->hash, &(raw_chunk->hash), sizeof(chunk_hash_t), error)) {
			GSETERROR(error, "Failed to convert chunk hash from hex to bin");
			return FALSE;
	}

	if (text_chunk->size != NULL)
		raw_chunk->size = g_ascii_strtoll(text_chunk->size, NULL, 10);

	if (text_chunk->position != NULL)
		raw_chunk->position = g_ascii_strtoull(text_chunk->position, NULL, 10);

	if (text_chunk->metadata != NULL)
		raw_chunk->metadata = metautils_gba_from_string(text_chunk->metadata);

	return TRUE;
}

static gboolean
_chunk_hash_is_null(const chunk_hash_t chunk_hash)
{
	return data_is_zeroed(chunk_hash, sizeof(chunk_hash_t));
}

static gboolean
_chunk_id_is_null(const chunk_id_t *chunk_id)
{
	return data_is_zeroed(chunk_id, sizeof(chunk_id_t));
}

static gboolean
_container_id_is_null(const container_id_t container_id)
{
	return data_is_zeroed(container_id, sizeof(container_id_t));
}

gboolean
convert_chunk_raw_to_text(const struct meta2_raw_content_s* raw_content, struct chunk_textinfo_s* text_chunk, GError** error)
{
	gchar buffer[2048];
	struct meta2_raw_chunk_s* raw_chunk = NULL;

	if (raw_content == NULL) {
		GSETERROR(error, "raw_content is null");
		return FALSE;
	}

	if (raw_content->raw_chunks == NULL) {
		GSETERROR(error, "raw_chunk list in content is null");
		return FALSE;
	}

	if (g_slist_length(raw_content->raw_chunks) == 0) {
		GSETERROR(error, "raw_chunk list in content is empty");
		return FALSE;
	}

	if (g_slist_length(raw_content->raw_chunks) > 1) {
		GSETERROR(error, "raw_chunk list in content contains more than a chunk, can't choose which one to use");
		return FALSE;
	}

	raw_chunk = g_slist_nth_data(raw_content->raw_chunks, 0);

	memset(text_chunk, 0, sizeof(struct chunk_textinfo_s));

	if (!_chunk_id_is_null( &(raw_chunk->id) )) {
		memset(buffer, '\0', sizeof(buffer));
		chunk_id_to_string(&(raw_chunk->id), buffer, sizeof(buffer));
		text_chunk->id = g_strdup(buffer);
	}

	if (strlen(raw_content->path) > 0)
		text_chunk->path = g_strdup(raw_content->path);

	text_chunk->size = g_strdup_printf("%"G_GINT64_FORMAT, raw_chunk->size);
	text_chunk->position = g_strdup_printf("%"G_GUINT32_FORMAT, raw_chunk->position);

	if (!_chunk_hash_is_null(raw_chunk->hash)) {
		memset(buffer, '\0', sizeof(buffer));
		buffer2str(raw_chunk->hash, sizeof(chunk_hash_t), buffer, sizeof(buffer));
		text_chunk->hash = g_strdup(buffer);
	}

	if (raw_chunk->metadata != NULL)
		text_chunk->metadata = g_strndup((gchar*)raw_chunk->metadata->data, raw_chunk->metadata->len);

	if (!_container_id_is_null( raw_content->container_id)) {
		memset(buffer, '\0', sizeof(buffer));
		container_id_to_string(raw_content->container_id, buffer, sizeof(buffer));
		text_chunk->container_id = g_strdup(buffer);
	}

	return TRUE;
}

gchar*
key_value_pair_to_string(key_value_pair_t * kv)
{
        gchar *str_value = NULL, *result = NULL;
        gsize str_value_len;

        if (!kv)
                return g_strdup("KeyValue|NULL|NULL");

        if (!kv->value)
                return g_strconcat("KeyValue|",(kv->key?kv->key:"NULL"),"|NULL", NULL);

        str_value_len = 8 + 3 * kv->value->len;
        str_value = g_malloc0(str_value_len);
        metautils_gba_data_to_string(kv->value, str_value, str_value_len);

        result = g_strconcat("KeyValue|",(kv->key?kv->key:"NULL"), "|", str_value, NULL);
        g_free(str_value);

        return result;
}

struct meta1_service_url_s*
meta1_unpack_url(const gchar *url)
{
	gchar *type = NULL, *host = NULL, *args = NULL;

	EXTRA_ASSERT(url != NULL);

	int len = strlen(url);
	gchar *tmp = g_alloca(len+1);
	g_strlcpy(tmp, url, len+1);

	if (!(type = strchr(tmp, '|')))
		return NULL;
	*(type++) = '\0';

	if (!(host = strchr(type, '|')))
		return NULL;
	*(host++) = '\0';

	if (!(args = strchr(host, '|')))
		return NULL;
	*(args++) = '\0';

	struct meta1_service_url_s *result;
	result = g_malloc0(sizeof(*result) + strlen(args) + 1);
	result->seq = g_ascii_strtoll(url, NULL, 10);
	g_strlcpy(result->srvtype, type, sizeof(result->srvtype));
	g_strlcpy(result->host, host, sizeof(result->host));
	strcpy(result->args, args);

	return result;
}

void
meta1_service_url_clean(struct meta1_service_url_s *u)
{
	if (u) {
		u->seq = 0;
		u->srvtype[0] = u->host[0] = u->args[0] = 0;
		g_free(u);
	}
}

void
meta1_service_url_vclean(struct meta1_service_url_s **uv)
{
	struct meta1_service_url_s **p;

	if (!uv)
		return;
	for (p=uv; *p ;p++)
		meta1_service_url_clean(*p);
	g_free(uv);
}

gchar*
meta1_pack_url(struct meta1_service_url_s *u)
{
	return (NULL == u) ? NULL : g_strdup_printf(
			"%"G_GINT64_FORMAT"|%s|%s|%s",
			u->seq, u->srvtype, u->host, u->args);
}

gboolean
meta1_url_get_address(struct meta1_service_url_s *u,
		struct addr_info_s *dst)
{
	return l4_address_init_with_url(dst, u->host, NULL);
}

gboolean
meta1_strurl_get_address(const gchar *str, struct addr_info_s *dst)
{
	gboolean rc;
	struct meta1_service_url_s *u;

	u = meta1_unpack_url(str);
	rc = meta1_url_get_address(u, dst);
	g_free(u);

	return rc;
}

gsize
metautils_strlcpy_physical_ns(gchar *d, const gchar *s, gsize dlen)
{
    register gsize count = 0;

	if (dlen > 0) {
		-- dlen; // Keep one place for the trailing '\0'
	    for (; count<dlen && *s && *s != '.' ;count++)
			*(d++) = *(s++);
		if (dlen)
			*d = '\0';
	}

    for (; *s && *s != '.' ;count++,s++) { }
    return count;
}

void
metautils_randomize_buffer(guint8 *buf, gsize buflen)
{
	union {
		guint32 r32;
		guint8 r8[4];
	} raw;
	GRand *r = g_rand_new();

	if (NULL == buf || 0 == buflen)
		return;

	// Fill 4 by 4
	gsize mod32 = buflen % 4;
	gsize max32 = buflen / 4;
	for (register gsize i32=0; i32 < max32 ; ++i32) {
		raw.r32 = g_rand_int(r);
		((guint32*)buf)[i32] = raw.r32;
	}

	// Finish with the potentially remaining unset bytes
	raw.r32 = g_rand_int(r);
	switch (mod32) {
		case 3:
			buf[ (max32*4) + 2 ] = raw.r8[2];
		case 2:
			buf[ (max32*4) + 1 ] = raw.r8[1];
		case 1:
			buf[ (max32*4) + 0 ] = raw.r8[0];
	}

	g_rand_free(r);
}

