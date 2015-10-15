/*
OpenIO SDS metautils
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

#include "metautils.h"

gsize
container_id_to_string(const container_id_t id, gchar * dst, gsize dstsize)
{
	return oio_str_bin2hex(id, sizeof(container_id_t), dst, dstsize);
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

void g_free0(gpointer p) { if (p) g_free(p); }
void g_free1(gpointer p1, gpointer p2) { (void) p2; g_free0(p1); }
void g_free2(gpointer p1, gpointer p2) { (void) p1; g_free0(p2); }

/* ----------------------------------------------------------------------------------- */

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

