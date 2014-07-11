#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "stats.client.lib"
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <math.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include <gridd/plugins/msg_stats/msg_stats.h>

#include "./stats_remote.h"

static gchar *
_get_value(MESSAGE req, const gchar *name)
{
	void *ptr = NULL;
	gsize ptr_len = 0;

	if (0 >= message_get_field(req, name, strlen(name), &ptr, &ptr_len, NULL)) {
		WARN("field '%s' not found (very strange!)", name);
		return NULL;
	}

	return g_strndup(ptr, ptr_len);
}

static gboolean
field_extractor(GError **e, gpointer u, gint code, MESSAGE r)
{
	gchar **fields, **field;
	GHashTable *ht = *((GHashTable**)u);

	(void) code;

	if (!r) {
		GSETERROR(e, "invalid parameter");
		return FALSE;
	}

	if (!(fields = message_get_field_names (r, e))) {
		GSETERROR(e, "cannot get the field names in the message");
		return FALSE;
	}

	for (field=fields; *field ;field++) {
		gchar *str_val = NULL;
		gdouble val;

		if (!g_str_has_prefix(*field, MSGFIELD_STATPREFIX))
			continue;
		if (!(str_val = _get_value(r, *field)))
			continue;

		if (strchr(str_val, '.'))
			val = g_ascii_strtod (str_val, NULL);
		else {
			gint64 i64 = g_ascii_strtoll(str_val, NULL, 10);
			val = i64;
		}
		g_free(str_val);

		if (errno==ERANGE) {
			WARN("wrong stat for '%s' : overflow/underflow", *field);
			continue;
		}

		g_hash_table_insert(ht,
				g_strdup((*field) + strlen(MSGFIELD_STATPREFIX)),
				g_memdup(&val, sizeof(val)));
	}

	g_strfreev(fields);
	return TRUE;
}
	
GHashTable*
gridd_stats_remote (addr_info_t *ai, gint ms, GError **err, const gchar *pattern)
{
	MESSAGE request=NULL;
	GHashTable *ht=NULL;
	
	struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, field_extractor },
		{ 206, 0, NULL, field_extractor },
		{ 0, 0, NULL, NULL },
	};
	struct reply_sequence_data_s data = { &ht , 0 , codes };

	/*create the result hash table*/
	ht = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
	if (!ht) {
		GSETERROR(err, "cannot create a hashtable");
		return NULL;
	}

	/*create and fill the request*/
	GByteArray *gba_pattern = g_byte_array_append(g_byte_array_new(), (guint8*)pattern, strlen(pattern));
	request = message_create_request(err, NULL/*id*/, MSG_NAME, NULL /*body*/,
			MSGKEY_PATTERN, gba_pattern,
			NULL);
	g_byte_array_free(gba_pattern, TRUE);

	if (!request) {
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}

	/*run the reply sequence*/
	if (!metaXClient_reply_sequence_run_from_addrinfo(err, request, ai, ms, &data)) {
		GSETERROR(err, "Cannot execute the request and parse the answers");
		goto errorLabel;
	}

	message_destroy (request, NULL);	
	return ht;
	
errorLabel:
	if (ht)
		g_hash_table_destroy (ht);
	if (request)
		message_destroy (request, NULL);
	return NULL;
}

