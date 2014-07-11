#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.meta1"
#endif

#include "./internals.h"
#include "./meta1_remote.h"

MESSAGE
meta1_create_message(const gchar *reqname, const container_id_t cid, GError **err)
{
	MESSAGE result = NULL;

	g_assert(reqname != NULL);
	g_assert(cid != NULL);

	if (!message_create(&result, err)) {
		GSETERROR(err, "Memory allocation failure");
		return NULL;
	}

	if (!message_set_NAME(result, reqname, strlen(reqname), err)) {
		message_destroy(result, NULL);
		GSETERROR(err, "Memory allocation failure");
		return NULL;
	}

	if (!message_add_field(result, NAME_MSGKEY_CONTAINERID, sizeof(NAME_MSGKEY_CONTAINERID)-1,
				cid, sizeof(container_id_t), err)) {
		message_destroy(result, NULL);
		GSETERROR(err, "Failed to add container ID in header '%s'", NAME_MSGKEY_CONTAINERID);
		return NULL;
	}

	return result;
}

gboolean
meta1_enheader_addr_list(MESSAGE req, const gchar *fname, GSList *addr, GError **err)
{
	gint rc;
	GByteArray *encoded;

	g_assert(req != NULL);
	g_assert(fname != NULL);
	g_assert(addr != NULL);

	if (!(encoded = addr_info_marshall_gba(addr, err))) {
		GSETERROR(err, "Encode error");
		return FALSE;
	}
	
	rc = message_add_field(req, fname, strlen(fname), encoded->data, encoded->len, err);
	g_byte_array_free(encoded, TRUE);

	if (rc > 0)
		return TRUE;
	GSETERROR(err, "Failed to set field '%s'", fname);
	return FALSE;
}

