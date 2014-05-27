#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "metautils"
#endif

#include "metautils.h"


char *
storage_policy_from_mdsys_str(const char *mdsys)
{
	if(NULL != mdsys) {
		GError *e = NULL;
		GHashTable *unpacked = metadata_unpack_string(mdsys, &e);
		if(!e) {
			char *pol = g_hash_table_lookup(unpacked, "storage-policy");
			GRID_TRACE2("pol from md table : %s", pol);
			if(NULL != pol)
				pol = g_strdup(pol);
			g_hash_table_destroy(unpacked);
			return pol;
		}
		GRID_WARN("Failed to unpack mdsys send by client : %s", e->message);
		g_clear_error(&e);
	}

	return NULL;
}

GError *
storage_policy_from_metadata(GByteArray *sys_metadata, gchar **storage_policy)
{
	/* sanity check */
	if(!sys_metadata || !sys_metadata->data || !storage_policy)
		return NEWERROR(500, "Invalid parameter");

	gchar buf[sys_metadata->len +1];
	gchar **metadata_tokens = NULL;
	GError *result = NULL;
	guint i = 0;

	bzero(buf, sizeof(buf));
	memcpy(buf, sys_metadata->data, sys_metadata->len);

	metadata_tokens = g_strsplit(buf, ";", 0);

	for(i = 0; i < g_strv_length(metadata_tokens); i++) {
		if(!g_str_has_prefix(metadata_tokens[i], "storage-policy"))
			continue;
		gchar *p = strchr(metadata_tokens[i], '=');
		if(p) {
			*storage_policy = g_strdup(p + 1);
		} else {
			result = NEWERROR(500,
					"Failed to extract policy from metadata tokens: [%s]",
					metadata_tokens[i]);
		}
		break;
	}

	if(metadata_tokens)
		g_strfreev(metadata_tokens);

	return result;
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

