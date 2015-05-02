#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metautils"
#endif

#include "metautils.h"
#include "url.h"
#include <glib.h>

gboolean
metautils_requri_parse (const char *str, struct req_uri_s *uri)
{
	EXTRA_ASSERT(str != NULL);
	EXTRA_ASSERT(uri != NULL);

	gchar *pq = strchr (str, '?');
	gchar *pa = pq ? strchr (pq, '#') : strchr (str, '#');

	// Extract the main components
	if (pq || pa)
		uri->path = g_strndup (str, (pq ? pq : pa) - str);
	else
		uri->path = g_strdup (str);

	if (pq) {
		if (pa)
			uri->query = g_strndup (pq + 1, pa - pq);
		else
			uri->query = g_strdup (pq + 1);
	} else
		uri->query = g_strdup("");

	if (pa)
		uri->fragment = g_strdup (pa + 1);
	else
		uri->fragment = g_strdup("");

	// Split compound components of interest
	if (uri->query)
		uri->query_tokens = g_strsplit(uri->query, "&", -1);
	else
		uri->query_tokens = g_malloc0(sizeof(void*));

	return TRUE;
}

void
metautils_requri_clear (struct req_uri_s *uri)
{
	metautils_str_clean (&uri->path);
	metautils_str_clean (&uri->query);
	metautils_str_clean (&uri->fragment);
	g_strfreev(uri->query_tokens);
}

