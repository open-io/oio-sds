#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "m1v2"
#endif

#include <metautils/lib/metautils.h>

#include "./compound_types.h"

void
compound_type_clean(struct compound_type_s *ct)
{
	if (!ct)
		return;
	if (ct->type)
		g_free(ct->type);
	if (ct->req.k)
		g_free(ct->req.k);
	if (ct->req.v)
		g_free(ct->req.v);
	if (ct->baretype)
		g_free(ct->baretype);
	if (ct->subtype)
		g_free(ct->subtype);
	memset(ct, 0, sizeof(*ct));
}

static void
_parse_type(struct compound_type_s *ct, gchar *s)
{
	gchar **tokens = g_strsplit(s, ".", 2);
	ct->type = s;
	ct->baretype = tokens[0];
	ct->subtype = tokens[1] ? tokens[1] : g_strdup("");
	g_free(tokens);
}

static void
_parse_args(struct compound_type_s *ct, gchar *s)
{
	if (!s)
		return;

	gchar **tokens = g_strsplit(s, "=", 2);
	ct->req.k = tokens[0];
	ct->req.v = tokens[1];
	g_free(tokens);
	g_free(s);
}

GError*
compound_type_parse(struct compound_type_s *ct, const gchar *srvtype)
{
	g_assert(ct != NULL);
	memset(ct, 0, sizeof(struct compound_type_s));

	if (!srvtype || !*srvtype || *srvtype == '.' || *srvtype == ';')
		return NEWERROR(400, "Bad service type [%s]", srvtype);

	ct->fulltype = srvtype;

	gchar **tokens = g_strsplit(srvtype, ";", 2);
	_parse_type(ct, tokens[0]);
	_parse_args(ct, tokens[1]);
	g_free(tokens);

	GRID_TRACE("CT full[%s] type[%s] bare[%s] sub[%s] args[%s|%s]",
			ct->fulltype, ct->type, ct->baretype, ct->subtype,
			ct->req.k, ct->req.v);

	return NULL;
}

void
compound_type_update_arg(struct compound_type_s *ct,
		struct service_update_policies_s *pol, gboolean override)
{
	gchar *k = NULL, *v = NULL;

	if (service_update_tagfilter(pol, ct->baretype, &k, &v)) {
		if (override || !ct->req.k) {
			metautils_str_reuse(&(ct->req.k),  k);
			metautils_str_reuse(&(ct->req.v),  v);
			k = v = NULL;
		}
	}

	if (k)
		g_free(k);
	if (v)
		g_free(v);
}

