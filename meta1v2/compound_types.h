#ifndef HC_compound_type__H
#define HC_compound_type__H 1
#include <glib.h>

struct service_update_policies_s;

struct compound_type_s
{
	const gchar *fulltype;
	gchar *baretype;
	gchar *subtype;
	gchar *type; // baretype . subtype

	struct { // <key,value> to be matched
		gchar *k;
		gchar *v;
	} req;
};

// Calls g_free on each non NULL field of the structure.
void compound_type_clean(struct compound_type_s *ct);

// Parses the configuration string.
// In case of error, the fields of CT are cleaned.
// Before starting to work, the structure is blanked (i.e. not cleaned
// with compound_type_clean().
// format: TYPE[.SUBTYPE][;ARGS]
GError* compound_type_parse(struct compound_type_s *ct, const gchar *srvtype);

// Updates the 'arg' field of 'ct' with the help of
// the information hold in the service_update policy.
void compound_type_update_arg(struct compound_type_s *ct,
		struct service_update_policies_s *pol, gboolean override);

#endif // HC_compound_type__H
