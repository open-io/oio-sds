#ifndef RC_metautils_storage_policy_internals__h
# define RC_metautils_storage_policy_internals__h 1

#include <glib.h>

#include "storage_policy.h"

struct data_security_s
{
	gchar *name;
	enum data_security_e type;
	GHashTable *params;
};

struct data_treatments_s
{
	gchar *name;
	enum data_treatments_e type;
	GHashTable *params;
};

struct storage_class_s
{
	gchar *name;
	GSList *fallbacks;
};

struct storage_policy_s
{
	gchar *name;
	struct data_security_s *datasec;
	struct data_treatments_s *datatreat;
	struct storage_class_s *stgclass;
};

#endif
