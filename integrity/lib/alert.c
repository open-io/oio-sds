#include <metautils/lib/metautils.h>

#include "alert.h"

gboolean
alert(const gchar* domain, int criticity, const gchar* message)
{
	(void) criticity;
	ALERT_DOMAIN(domain, message);

	return TRUE;
}
