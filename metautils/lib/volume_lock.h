#ifndef HC__METAUTILS_VOL_SRVLOCK__H
# define HC__METAUTILS_VOL_SRVLOCK__H 1
# include <glib.h>

GError* volume_service_lock(const gchar *vol, const gchar *type,
		const gchar *id, const gchar *ns);

#endif /* HC__METAUTILS_VOL_SRVLOCK__H */
