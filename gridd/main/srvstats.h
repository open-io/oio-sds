#ifndef __SRV_STATISTICS_H__
# define __SRV_STATISTICS_H__

#include <glib.h>

typedef void (*srvstat_iterator_gvariant_f) (gpointer u, const gchar *name, GVariant *gv);

/*!
 * @deprecated
 * @see srvstat_set_double()
 * @see srvstat_set_gvariant()
 */
gboolean srvstat_set (const gchar *name, gdouble value);

gboolean srvstat_set_double (const gchar *name, gdouble value);

gboolean srvstat_set_int (const gchar *name, gint value);

gboolean srvstat_set_long (const gchar *name, glong value);

gboolean srvstat_set_u64 (const gchar *name, guint64 value);

gboolean srvstat_set_i64 (const gchar *name, gint64 value);

gboolean srvstat_set_bool (const gchar *name, gboolean value);

gboolean srvstat_set_string (const gchar *name, const gchar* value);

gboolean srvstat_set_gvariant(const gchar *name, GVariant* gv);

/*!
 * @deprecated
 * @see srvstat_get_double()
 * @see srvstat_get_gvariant()
 */
gboolean srvstat_get (const gchar *name, gdouble *value);

gboolean srvstat_get_double (const gchar *name, gdouble *value);

gboolean srvstat_get_i64 (const gchar *name, gint64 *value);

gboolean srvstat_get_bool (const gchar *name, gboolean *value);

gboolean srvstat_get_string (const gchar *name, gchar **value);

GVariant* srvstat_get_gvariant (const gchar *name);


void srvstat_del (const gchar *name);

void srvstat_init (void);

void srvstat_fini (void);

void srvstat_flush (void);

void srvstat_foreach_gvariant (const gchar *pattern, srvstat_iterator_gvariant_f cb, void *udata);

#endif /*__SRV_STATISTICS_H__*/
