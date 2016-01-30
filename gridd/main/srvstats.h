/*
OpenIO SDS gridd
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef OIO_SDS__gridd__main__srvstats_h
# define OIO_SDS__gridd__main__srvstats_h 1

#include <glib.h>

typedef void (*srvstat_iterator_gvariant_f) (gpointer u, const gchar *name, GVariant *gv);

/*!
 * @deprecated
 * @see srvstat_set_double()
 * @see srvstat_set_gvariant()
 */
gboolean srvstat_set (const gchar *name, gdouble value);

gboolean srvstat_set_double (const gchar *name, gdouble value);

gboolean srvstat_set_u64 (const gchar *name, guint64 value);

gboolean srvstat_set_gvariant(const gchar *name, GVariant* gv);

/*!
 * @deprecated
 * @see srvstat_get_double()
 * @see srvstat_get_gvariant()
 */
gboolean srvstat_get (const gchar *name, gdouble *value);

gboolean srvstat_get_double (const gchar *name, gdouble *value);

GVariant* srvstat_get_gvariant (const gchar *name);

void srvstat_del (const gchar *name);

void srvstat_init (void);

void srvstat_fini (void);

void srvstat_flush (void);

void srvstat_foreach_gvariant (const gchar *pattern, srvstat_iterator_gvariant_f cb, void *udata);

#endif /*OIO_SDS__gridd__main__srvstats_h*/
