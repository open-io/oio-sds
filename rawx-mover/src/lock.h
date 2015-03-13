/*
OpenIO SDS rawx-mover
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

#ifndef OIO_SDS__rawx_mover__src__lock_h
# define OIO_SDS__rawx_mover__src__lock_h 1

// TODO FIXME should be removed and replaced by volume_service_lock() from metautils
#ifndef GS_CRAWLER_LOCK__H
# define GS_CRAWLER_LOCK__H 1
# include <glib/gtypes.h>

int volume_lock_get(const gchar *path, const gchar *xattr_name);

void volume_lock_release(const gchar *path, const gchar *xattr_name);

int volume_lock_set(const gchar *path, const gchar *xattr_name);

#endif /* GS_CRAWLER_LOCK__H */

#endif /*OIO_SDS__rawx_mover__src__lock_h*/