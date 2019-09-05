/*
OpenIO SDS metautils
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#ifndef OIO_SDS__metautils__lib__volume_lock_h
# define OIO_SDS__metautils__lib__volume_lock_h 1

# include <glib.h>

/**
 * Lock a volume by setting some extended attributes.
 * If `autoset` is true, set the attributes if they are not found.
 * If not, just check their presence and return an error is they are missing.
 * In both cases, it returns an error if any attribute differs.
 */
GError* volume_service_lock(const char *vol, const char *type,
		const char *id, const char *ns, const gboolean autoset);

#endif /*OIO_SDS__metautils__lib__volume_lock_h*/
