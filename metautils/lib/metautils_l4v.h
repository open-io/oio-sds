/*
OpenIO SDS metautils
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2016 OpenIO SAS, as part of OpenIO SDS

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

#ifndef OIO_SDS__metautils__lib__metautils_l4v_h
# define OIO_SDS__metautils__lib__metautils_l4v_h 1

#include <glib/gtypes.h>

/**
 * Reads a whole L4V enclosed buffer from the file descriptor fd.
 *
 * @param fd an opened an connected file descriptor.
 * @param ms1 the maximal time spent to wait the header of the data
 *        (the size on 4 bytes)
 * @param msAll the maximal time spent to wait the body of the data
 * @param err an error structure set in case of error
 *
 * @return the data read under the form of a GLib byte Array
 */
GByteArray *l4v_read_2to(int fd, gint ms1, gint msAll, GError ** err);

#endif /*OIO_SDS__metautils__lib__metautils_l4v_h*/
