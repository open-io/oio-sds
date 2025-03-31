/*
OpenIO SDS core library
Copyright (C) 2025 OVH SAS

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

#ifndef OIO_SDS__core__oioerrors_h
# define OIO_SDS__core__oioerrors_h 1

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>

/** Tell if the specified error is a redirection to an unreachable service */
gboolean error_is_bad_redirect(GError *err);

/** Tell if the specified error is due to the requested service being stopped */
gboolean error_is_exiting(GError *err);

#ifdef __cplusplus
}
#endif
#endif /*OIO_SDS__core__oioerrors_h*/
