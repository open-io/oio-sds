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

#include <core/oioerrors.h>

#include "internals.h"

gboolean
error_is_bad_redirect(GError *err)
{
	return err && err->code == CODE_FAILED_REDIRECT;
}

gboolean
error_is_exiting(GError *err)
{
	// Some modules prefix the error message (e.g. "cache error: ")
	return err && err->code == CODE_UNAVAILABLE
			&& g_str_has_suffix(err->message, "service exiting");
}
