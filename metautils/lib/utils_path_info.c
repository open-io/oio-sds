/*
OpenIO SDS metautils
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "metautils.path_info"
#endif

#include "metautils.h"

void
path_info_gclean(gpointer d, gpointer u)
{
	(void) u;
	if (d)
		path_info_clean((path_info_t *) d);
}

void
path_info_clean(path_info_t * pi)
{
	if (!pi)
		return;

	if (pi->system_metadata)
		g_byte_array_free(pi->system_metadata, TRUE);
	if (pi->user_metadata)
		g_byte_array_free(pi->user_metadata, TRUE);

	if (pi->version)
		g_free(pi->version);

	pi->version = NULL;
	pi->system_metadata = NULL;
	pi->user_metadata = NULL;
	g_free(pi);
}
