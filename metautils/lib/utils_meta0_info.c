/*
OpenIO SDS metautils
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

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

#include <errno.h>

#include "metautils.h"

void
meta0_info_clean(meta0_info_t *m0)
{
	if (!m0) {
		errno = EINVAL;
		return;
	}
	if (m0->prefixes) {
		g_free(m0->prefixes);
		m0->prefixes = NULL;
	}
	g_free(m0);
}

void
meta0_info_gclean(gpointer d, gpointer u)
{
	(void) u;
	meta0_info_clean(d);
}

