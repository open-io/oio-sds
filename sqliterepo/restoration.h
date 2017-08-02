/*
OpenIO SDS sqliterepo
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

#ifndef OIO_SDS__sqliterepo__restoration_h
# define OIO_SDS__sqliterepo__restoration_h 1

#include <glib.h>

struct restore_ctx_s
{
	int fd;
	gchar path[];
};

GError *restore_ctx_create(const gchar *path_pattern, struct restore_ctx_s **ctx);
void restore_ctx_clear(struct restore_ctx_s **ctx);
GError *restore_ctx_append(struct restore_ctx_s *ctx, guint8 *raw, gsize rawsize);

#endif /*OIO_SDS__sqliterepo__restoration_h*/