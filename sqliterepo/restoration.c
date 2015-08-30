/*
OpenIO SDS sqliterepo
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

#include <errno.h>
#include <unistd.h>

#include <glib.h>

#include <metautils/metautils.h>
#include "restoration.h"

GError*
restore_ctx_create(const gchar *path_pattern, struct restore_ctx_s **ctx)
{
	EXTRA_ASSERT(ctx != NULL);

	struct restore_ctx_s *res = NULL;
	res = g_malloc(sizeof(struct restore_ctx_s) + strlen(path_pattern) + 1);
	g_stpcpy(res->path, path_pattern);
	res->fd = g_mkstemp(res->path);
	if (res->fd < 0) {
		g_free(res);
		return NEWERROR(errno, "mkstemp: %s", strerror(errno));
	}
	*ctx = res;
	return NULL;
}

void
restore_ctx_clear(struct restore_ctx_s **ctx)
{
	if (!ctx || !*ctx)
		return;
	if ((*ctx)->fd >= 0) {
		metautils_pclose(&((*ctx)->fd));
		(*ctx)->fd = -1;
	}
	unlink((*ctx)->path);
	g_free(*ctx);
	*ctx = NULL;
}

GError*
restore_ctx_append(struct restore_ctx_s *ctx, guint8 *raw, gsize rawsize)
{
	for (gsize wtotal = 0; wtotal < rawsize; ) {
		gssize w = write(ctx->fd, raw + wtotal, rawsize - wtotal);
		if (w < 0) {
			return NEWERROR(errno, "write: %s", strerror(errno));
		}
		wtotal += w;
	}
	return NULL;
}
