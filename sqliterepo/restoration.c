#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "sqliterepo.restore"
#endif

#include <errno.h>
#include <glib.h>

#include <metautils/lib/metautils.h>
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
