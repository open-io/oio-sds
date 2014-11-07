#ifndef __SQLITEREPO_RESTORATION_H
#define __SQLITEREPO_RESTORATION_H 1

#include <glib.h>

struct restore_ctx_s
{
	int fd;
	gchar path[];
};

GError *restore_ctx_create(const gchar *path_pattern, struct restore_ctx_s **ctx);
void restore_ctx_clear(struct restore_ctx_s **ctx);
GError *restore_ctx_append(struct restore_ctx_s *ctx, guint8 *raw, gsize rawsize);


#endif
