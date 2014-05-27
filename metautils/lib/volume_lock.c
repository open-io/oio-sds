#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "lock"
#endif

#include <errno.h>
#include <sys/types.h>
#include <attr/xattr.h>

#include "metautils.h"
#include "volume_lock.h"

#define alloca_xattr(r,fmt,t) do { \
	size_t rs = strlen(fmt) + strlen(t) + 1; \
	r = g_alloca(rs); \
	g_snprintf(r, rs, fmt, t); \
} while (0)

static GError*
_check_lock(const gchar *vol, const gchar *n, const gchar *v)
{
	static gssize max_size = 256;
	gchar *buf;
	gssize bufsize, realsize;
	GError *err = NULL;

	bufsize = max_size;
	buf = g_malloc(bufsize);
retry:
	memset(buf, 0, sizeof(bufsize));
	realsize = getxattr(vol, n, buf, bufsize-1);

	if (realsize < 0) {

		if (errno != ERANGE)
			err = NEWERROR(errno, "XATTR get error: %s", strerror(errno));
		else { /* buffer too small */
			bufsize = realsize + 1;
			max_size = 1 + MAX(max_size,bufsize);
			buf = g_realloc(buf, bufsize);
			goto retry;
		}
	}

	if (!err) {
		if (strlen(v) != (gsize)realsize)
			err = NEWERROR(500, "XATTR size differ");
		else if (0 != memcmp(v,buf,realsize))
			err = NEWERROR(500, "XATTR differ");
	}

	g_free(buf);
	return err;
}

static GError*
_set_lock(const gchar *vol, const gchar *n, const gchar *v)
{
	int rc;

	rc = setxattr(vol, n, v, strlen(v), XATTR_CREATE);
	if (!rc)
		return NULL;

	return (errno == EEXIST) ? _check_lock(vol, n, v)
		: NEWERROR(errno, "XATTR set error: %s", strerror(errno));
}

GError*
volume_service_lock(const gchar *vol, const gchar *type, const gchar *id,
		const gchar *ns)
{
	GError *err;
	gchar *n, pns[256];

	if (!type || !*type)
		return NEWERROR(EINVAL, "Invalid service type");

	if (ns && *ns) {
		metautils_strlcpy_physical_ns(pns, ns, sizeof(pns));
		alloca_xattr(n, "user.%s_server.namespace", type);
		if (NULL != (err = _set_lock(vol, n, pns)))
			return err;
	}

	if (id && *id) {
		alloca_xattr(n, "user.%s_server.address", type);
		if (NULL != (err = _set_lock(vol, n, id)))
			return err;
	}

	return NULL;
}

