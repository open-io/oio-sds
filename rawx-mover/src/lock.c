// TODO FIXME should be removed and replaced by volume_service_lock() from metautils
#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "rawx.lock"
#endif

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <attr/xattr.h>

#include <metautils/lib/metautils.h>

#include "lock.h"

int
volume_lock_get(const gchar *path, const gchar *xattr_name)
{
	gint64 i64_pid_found;
	int rc, pid;
	char str_pid[16], str_pid_found[16];

	bzero(str_pid, sizeof(str_pid));
	bzero(str_pid_found, sizeof(str_pid_found));
	g_snprintf(str_pid, sizeof(str_pid), "%d", getpid());

	if (0 == setxattr(path, xattr_name, str_pid, strlen(str_pid), XATTR_CREATE)) {
		NOTICE("Volume lock set for pid=%d", getpid());
		return getpid();
	}

	if (errno == EEXIST) {

		rc = getxattr(path, xattr_name, str_pid_found, sizeof(str_pid_found)-1);
		if (rc == -1)
			return -1;

		i64_pid_found = g_ascii_strtoll(str_pid_found, NULL, 10);
		pid = i64_pid_found;
		return pid;
	}

	WARN("Volume lock error : %s", strerror(errno));
	return -1;
}

void
volume_lock_release(const gchar *path, const gchar *xattr_name)
{
	if (-1 == removexattr(path, xattr_name)) {
		WARN("Volume lock not removed : %s", strerror(errno));
		return;	
	}
	NOTICE("Volume lock released");
}

int 
volume_lock_set(const gchar *path, const gchar *xattr_name)
{
	pid_t pid_lock;
	guint lock_attempts = 3;
retry:
	pid_lock = volume_lock_get(path, xattr_name);
	if (pid_lock < 0) {
		WARN("Lock error : cannot be set");
		return 0;
	}
	if (pid_lock != getpid()) {
		if (pid_lock > 0 && 0 != kill(pid_lock, 0)) {
			NOTICE("Volume locked by dead pid=%d", pid_lock);
			if (!--lock_attempts)
				ERROR("Lock error : Too many lock attempts");
			else if (0 == removexattr(path, xattr_name)) {
				INFO("Retrying the volume lock");
				goto retry;
			}
		}
		else
			WARN("Lock error : owned by pid=%d", pid_lock);
		return 0;
	}

	return 1;
}

