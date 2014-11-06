#ifndef RC_SVCMONITOR_utils_h
#define RC_SVCMONITOR_utils_h 1

/** @file Extension to the gridinit-utils library.
 * Not destined to be installed.
 */

// Used in rawx-monitor and svc-monitor
static inline void
supervisor_preserve_env (const gchar *child)
{
	gchar **keys = g_listenv();
	if (!keys)
		return;
	for (gchar **pk = keys; *pk ;++pk)
		supervisor_children_setenv(child, *pk, g_getenv(*pk));
	g_strfreev(keys);
}

#endif // RC_SVCMONITOR_utils_h
