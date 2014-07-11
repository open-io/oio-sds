#include "./gs_internals.h"

#define _SNAPSHOT_FUNC_HEAD \
	GError *err = NULL; \
	gs_error_t *gserr = NULL; \
\
	char target[64]; \
	bzero(target, sizeof(target)); \
	addr_info_to_string(&(container->meta2_addr), target, 64); \
\
	struct hc_url_s *url = hc_url_empty(); \
	hc_url_set(url, HCURL_NS, gs_get_full_vns(container->info.gs)); \
	hc_url_set(url, HCURL_REFERENCE, C0_NAME(container)); \


#define _SNAPSHOT_FUNC_TAIL(ERR_MSG) \
	if (err != NULL) { \
		GSERRORCAUSE(&gserr, err, (ERR_MSG), \
				snapshot_name, C0_NAME(container)); \
		g_clear_error(&err); \
	} \
\
	hc_url_clean(url); \
	return gserr; \


struct redc_snapshot_s {
	char name[GS_SNAPSHOT_MAXLENGTH];
	gint64 version;
};

redc_snapshot_t* redc_snapshot_new(void);
void redc_snapshot_clean(redc_snapshot_t *snapshot);


void
redc_snapshot_clean(redc_snapshot_t *snapshot)
{
	g_free(snapshot);
}

void
redc_snapshot_array_clean(redc_snapshot_t **snapshots)
{
	if (snapshots == NULL)
		return;
	redc_snapshot_t **snapshots2 = snapshots;
	while (*snapshots != NULL) {
		redc_snapshot_clean(*snapshots);
		*snapshots = NULL;
		snapshots++;
	}
	g_free(snapshots2);
}

redc_snapshot_t*
redc_snapshot_new(void)
{
	return g_malloc0(sizeof(redc_snapshot_t));
}

const char*
redc_snapshot_get_name(redc_snapshot_t *snapshot)
{
	if (snapshot == NULL)
		return NULL;
	return snapshot->name;
}

gs_error_t*
redc_take_snapshot(gs_container_t *container, const char *snapshot_name)
{
	_SNAPSHOT_FUNC_HEAD;

	hc_url_set(url, HCURL_SNAPSHOT, snapshot_name);
	err = m2v2_remote_execute_SNAP_TAKE(target, NULL, url);

	_SNAPSHOT_FUNC_TAIL("Failed to take snapshot '%s' of container '%s': ");
}

gs_error_t*
redc_delete_snapshot(gs_container_t *container, const char *snapshot_name)
{
	_SNAPSHOT_FUNC_HEAD;

	hc_url_set(url, HCURL_SNAPSHOT, snapshot_name);
	err = m2v2_remote_execute_SNAP_DELETE(target, NULL, url);

	_SNAPSHOT_FUNC_TAIL("Failed to delete snapshot '%s' of container '%s': ");
}

gs_error_t*
redc_restore_snapshot(gs_container_t *container, const char *snapshot_name,
		int hard_restore)
{
	_SNAPSHOT_FUNC_HEAD;

	hc_url_set(url, HCURL_SNAPSHOT, snapshot_name);
	err = m2v2_remote_execute_SNAP_RESTORE(target, NULL, url,
			(gboolean)hard_restore);

	_SNAPSHOT_FUNC_TAIL("Failed to restore snapshot '%s' of container '%s': ");
}

gs_error_t*
redc_restore_snapshot_alias(gs_container_t *container, const char *alias,
		const char *snapshot_name)
{
	_SNAPSHOT_FUNC_HEAD;

	hc_url_set(url, HCURL_SNAPSHOT, snapshot_name);
	hc_url_set(url, HCURL_PATH, alias);
	err = m2v2_remote_execute_SNAP_RESTORE(target, NULL, url, FALSE);

	_SNAPSHOT_FUNC_TAIL("Failed to restore snapshot '%s' of container '%s': ");
}

static redc_snapshot_t*
_bean_to_snapshot(gpointer bean)
{
	redc_snapshot_t *snapshot = redc_snapshot_new();
	strncpy(snapshot->name, SNAPSHOTS_get_name(bean)->str,
			GS_SNAPSHOT_MAXLENGTH);
	snapshot->version = SNAPSHOTS_get_version(bean);
	return snapshot;
}

gs_error_t*
redc_list_snapshots(gs_container_t *container, redc_snapshot_t ***snapshots)
{
	GSList *beans = NULL;
	_SNAPSHOT_FUNC_HEAD;

	err = m2v2_remote_execute_SNAP_LIST(target, NULL, url, &beans);

	if (err != NULL) {
		GSERRORCAUSE(&gserr, err, "Failed to list snapshots of container '%s'",
				C0_NAME(container));
		g_clear_error(&err);
	} else {
		GSList *cursor = beans;
		GPtrArray *result = g_ptr_array_new();
		for (; cursor != NULL; cursor = cursor->next) {
			g_ptr_array_add(result, _bean_to_snapshot(cursor->data));
		}
		g_ptr_array_add(result, NULL);
		*snapshots = (redc_snapshot_t **)g_ptr_array_free(result, FALSE);
		_bean_cleanl2(beans);
	}

	hc_url_clean(url);
	return gserr;
}

