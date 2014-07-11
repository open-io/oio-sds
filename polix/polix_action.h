#ifndef __POLIX_ACTION_H
#define __POLIX_ACTION_H
#include <glib.h>

typedef struct {
	guint  nb_del;    // nb chunk deleted
	gint64 del_size;  // size deleted
} polix_action_purge_result_t;

struct hc_url_s;

char* polix_action_get_meta2_url_byhexid(char* ns, char* hexid, GError **error);


gboolean polix_action_purge(char* namespace, char* hexid, const char* meta2_url,
		gdouble timeout_request, gboolean dryrun,
		polix_action_purge_result_t* result, GError **error);


gboolean polix_action_purge_byurl(struct hc_url_s *url, const char* meta2_url,
		gdouble timeout_request, gboolean dryrun,
		polix_action_purge_result_t* result, GError **error);

gboolean polix_action_drop_chunks(gboolean dryrun, GSList *del_chunks_list,
        polix_action_purge_result_t* result, GError **error);

#endif
