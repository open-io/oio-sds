#ifndef __POLIX_EVENT_MANAGE_H
#define __POLIX_EVENT_MANAGE_H
#include <glib.h>

typedef struct grid_polix_s {
	gdouble timeout;
} grid_polix_t;


grid_polix_t* polix_event_create(void);


void polix_event_free(grid_polix_t* polix);


gboolean polix_event_manager(grid_polix_t *polix, const gchar *ueid,
        gridcluster_event_t *event, gboolean *flag_retry, gboolean flag_dryrun, GError **err);


#endif
