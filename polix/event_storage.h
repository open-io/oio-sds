#ifndef __POLIX_EVENT_STORAGE_H
#define __POLIX_EVENT_STORAGE_H
#include <glib.h>


typedef enum event_status_e event_status_et;


typedef struct polix_event_t {
    gchar*               ueid;
    gridcluster_event_t *event;
} polix_event_t;


polix_event_t* pe_create(void);

gboolean pes_init(void);
void     pes_close(void);
gboolean pes_IsExist(const gchar* ueid);
gboolean pes_get_status(const gchar* ueid, event_status_et *status);
gboolean pes_set_status(polix_event_t *pe, event_status_et status);
gboolean pes_delete(const gchar* ueid, gboolean bAll);

#endif
