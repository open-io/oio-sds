#ifndef _EVENT_H_
#define _EVENT_H_
#include <glib.h>
#define SPOOLDIR "/GRID/common/spool"

typedef struct spooldir_stat_s {
	guint32 nb_evt;
	guint32 total_age;
	guint32 oldest;
} spooldir_stat_t;

gboolean stat_events(spooldir_stat_t *spstat, const gchar *dir);

GSList* list_ns(const gchar * dir);

#endif	/* _EVENT_H_ */
