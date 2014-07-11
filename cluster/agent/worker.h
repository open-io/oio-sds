#ifndef _WORKER_H
#define _WORKER_H

#include <sys/time.h>
#include <glib.h>

#define CLEAR_WORKER_DATA(d) if (d) {\
	if ((d)->buffer) { g_free((d)->buffer); (d)->buffer = NULL; }\
	(d)->buffer_size = (d)->done = 0; }

typedef struct worker_data_s worker_data_t;
typedef struct worker_s worker_t;

typedef int (*worker_func_f)(worker_t *worker, GError **error);
typedef void (*worker_clean_f)(worker_t *worker);

struct worker_data_s {
	int fd;
	long sock_timeout;
	void *buffer;
	guint32 buffer_size;
	guint32 done;
	void *session;
	gboolean size_64;
};

struct worker_s {
	worker_func_f func;
	worker_clean_f clean;
	worker_data_t data;
	long timeout;
	struct timeval timestamp;
};

int agent_worker_default_func( worker_t *worker, GError **error );

void agent_worker_default_cleaner( worker_t *worker );

#endif		/* _WORKER_H */
