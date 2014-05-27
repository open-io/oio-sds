#ifndef _TASK_H
# define _TASK_H
# include <glib.h>
# include <cluster/agent/worker.h>

typedef int (*task_handler_f) (gpointer udata, GError **err);

typedef struct {
	char *id;
	long period;
	long next_schedule;
	gboolean busy;
	task_handler_f task_handler;
	GDestroyNotify clean_udata;
	gpointer udata;
	/** allows */
	char flag_destroy;
} task_t;

#endif	/* _TASK_H */
