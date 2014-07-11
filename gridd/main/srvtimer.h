#ifndef __SRV_TIMER_H__
# define __SRV_TIMER_H__

#include <glib.h>

typedef void (*srvtimer_f) (gpointer udata);

gboolean srvtimer_register_regular (const char *name, srvtimer_f fire,
	srvtimer_f close, gpointer udata, guint64 freq);

void srvtimer_init (void);

void srvtimer_fini (void);

void srvtimer_fire (guint64 ticks);

#endif /*__SRV_TIMER_H__*/
