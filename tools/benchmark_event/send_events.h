#ifndef OIO_SDS__tools__benchmark_event__send_events_h
#define OIO_SDS__tools__benchmark_event__send_events_h

#include <glib.h>

void send_events_defaults(void);

gboolean send_events_configure(int argc, char **argv);

void send_events_run(void);

void send_events_fini(void);

#endif /* OIO_SDS__tools__benchmark_event__send_events_h */
