#ifndef OIO_SDS__tools__benchmark_event__fake_service_h
#define OIO_SDS__tools__benchmark_event__fake_service_h

#include <glib.h>

gboolean fake_service_configure(void);

gboolean fake_service_run(void);

void fake_service_stop(void);

void fake_service_fini(void);

#endif /* OIO_SDS__tools__benchmark_event__fake_service_h */
