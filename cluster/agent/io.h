#include <sys/time.h>

typedef struct io_s {
	struct timeval last_time;
	unsigned long io_time;
} io_t;

/** Init the io struct */
void io_init(io_t *io, const char *device);

/** Return the % of time not doing IO */
int get_free_io(io_t *io);
