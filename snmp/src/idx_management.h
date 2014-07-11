#ifndef _IDX_MANAGEMENT_H
#define _IDX_MANAGEMENT_H

#include <glib.h>

#define MAX_DESC_LENGTH (MAX(STRLEN_ADDRINFO, LIMIT_LENGTH_VOLUMENAME) + LIMIT_LENGTH_NSNAME + 2)

struct grid_service_data {
        int idx;
        char desc[MAX_DESC_LENGTH];
};

int get_idx_of_service(const char *service_type, struct grid_service_data *service, GError **error);

#endif	/* _IDX_MANAGEMENT_H */
