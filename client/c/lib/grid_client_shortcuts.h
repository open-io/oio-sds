#ifndef __GSCLIENT_SHORTCUTS_H__
# define __GSCLIENT_SHORTCUTS_H__ 1

# include <metautils/lib/metatypes.h>

gs_content_t*
gs_container_get_content_from_raw(gs_grid_storage_t *client,
                struct meta2_raw_content_s *raw, gs_error_t **gserr);

#endif
