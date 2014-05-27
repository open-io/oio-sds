#ifndef __SOLR_UTILS_H__
#define __SOLR_UTILS_H__

#include <glib.h>
  
extern gboolean
set_solr_service(gs_grid_storage_t *grid, const gchar *container_name, const gchar *new_solr_service);
 
#endif /*  __SOLR_UTILS_H__ */
