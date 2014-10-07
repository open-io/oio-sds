#ifndef META_BACKEND_COMMON__H
# define META_BACKEND_COMMON__H 1
# include <glib.h>
# include <metautils/lib/metautils.h>

# include <sqliterepo/sqliterepo.h>

struct meta_backend_common_s {
	gchar ns_name[LIMIT_LENGTH_NSNAME];
	namespace_info_t ns_info;
	GMutex *ns_info_lock;
	const gchar *type;
	struct sqlx_repository_s *repo;

	// Managed by sqlx_service_extra, do not allocate/free
	struct grid_lbpool_s *lb;
	struct event_config_repo_s *evt_repo;
};

#endif

