#ifndef SQLX_UPGRADE__H
# define SQLX_UPGRADE__H 1
# include <glib/gtypes.h>

struct sqlx_sqlite3_s;
struct sqlx_upgrader_s;

typedef GError* (sqlx_upgrade_cb) (struct sqlx_sqlite3_s *sq3,
		gpointer cb_data);

struct sqlx_upgrader_s* sqlx_upgrader_create(void);

void sqlx_upgrader_destroy(struct sqlx_upgrader_s *su);

void sqlx_upgrader_register(struct sqlx_upgrader_s *su,
		const gchar *p0, const gchar *p1,
		sqlx_upgrade_cb cb, gpointer cb_data);

GError* sqlx_upgrade_do(struct sqlx_upgrader_s *su,
		struct sqlx_sqlite3_s *sq3);

#endif /* SQLX_UPGRADE__H */
