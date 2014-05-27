#ifndef __META2_BACKEND_DBCONVERT_H__
# define __META2_BACKEND_DBCONVERT_H__ 1
# include <glib.h>
# include <sqlite3.h>

void m2v2_init_db(void);

void m2v2_clean_db(void);

GError* m2_convert_db(sqlite3 *db);

GError* m2_unconvert_db(sqlite3 *db);

#endif /* __META2_BACKEND_DBCONVERT_H__ */
