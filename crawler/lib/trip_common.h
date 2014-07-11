#ifndef __CRAWLER_TRIP_COMMON_H
#define __CRAWLER_TRIP_COMMON_H


/**
 *  * \brief initialize repository structure
 *   *
 *    * basedir:  path base
 *     * svc_type: SQLX_TYPE / MITA1_TYPE....
 *      * repo:     the final structur initalised
 *       */
GError* tc_sqliterepo_initRepository(const gchar* basedir, gchar* svc_type, sqlx_repository_t **repo);

gchar*  tc_sqliterepo_admget(sqlx_repository_t* repo, gchar* type_, gchar* bddnameWithExtension, gchar* key);

void    tc_sqliterepo_free(sqlx_repository_t** repo);


#endif 

