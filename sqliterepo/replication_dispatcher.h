/**
 * @file replication_dispatcher.h
 */

#ifndef GRID__SQLXREPLI_GRIDD_DISPATCHER__H
# define GRID__SQLXREPLI_GRIDD_DISPATCHER__H 1

/**
 * @defgroup sqliterepo_gridd Gridd requests dispatcher
 * @ingroup sqliterepo
 * @brief
 * @details
 *
 * @{
 */

struct gridd_request_descr_s;

/**
 * The easiest way to retrieve the set of exported function out of
 * the META1 backend.
 *
 * All these functions take a meta1_backend_s as first argument.
 *
 * @return
 */
const struct gridd_request_descr_s* sqlx_repli_gridd_get_requests(void);

/**
 * @return
 */
const struct gridd_request_descr_s * sqlx_sql_gridd_get_requests(void);

/** @} */

#endif

