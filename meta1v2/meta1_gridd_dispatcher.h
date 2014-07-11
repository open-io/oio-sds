/**
 * @file meta1_gridd_dispatcher.h
 */

#ifndef GRID__META1_GRIDD_DISPATCHER__H
# define GRID__META1_GRIDD_DISPATCHER__H 1

/**
 * @addtogroup meta1v2_gridd 
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
const struct gridd_request_descr_s* meta1_gridd_get_requests(void);

/** @} */

#endif
