#ifndef GRID__META2_GRIDD_DISPATCHER__H
# define GRID__META2_GRIDD_DISPATCHER__H 1

struct gridd_request_descr_s;

/**
 * The easiest way to retrieve the set of exported function out of
 * the META2 backend.
 *
 * All these functions take a meta1_backend_s as first argument.
 */
const struct gridd_request_descr_s* meta2_gridd_get_v1_requests(void);

/**
 * The easiest way to retrieve the set of exported function out of
 * the META2 backend.
 *
 * All these functions take a meta1_backend_s as first argument.
 */
const struct gridd_request_descr_s* meta2_gridd_get_v2_requests(void);

#endif

