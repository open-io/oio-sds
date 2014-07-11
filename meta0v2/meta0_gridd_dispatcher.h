/**
 * @file meta0_gridd_dispatcher.h
 */

#ifndef GRID__META0_GRIDD_DISPATCHER__H
# define GRID__META0_GRIDD_DISPATCHER__H 1

#include <sqliterepo/zk_manager.h>
/**
 * @addtogroup meta0v2_gridd 
 * @{
 */

struct gridd_request_descr_s;

struct meta0_disp_s;


/**
 * The easiest way to retrieve the set of exported function out of
 * the META0 backend.
 *
 * All these functions take a meta0_disp_s as first argument.
 *
 * @return
 */
const struct gridd_request_descr_s* meta0_gridd_get_requests(void);


/**
 * @param m0disp
 */
void meta0_gridd_free_dispatcher(struct meta0_disp_s *m0disp);


/**
 * @param m0
 * @return
 */
struct meta0_disp_s* meta0_gridd_get_dispatcher(struct meta0_backend_s *m0, struct zk_manager_s *m0zkmanager, gchar *ns_name);

void meta0_gridd_requested_reload(struct meta0_disp_s *m0disp);

/** @} */

#endif

