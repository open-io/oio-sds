/**
 * @file transport_echo.h
 */

#ifndef GRID__TRANSPORT_ECHO__H
# define GRID__TRANSPORT_ECHO__H 1

/**
 * @defgroup server_transecho ECHO transport
 * @ingroup server
 * @brief
 * @details
 * 
 * @{
 */

struct network_client_s;

/**
 * @param u
 * @param clt
 */
void transport_echo_factory(gpointer u, struct network_client_s *clt);

/** @} */

#endif
