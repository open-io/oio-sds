/**
 * @file alert.h
 */

#ifndef ALERT_H
#define ALERT_H

/**
 * @defgroup integrity_loop_lib_alert Alerting
 * @ingroup integrity_loop_lib
 * @{
 */

#include <glib.h>

/**
 * Sends an alert to the alerting system
 *
 * @param domain the domain this alert applies to (x.y.z)
 * @param criticity this alert criticity
 * @param message the alert message
 *
 * @return TRUE or FALSE if the alert was not successfully sent to the alerting system
 */
gboolean alert(const gchar* domain, int criticity, const gchar* message);

/** @} */

#endif /* ALERT_H */
