#ifndef __SRV_ALERT_HANDLER_H__
# define __SRV_ALERT_HANDLER_H__

#include <stdlib.h>
#include <string.h>

#include <metautils/lib/metautils.h>
#include "./message_handler.h"
#include "./srvalert.h"

/*dummy alert handler*/

static int
srv_dumy_alert_handler(void *user_data, const char *id, const char *criticity, const char *msg)
{
	(void)user_data;
	ALERT_DOMAIN((id ? id : "alert"), "%s:%s", criticity, msg);
	return 1;
}

/* ------------------------------------------------------------------------- */

static gpointer alert_handler_user_data = NULL;
static srv_alert_handler alert_handler = srv_dumy_alert_handler;

gpointer
srv_set_alert_handler(srv_alert_handler h, gpointer user_data)
{
	gpointer previous_user_data = alert_handler_user_data;

	alert_handler = h;
	alert_handler_user_data = user_data;
	NOTICE("Alert handler replaced : handler[%p] user_data[%p]", h, user_data);
	return previous_user_data;
}

int
srv_send_alert(const char *id, const char *criticity, const char *msg)
{
	static volatile int warning_sent = 0;

	if (!criticity || !id || !msg) {
		WARN("Invalid parameter");
		return 0;
	}

	if (alert_handler) {
		return alert_handler(alert_handler_user_data, id, criticity, msg);
	}

	if (!warning_sent) {
		WARN("No server alert handler registered");
		warning_sent = 1;
	}

	return 0;
}

int
srv_send_valert(const char *id, const char *criticity, const char *fmt, va_list args)
{
	char formatted_msg[8192];

	if (!fmt) {
		WARN("Invalid parameter");
		return 0;
	}
	memset(formatted_msg, 0x00, sizeof(formatted_msg));
	g_vsnprintf(formatted_msg, sizeof(formatted_msg) - 1, fmt, args);
	return srv_send_alert(id, criticity, formatted_msg);
}

int
srv_send_falert(const char *id, const char *criticity, const char *fmt, ...)
{
	int rc;
	va_list args;

	va_start(args, fmt);
	rc = srv_send_valert(id, criticity, fmt, args);
	va_end(args);
	return rc;
}

#endif /*__SRV_ALERT_HANDLER_H__*/
