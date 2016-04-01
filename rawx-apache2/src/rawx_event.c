#include <stdlib.h>
#include <assert.h>

#include <beanstalk.h>
#include <glib.h>

#include <core/oioext.h>
#include "metautils/lib/metautils_sockets.h"
#include "rawx_event.h"

static char beanstalkd_addr[RAWX_EVENT_ADDR_SIZE] = {0};
static int beanstalkd_port = 11300;
static int beanstalkd_ttr = 120;
static int beanstalkd_priority = 0x7fffffff;

int
rawx_event_init(const char *addr)
{
	if (addr == NULL)
		return 0;

	memset(beanstalkd_addr, 0, sizeof(beanstalkd_addr));
	const char *port_str = strrchr(addr, ':');
	if (port_str) {
		beanstalkd_port = atoi(port_str + 1);
		strncpy(beanstalkd_addr, addr, port_str - addr);
	} else {
		g_strlcpy(beanstalkd_addr, addr, sizeof(beanstalkd_addr));
	}
	// TODO: keep an open connection to beanstalkd
	return 1;
}

void
rawx_event_destroy(void)
{
	// Nothing to do at the moment
}

int
rawx_event_send(const char *event_type, GString *data_json) {
	if (!beanstalkd_addr[0])
		return 0;

	GString *json = g_string_sized_new(256);

	g_string_append_printf(json,
			"{"
			"\"event\":\"%s\","
			"\"when\":%"G_GINT64_FORMAT","
			"\"data\":%s"
			"}",
			event_type,
			oio_ext_real_time() / G_TIME_SPAN_SECOND,
			data_json->str);

	g_string_free(data_json, TRUE);

	return rawx_event_send_raw(json);
}

int
rawx_event_send_raw(GString *json) {
	int rc = 1;
	int sock = bs_connect(beanstalkd_addr, beanstalkd_port);
	if (sock == BS_STATUS_FAIL) {
		rc = 0;
		goto end;
	}
	sock_set_linger_default(sock);

	int id = bs_put(sock, beanstalkd_priority, 0, beanstalkd_ttr,
			json->str, json->len);
	if (id <= 0)
		rc = 0;

	bs_disconnect(sock);
end:
	g_string_free(json, TRUE);
	return rc;
}
