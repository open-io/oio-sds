#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "sqlx.remote"
#endif

#include <errno.h>
#include <stdlib.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <sqliterepo/sqlite_utils.h>
#include <sqliterepo/sqlx_remote.h>
#include <sqliterepo/sqlx_remote_ex.h>

static gboolean on_reply_gba(gpointer out, MESSAGE reply)
{
	void *b = NULL;
	gsize bsize = 0;
	GByteArray *out_gba = (GByteArray *) out;

	if (0 < message_get_BODY(reply, &b, &bsize, NULL)) {
		if (!out_gba)
			return TRUE;
		g_byte_array_append(out_gba, b, bsize);
	}
	return TRUE;
}

GError*
sqlx_remote_execute_DESTROY(const gchar *target, GByteArray *sid,
		struct sqlxsrv_name_s *name, gboolean local)
{
	(void) sid;
	GError *err = NULL;
	GByteArray *req = sqlx_pack_DESTROY(name, local);

	struct client_s *client = gridd_client_create(target, req, NULL, NULL);
	g_byte_array_unref(req);

	gridd_client_start(client);
	if (!(err = gridd_client_loop(client))) {
		err = gridd_client_error(client);
	}

	gridd_client_free(client);
	return err;
}

GError*
sqlx_remote_execute_DESTROY_many(gchar **targets, GByteArray *sid,
		struct sqlxsrv_name_s *name)
{
	(void) sid;
	GError *err = NULL;
	GByteArray *req = sqlx_pack_DESTROY(name, TRUE);

	struct client_s **clients = gridd_client_create_many(targets, req,
			NULL, NULL);
	metautils_gba_unref(req);
	req = NULL;

	if (clients == NULL) {
		err = NEWERROR(0, "Failed to create gridd clients");
		return err;
	}

	gridd_clients_start(clients);
	err = gridd_clients_loop(clients);

	for (struct client_s **p = clients; !err && p && *p ;p++) {
		if (!(err = gridd_client_error(*p)))
			continue;
		GRID_DEBUG("Database destruction attempts failed: (%d) %s",
				err->code, err->message);
		if (err->code == CODE_CONTAINER_NOTFOUND || err->code == 404) {
			g_clear_error(&err);
			continue;
		}
	}

	gridd_clients_free(clients);
	return err;
}

GError*
sqlx_remote_execute_ADMGET(const gchar *target, GByteArray *sid,
		struct sqlx_name_s *name, const gchar *k, gchar **v)
{
	(void) sid;
	GError *err = NULL;
	GByteArray *encoded = sqlx_pack_ADMGET(name, k);
	GByteArray *gba_buf = g_byte_array_new();
	struct client_s *client = gridd_client_create(target, encoded,
			gba_buf, on_reply_gba);
	g_byte_array_unref(encoded);

	gridd_client_start(client);
	if (!(err = gridd_client_loop(client))) {
		if (!(err = gridd_client_error(client))) {
			gchar *buf = g_malloc0(gba_buf->len + 1);
			metautils_gba_data_to_string(gba_buf, buf, gba_buf->len + 1);
			*v = buf;
		}
	}

	gridd_client_free(client);
	metautils_gba_unref(gba_buf);
	return err;
}

GError*
sqlx_remote_execute_ADMSET(const gchar *target, GByteArray *sid,
		struct sqlx_name_s *name, const gchar *k, const gchar *v)
{
	(void) sid;
	GError *err = NULL;
	GByteArray *encoded = sqlx_pack_ADMSET(name, k, v);
	struct client_s *client = gridd_client_create(target, encoded, NULL, NULL);
	g_byte_array_unref(encoded);
	gridd_client_start(client);
	if (!(err = gridd_client_loop(client)))
		err = gridd_client_error(client);
	gridd_client_free(client);
	return err;
}

GError*
sqlx_get_admin_status(const gchar *target, struct sqlx_name_s *name,
		guint32 *status)
{
	GError *err = NULL;
	gchar *str_status = NULL;
	err = sqlx_remote_execute_ADMGET(target, NULL, name,
			ADMIN_STATUS_KEY, &str_status);
	if (err == NULL) {
		gchar *tmp = NULL;
		errno = 0;
		guint32 res = strtoul(str_status, &tmp, 10);
		if (tmp == str_status) {
			err = NEWERROR(0, "Failed to parse '%s': %s",
					str_status, g_strerror(errno));
		} else {
			*status = res;
		}
	}
	g_free(str_status);
	return err;
}

GError*
sqlx_set_admin_status(const gchar *target, struct sqlx_name_s *name,
		guint32 status)
{
	GError *err = NULL;
	gchar str_status[16];
	g_snprintf(str_status, 16, "%u", status);

	err = sqlx_remote_execute_ADMSET(target, NULL, name,
			ADMIN_STATUS_KEY, str_status);

	return err;
}

