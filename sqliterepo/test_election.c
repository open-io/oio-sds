#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "test"
#endif

#include <metautils/lib/metautils.h>
#include "election.h"
#include "version.h"

static const gchar * _get_id (gpointer ctx) {
	(void) ctx;
	return "0.0.0.0:0";
}

static GError* _get_peers (gpointer ctx, const gchar *n, const gchar *t,
		gchar ***result) {
	(void) ctx, (void) n, (void) t;
	*result = g_malloc0(sizeof(gchar*));
	return NULL;
}

static GError* _get_vers (gpointer ctx, const gchar *n, const gchar *t,
		GTree **result) {
	(void) ctx, (void) n, (void) t;
	*result = version_empty();
	return NULL;
}

static void
test_create_bad_config(void)
{
	struct election_manager_s *m = NULL;
	GError *err;

	struct replication_config_s cfg0 = { NULL, _get_peers, _get_vers,
		NULL, ELECTION_MODE_NONE};
	err = election_manager_create(&cfg0, &m);
	g_assert_error(err, g_quark_from_static_string("sqliterepo"), ERRCODE_PARAM);
	g_clear_error(&err);

	struct replication_config_s cfg1 = { _get_id, NULL, _get_vers,
		NULL, ELECTION_MODE_NONE};
	err = election_manager_create(&cfg1, &m);
	g_assert_error(err, g_quark_from_static_string("sqliterepo"), ERRCODE_PARAM);
	g_clear_error(&err);

	struct replication_config_s cfg2 = { _get_id, _get_peers, NULL,
		NULL, ELECTION_MODE_NONE};
	err = election_manager_create(&cfg2, &m);
	g_assert_error(err, g_quark_from_static_string("sqliterepo"), ERRCODE_PARAM);
	g_clear_error(&err);

	struct replication_config_s cfg3 = { _get_id, _get_peers, _get_vers,
		NULL, ELECTION_MODE_NONE+3};
	err = election_manager_create(&cfg3, &m);
	g_assert_error(err, g_quark_from_static_string("sqliterepo"), ERRCODE_PARAM);
	g_clear_error(&err);
}

static void
test_create_ok(void)
{
	struct replication_config_s cfg = { _get_id, _get_peers, _get_vers,
		NULL, ELECTION_MODE_NONE};
	struct election_manager_s *m = NULL;
	GError *err;

	err = election_manager_create(&cfg, &m);
	g_assert_no_error(err);
	g_assert(&cfg == election_manager_get_config0(m));
	election_manager_clean(m);
}

static void
test_election_init(void)
{
	struct replication_config_s cfg = { _get_id, _get_peers, _get_vers,
		NULL, ELECTION_MODE_NONE};
	struct election_manager_s *m = NULL;
	GError *err = NULL;

	err = election_manager_create(&cfg, &m);
	g_assert_no_error(err);
	g_assert(&cfg == election_manager_get_config0(m));

	err = election_init(m, "name", "type");
	g_assert_no_error(err);

	election_manager_clean(m);
}

int
main(int argc, char **argv)
{
	HC_PROC_INIT(argv,GRID_LOGLVL_INFO);
	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/sqlx/election/create_bad_config",
			test_create_bad_config);
	g_test_add_func("/sqlx/election/create_ok",
			test_create_ok);
	g_test_add_func("/sqlx/election/election_init",
			test_election_init);
	return g_test_run();
}
