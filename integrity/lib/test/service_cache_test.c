#include <test-dept.h>

#include <metautils/lib/metautils.h>

#include "service_cache.h"
#include "stub_headers.h"

#define NS_NAME "namespace"

static GSList*
list_local_services_fake(GError **error)
{
	GSList* result = NULL;
	service_info_t *si1 = NULL, *si2 = NULL;

	
	/* Create 2 fake service_info */
	si1 = g_new0(service_info_t, 1);
	strcpy(si1->ns_name, NS_NAME);
	strcpy(si1->type, NAME_SRVTYPE_RAWX);
	memcpy(&(si1->addr), build_addr_info("127.0.0.1", 6000, error), sizeof(addr_info_t));

	si2 = g_new0(service_info_t, 1);
	strcpy(si2->ns_name, NS_NAME);
	strcpy(si2->type, NAME_SRVTYPE_RAWX);
	memcpy(&(si2->addr), build_addr_info("127.0.0.1", 8000, error), sizeof(addr_info_t));

	result = g_slist_prepend(result, si1);
	result = g_slist_prepend(result, si2);

	return result;
}

void setup()
{
	log4c_init();
}

void teardown()
{
	log4c_fini();
}

void test_update_service_cache_args_null()
{
        GError *error = NULL;

	test_dept_assert_false(update_service_cache(NULL, &error));
        test_dept_assert_true(error);
}

void test_update_service_cache()
{
	GError *error = NULL;
	struct service_cache_s service_cache;
	struct pooled_service_s *ps1 = NULL, *ps2 = NULL;
	service_info_t *si1 = NULL, *si2 = NULL;

	/* Override list_local_services() */
	test_dept_list_local_services_set(list_local_services_fake);

	/* Create 2 fake service_info */
	si1 = g_new0(service_info_t, 1);
	strcpy(si1->ns_name, NS_NAME);
	strcpy(si1->type, NAME_SRVTYPE_RAWX);
	memcpy(&(si1->addr), build_addr_info("127.0.0.1", 6000, &error), sizeof(addr_info_t));

	si2 = g_new0(service_info_t, 1);
	strcpy(si1->ns_name, NS_NAME);
	strcpy(si1->type, NAME_SRVTYPE_RAWX);
	memcpy(&(si1->addr), build_addr_info("127.0.0.1", 7000, &error), sizeof(addr_info_t));

	/* Create 2 fake pooled service */
	ps1 = g_new0(struct pooled_service_s, 1);
	ps1->in_pool = TRUE;
	ps1->service_info = si1;

	ps2 = g_new0(struct pooled_service_s, 1);
	ps2->in_pool = TRUE;
	ps2->service_info = si2;

	/* Prepare a fake service_cache */
	memset(&service_cache, 0, sizeof(struct service_cache_s));
	service_cache.service_type = NAME_SRVTYPE_RAWX;
	service_cache.service_list = g_slist_prepend(service_cache.service_list, ps1);
	service_cache.service_list = g_slist_prepend(service_cache.service_list, ps2);

	test_dept_assert_true(update_service_cache(&service_cache, &error));
	test_dept_assert_false(error);

	/* Test the new list is ok */
	test_dept_assert_equals_int(2, g_slist_length(service_cache.service_list));

	ps1 = g_slist_nth_data(service_cache.service_list, 0);
	ps2 = g_slist_nth_data(service_cache.service_list, 1);

	test_dept_assert_not_equals_int(7000, ps1->service_info->addr.port);
	test_dept_assert_not_equals_int(7000, ps2->service_info->addr.port);
}
