/*
 * OpenIO SDS client
 * Copyright (C) 2014 Worldine, original work as part of Redcurrant
 * Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 * */

#include "./gs_internals.h"

static void
_gs_error_clear(gs_error_t ** e)
{
	gs_error_free(*e);
	*e = NULL;
}

static char *
gen_random(size_t length)
{

	static char charset[] =
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.-#'?!";
	char *randomString = NULL;

	if (length) {
		randomString = malloc(sizeof(char) * (length + 1));

		if (randomString) {
			for (unsigned int n = 0; n < length; n++) {
				int key = rand() % (int) (sizeof(charset) - 1);

				randomString[n] = charset[key];
			}

			randomString[length] = '\0';
		}
	}

	return randomString;
}

static char *
test_init(gs_grid_storage_t * gs, char *init_type)
{
	char *nameRef = gen_random(8);
	gchar **tmp = NULL;

	hc_create_reference(gs, nameRef);

	if (strcmp(init_type, "Ref_linked") == 0)
		hc_link_service_to_reference(gs, nameRef, "meta2", &tmp);

	return nameRef;
}

static void
test_end(gs_grid_storage_t * gs, char *nameRef)
{
	hc_unlink_reference_service(gs, nameRef, "meta2");
	hc_delete_reference(gs, nameRef);
}

static void
test_link_service_to_reference(gs_grid_storage_t * gs)
{
	char *nameRef = test_init(gs, "Ref");
	gchar **tmp = NULL;
	gchar **tmp2 = NULL;

	gs_error_t *err = hc_link_service_to_reference(gs, nameRef, "meta2", &tmp);

	g_assert_true(err == NULL);

	hc_list_reference_services(gs, nameRef, "meta2", &tmp2);

    g_assert_true(tmp[0] != NULL);
    int i=0, next=1, success=1;
    while(next && success)
    {
        if(tmp[i] == NULL) next = 0;
        else success=strcmp(tmp[i], tmp2[i]); 
        i++;
    }
    g_assert_true(success==0);

	test_end(gs, nameRef);
}

static void
test_link_service_to_reference_again(gs_grid_storage_t * gs)
{
	char *nameRef = test_init(gs, "Ref");
	gchar **tmp = NULL;

	hc_link_service_to_reference(gs, nameRef, "meta2", &tmp);
	gs_error_t *err = hc_link_service_to_reference(gs, nameRef, "meta2", &tmp);

	g_assert_true(err == NULL);

	test_end(gs, nameRef);
}

static void
test_link_service_to_reference_wrong(gs_grid_storage_t * gs)
{
	gchar **tmp = NULL;

	gs_error_t *err = hc_link_service_to_reference(gs, "Error", "meta2", &tmp);

	if (err != NULL)
		g_assert_true(err->code == 431);
	else
		g_test_fail();
}

static void
test_link_service_to_reference_bad_meta(gs_grid_storage_t * gs)
{
	char *nameRef = test_init(gs, "Ref");
	gchar **tmp = NULL;

	gs_error_t *err = hc_link_service_to_reference(gs, nameRef, "Error", &tmp);

	if (err != NULL)
		g_assert_true(err->code == 453);
	else
		g_test_fail();

	test_end(gs, nameRef);
}

static void
test_unlink_reference_service(gs_grid_storage_t * gs)
{
	char *nameRef = test_init(gs, "Ref_linked");
	gchar **tmp = NULL;

	gs_error_t *err = hc_unlink_reference_service(gs, nameRef, "meta2");

	g_assert_true(err == NULL);

	hc_list_reference_services(gs, nameRef, "meta2", &tmp);
	g_assert_true(tmp[0] == NULL);

	test_end(gs, nameRef);
}

static void
test_unlink_reference_service_wrong_name(gs_grid_storage_t * gs)
{
	gs_error_t *err = hc_unlink_reference_service(gs, "Error", "meta2");

	if (err != NULL)
		g_assert_true(err->code == 431);
	else
		g_test_fail();
}

static void
test_unlink_reference_service_bad_meta(gs_grid_storage_t * gs)
{

	char *nameRef = test_init(gs, "Ref_linked");

	gs_error_t *err = hc_unlink_reference_service(gs, nameRef, "Error");

	if (err != NULL)
		g_assert_true(err->code == 453);
	else
		g_test_fail();

	test_end(gs, nameRef);
}

static void
test_list_reference_services(gs_grid_storage_t * gs)
{
	char *nameRef = test_init(gs, "Ref_linked");
	gchar **tmp = NULL;

	gs_error_t *err = hc_list_reference_services(gs, nameRef, "meta2", &tmp);

	g_assert_true(err == NULL);

	test_end(gs, nameRef);
}

static void
test_list_reference_services_wrong(gs_grid_storage_t * gs)
{
	gchar **tmp = NULL;

	gs_error_t *err = hc_list_reference_services(gs, "Error", "meta2", &tmp);

	if (err != NULL)
		g_assert_true(err->code == 431);
	else
		g_test_fail();
}

static void
test_list_reference_services_bad_meta(gs_grid_storage_t * gs)
{
	char *nameRef = test_init(gs, "Ref_linked");
	gchar **tmp = NULL;

	gs_error_t *err = hc_list_reference_services(gs, nameRef, "Error", &tmp);

	if (err != NULL)
		g_assert_true(err->code == 453);
	else
		g_test_fail();

	test_end(gs, nameRef);
}

static void
test_poll_service(gs_grid_storage_t * gs)
{
	char *nameRef = test_init(gs, "Ref");
	gchar *serv = NULL;

	char *list_serv[] = {
		"1|meta2|192.168.56.101:6010|",
		"1|meta2|192.168.56.101:6011|",
		"1|meta2|192.168.56.101:6012|"
	};

	gs_error_t *err = hc_poll_service(gs, nameRef, "meta2", &serv);

	g_assert_true(err == NULL);

    g_assert_true(list_serv[0] != NULL);
    int i=0, next=1, success=1;
    while(next && success)
    {
        if(list_serv[i] == NULL) next = 0;
        else success=strcmp(serv, list_serv[i]);
        i++;
    }
    g_assert_true(!success);

	test_end(gs, nameRef);
}

static void
test_poll_service_wrong(gs_grid_storage_t * gs)
{
	gchar *serv = NULL;

	gs_error_t *err = hc_poll_service(gs, "Error", "meta2", &serv);

	if (err != NULL)
		g_assert_true(err->code == 431);
	else
		g_test_fail();
}

static void
test_poll_service_bad_meta(gs_grid_storage_t * gs)
{
	char *nameRef = test_init(gs, "Ref");
	gchar *serv = NULL;

	gs_error_t *err = hc_poll_service(gs, nameRef, "meta2", &serv);

	if (err != NULL)
		g_assert_true(err->code == 453);
	else
		g_test_fail();

	test_end(gs, nameRef);
}

static void
test_force_service(gs_grid_storage_t * gs)
{
	char *nameRef = test_init(gs, "Ref");
	gchar **tmp = NULL;

	gs_error_t *err =
		hc_force_service(gs, nameRef, "1|meta2|192.168.56.101:6042|");
	g_assert_true(err == NULL);

	hc_list_reference_services(gs, nameRef, "meta2", &tmp);
	g_assert_true(strcmp(tmp[0], "1|meta2|192.168.56.101:6042|") == 0);

	test_end(gs, nameRef);
}

static void
test_force_service_linked(gs_grid_storage_t * gs)
{
	char *nameRef = test_init(gs, "Ref_linked");
	gchar **tmp = NULL;

	gs_error_t *err =
		hc_force_service(gs, nameRef, "1|meta2|192.168.56.101:6048|");

	if (err != NULL)
		g_test_fail();
	else {
		hc_list_reference_services(gs, nameRef, "meta2", &tmp);
		g_assert_true(strcmp(tmp[0], "1|meta2|192.168.56.101:6048|") == 0);
	}

	test_end(gs, nameRef);
}

static void
test_force_service_wrong(gs_grid_storage_t * gs)
{
	gs_error_t *err =
		hc_force_service(gs, "Error", "1|meta2|192.168.56.101:6010|");
	if (err != NULL)
		g_assert_true(err->code == 431);
	else
		g_test_fail();
}

static void
test_configure_service(gs_grid_storage_t * gs)
{
	char *nameRef = test_init(gs, "Ref_linked");
	gchar **tmp = NULL;

	gs_error_t *err = hc_configure_service(gs, nameRef, "1|meta2||test|");

	g_assert_true(err == NULL);

	hc_list_reference_services(gs, nameRef, "meta2", &tmp);

    g_assert_true(tmp[0] != NULL);
    int i=0, next=1, success=1;
    while(next && success)
    {
        if(tmp[i] == NULL) next = 0;
        else success=strcmp(tmp[i], "1|meta2|192.168.56.101:6008|test|");
        i++;
    }
    g_assert_true(!success);

	test_end(gs, nameRef);
}

static void
test_configure_service_wrong(gs_grid_storage_t * gs)
{
	gs_error_t *err = hc_configure_service(gs, "Error", "1|meta2||test|");

	if (err != NULL)
		g_assert_true(err->code == 431);
	else
		g_test_fail();
}

static void
test_configure_service_invalid_url(gs_grid_storage_t * gs)
{
	char *nameRef = test_init(gs, "Ref_linked");

	gs_error_t *err = hc_configure_service(gs, nameRef, "1|meta1||test|");

	if (err != NULL)
		g_assert_true(err->code == 454);
	else
		g_test_fail();

	test_end(gs, nameRef);
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc, argv);

	const char *ns = "NS";

	gs_error_t *err = NULL;
	gs_grid_storage_t *gs = gs_grid_storage_init(ns, &err);

	if (!gs) {
		fprintf(stderr, "OIO init error : (%d) %s\n", err->code, err->msg);
		_gs_error_clear(&err);
		abort();
	}

	g_test_set_nonfatal_assertions();

	g_test_add_data_func("/client/lib/serv/link_serv_ref", gs,
		(GTestDataFunc) test_link_service_to_reference);
	g_test_add_data_func("/client/lib/serv/link_serv_ref_w", gs,
		(GTestDataFunc) test_link_service_to_reference_wrong);
	g_test_add_data_func("/client/lib/serv/link_serv_ref_again", gs,
		(GTestDataFunc) test_link_service_to_reference_again);
	g_test_add_data_func("/client/lib/serv/link_serv_ref_bad_meta", gs,
		(GTestDataFunc)
		test_link_service_to_reference_bad_meta);

	g_test_add_data_func("/client/lib/serv/unlink_ref_serv", gs,
		(GTestDataFunc) test_unlink_reference_service);
	g_test_add_data_func("/client/lib/serv/unlink_ref_serv_w", gs,
		(GTestDataFunc)
		test_unlink_reference_service_wrong_name);
	g_test_add_data_func("/client/lib/serv/unlink_ref_serv_bad_meta", gs,
		(GTestDataFunc)
		test_unlink_reference_service_bad_meta);

	g_test_add_data_func("/client/lib/serv/list_ref_serv", gs,
		(GTestDataFunc) test_list_reference_services);
	g_test_add_data_func("/client/lib/serv/list_ref_serv_w", gs,
		(GTestDataFunc) test_list_reference_services_wrong);
	g_test_add_data_func("/client/lib/serv/list_ref_serv_bad_meta", gs,
		(GTestDataFunc)
		test_list_reference_services_bad_meta);

	g_test_add_data_func("/client/lib/serv/poll_serv", gs,
		(GTestDataFunc) test_poll_service);
	g_test_add_data_func("/client/lib/serv/poll_serv_w", gs,
		(GTestDataFunc) test_poll_service_wrong);
	g_test_add_data_func("/client/lib/serv/poll_serv_bad_meta", gs,
		(GTestDataFunc) test_poll_service_bad_meta);

	g_test_add_data_func("/client/lib/serv/force_serv", gs,
		(GTestDataFunc) test_force_service);
	g_test_add_data_func("/client/lib/serv/force_serv_linked", gs,
		(GTestDataFunc) test_force_service_linked);
	g_test_add_data_func("/client/lib/serv/force_serv_w", gs,
		(GTestDataFunc) test_force_service_wrong);

	g_test_add_data_func("/client/lib/serv/conf_serv", gs,
		(GTestDataFunc) test_configure_service);
	g_test_add_data_func("/client/lib/serv/conf_serv_w", gs,
		(GTestDataFunc) test_configure_service_wrong);
	g_test_add_data_func("/client/lib/serv/conf_serv_inv_url", gs,
		(GTestDataFunc) test_configure_service_invalid_url);

	int success = g_test_run();

	gs_grid_storage_free(gs);
	gs = NULL;

	return success;
}
