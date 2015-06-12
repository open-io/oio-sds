#include "./gs_internals.h"

static void _gs_error_clear (gs_error_t **e)
{
	gs_error_free (*e);
	*e = NULL;
}

char *gen_random(size_t length) {

    static char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.-#'?!";        
    char *randomString = NULL;

    if (length) {
        randomString = malloc(sizeof(char) * (length +1));

        if (randomString) {            
            for (int n = 0;n < length;n++) {            
                int key = rand() % (int)(sizeof(charset) -1);
                randomString[n] = charset[key];
            }

            randomString[length] = '\0';
        }
    }

    return randomString;
}

static char* test_init(gs_grid_storage_t *gs)
{
	char *nameRef = gen_random(8);
	char *nameRef2 = gen_random(8);
	hc_create_reference(gs, nameRef);
	return nameRef;
}

static void test_end(gs_grid_storage_t *gs, char *nameRef)
{
	hc_delete_reference(gs, nameRef);
}

static void test_create_reference(gs_grid_storage_t *gs)
{
	char *nameRef = gen_random(8);
	g_assert_true(hc_create_reference(gs, nameRef) == NULL);	
	g_assert_true(hc_has_reference(gs, nameRef) == NULL);

	test_end(gs, nameRef);
}

static void test_has_reference(gs_grid_storage_t *gs)
{
	char *nameRef = test_init(gs);
	g_assert_true(hc_has_reference(gs, nameRef) == NULL);

	test_end(gs, nameRef);
}

static void test_has_reference_wrong(gs_grid_storage_t *gs)
{
	gs_error_t *err = hc_has_reference(gs, "Error");
	g_assert_true(err->code == 431);
}

static void test_delete_reference(gs_grid_storage_t *gs)
{
	char *nameRef = test_init(gs);
	g_assert_true(hc_delete_reference(gs, nameRef) == NULL);
	g_assert_false(hc_has_reference(gs, nameRef) == NULL);
}

static void test_delete_reference_wrong(gs_grid_storage_t *gs)
{
	gs_error_t *err = hc_delete_reference(gs, "Error");
	g_assert_true(err->code == 431);
}

int main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	
	const char *ns = "NS";

	gs_error_t *err = NULL;
	gs_grid_storage_t *gs = gs_grid_storage_init (ns, &err);
	if (!gs) {
		fprintf(stderr, "OIO init error : (%d) %s\n", err->code, err->msg);
		_gs_error_clear (&err);
		abort();
	}

	g_test_add_data_func("/client/lib/meta/create_ref", gs, test_create_reference);
	g_test_add_data_func("/client/lib/meta/has_ref", gs, test_has_reference);
	g_test_add_data_func("/client/lib/meta/has_ref_w", gs, test_has_reference_wrong);
	g_test_add_data_func("/client/lib/meta/delete_ref", gs, test_delete_reference);
	g_test_add_data_func("/client/lib/meta/delete_ref_w", gs, test_delete_reference_wrong);
	
	int success = g_test_run();
	
	gs_grid_storage_free (gs);
	gs = NULL;

	return success;
}
