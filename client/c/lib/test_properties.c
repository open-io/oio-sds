#include "./gs_internals.h"

static void
_gs_error_clear (gs_error_t ** e)
{
  gs_error_free (*e);
  *e = NULL;
}

static char *
gen_random (size_t length)
{

  static char charset[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  char *randomString = NULL;

  if (length)
    {
      randomString = malloc (sizeof (char) * (length + 1));

      if (randomString)
	{
	  for (unsigned int n = 0; n < length; n++)
	    {
	      int key = rand () % (int) (sizeof (charset) - 1);
	      randomString[n] = charset[key];
	    }

	  randomString[length] = '\0';
	}
    }
  return randomString;
}

static char *
test_init (gs_grid_storage_t * gs, char *init_type, char **parameters)
{
  if (strstr (init_type, "Ref") != NULL)
    {
      char *nameRef = gen_random (8);
      gchar **tmp = NULL;

      hc_create_reference (gs, nameRef);

      if (strcmp (init_type, "Ref_linked") == 0)
	hc_link_service_to_reference (gs, nameRef, "meta2", &tmp);
      else if (strcmp (init_type, "Ref_params") == 0)
	{
	  hc_set_reference_property (gs, nameRef, parameters[0],
				     parameters[2]);
	  hc_set_reference_property (gs, nameRef, parameters[1],
				     parameters[3]);
	}

      return nameRef;
    }
  else
    return NULL;
}

static int
init_file ()
{
  FILE *file_test = fopen ("file_test.txt", "w");

  if (file_test != NULL)
    {
      fprintf (file_test, "This is random data to be dl");
      fclose (file_test);
      return 0;
    }
  else
    {
      fprintf (stderr,
	       "\nfile_test initialization has failed, tests won't be run \n");
      return 1;
    }

}

static gs_container_t *
container_init (gs_grid_storage_t * gs, char *nameCont)
{
  gs_error_t **err = NULL;
  gs_container_t *container =
    gs_get_storage_container_v2 (gs, nameCont, "SINGLE", "verspol_test", 1,
				 err);
  if (err != NULL)
    fprintf (stderr, "%s", err[0]->msg);
  return container;
}

static char **
parameters_init ()
{
  char **resp = (char **) malloc (4 * sizeof (char *));
  resp[0] = gen_random (6);
  resp[1] = gen_random (6);
  resp[2] = gen_random (10);
  resp[3] = gen_random (10);
  return resp;
}

static void
parameters_delete (char **params)
{
  for (int i = 0; i < 4; i++)
    free (params[i]);
  free (params);
}

static void
test_end (gs_grid_storage_t * gs, char *nameRef, gs_container_t * container)
{
  if (nameRef != NULL)
    {
      hc_unlink_reference_service (gs, nameRef, "meta2");
      hc_delete_reference (gs, nameRef);
    }
  if (container != NULL)
    {
      gs_container_free (container);
    }
}

static void
test_set_reference_property (gs_grid_storage_t * gs)
{
  char *nameRef = test_init (gs, "Ref", NULL);
  char **prop_array = parameters_init ();
  char *keys[] = { prop_array[0] };
  gchar **result = NULL;

  gs_error_t *err =
    hc_set_reference_property (gs, nameRef, prop_array[0], prop_array[2]);
  g_assert_true (err == NULL);

  hc_get_reference_property (gs, nameRef, keys, &result);
  g_assert_true (strcmp (result[0], prop_array[2]));

  parameters_delete (prop_array);
  test_end (gs, nameRef, NULL);
}

static void
test_get_reference_property (gs_grid_storage_t * gs)
{
  char **prop_array = parameters_init ();
  char *nameRef = test_init (gs, "Ref_params", prop_array);
  char *keys[] = { prop_array[0], prop_array[1] };
  gchar **result = NULL;

  gs_error_t *err = hc_get_reference_property (gs, nameRef, keys, &result);
  g_assert_true (err == NULL);

  g_assert_true ((strstr (result[0], prop_array[2]) != NULL
		  && strstr (result[1], prop_array[3]) != NULL)
		 || (strstr (result[0], prop_array[3]) != NULL
		     && strstr (result[1], prop_array[2]) != NULL));

  parameters_delete (prop_array);
  test_end (gs, nameRef, NULL);
}

static void
test_get_reference_property_wrong_key (gs_grid_storage_t * gs)	//to be improved
{
  char **prop_array = parameters_init ();
  char *nameRef = test_init (gs, "Ref_params", prop_array);
  char *keys = "key_error";
  gchar **result = NULL;

  hc_get_reference_property (gs, nameRef, &keys, &result);
  if (result != NULL)
    g_test_fail ();

  parameters_delete (prop_array);
  test_end (gs, nameRef, NULL);
}

static void
test_get_reference_property_void (gs_grid_storage_t * gs)
{
  char *nameRef = test_init (gs, "Ref", NULL);
  char *keys[] = { "Unknown_key" };
  gchar **result = NULL;

  gs_error_t *err = hc_get_reference_property (gs, nameRef, keys, &result);
  g_assert_true (err == NULL);
  g_assert_true (result[0] == NULL);

  test_end (gs, nameRef, NULL);
}

/*
static void
test_delete_reference_property (gs_grid_storage_t * gs)
{
  char **prop_array = parameters_init ();
  char *nameRef = test_init (gs, "Ref_params", prop_array);
  char *keys[] = { prop_array[0] };
  gchar **result = NULL;

  gs_error_t *err = hc_delete_reference_property (gs, nameRef, keys);

  if (err == NULL)
    {
      hc_get_reference_property (gs, nameRef, keys, &result);
      g_assert_true (result[0] == NULL);
    }
  else
    g_test_fail ();

  parameters_delete (prop_array);
  test_end (gs, nameRef, NULL);
}
*/
static void
test_set_container_storage_policy (gs_grid_storage_t * gs)
{
  char *nameRef = test_init (gs, "Ref_linked", NULL);
  char *nameCont = gen_random (7);
  gs_container_t *container = container_init (gs, nameCont);

  gs_error_t *err2 = hc_set_container_storage_policy (container, "TWOCOPIES");
  g_assert_true (err2 == NULL);

  test_end (gs, nameRef, container);
}

static void
test_set_container_storage_policy_wrong (gs_grid_storage_t * gs)	// to be improved
{
  char *nameRef = test_init (gs, "Ref_linked", NULL);
  char *nameCont = gen_random (7);
  gs_container_t *container = container_init (gs, nameCont);

  gs_error_t *err =
    hc_set_container_storage_policy (container, "Wrong_stgpol");
  if (err == NULL)
    g_test_fail ();

  test_end (gs, nameRef, container);
}

static void
test_set_container_quota (gs_grid_storage_t * gs)
{
  char *nameRef = test_init (gs, "Ref_linked", NULL);
  char *nameCont = gen_random (7);
  gs_container_t *container = container_init (gs, nameCont);

  gs_error_t *err2 = hc_set_container_quota (container, "test");
  g_assert_true (err2 == NULL);

  test_end (gs, nameRef, container);
}

static void
test_set_container_versioning (gs_grid_storage_t * gs)
{
  char *nameRef = test_init (gs, "Ref_linked", NULL);
  char *nameCont = gen_random (7);
  gs_container_t *container = container_init (gs, nameCont);

  gs_error_t *err = hc_set_container_versioning (container, "test");
  g_assert_true (err == NULL);

  test_end (gs, nameRef, container);
}

static void
test_del_container_versioning (gs_grid_storage_t * gs)
{
  char *nameRef = test_init (gs, "Ref_linked", NULL);
  char *nameCont = gen_random (7);
  gs_container_t *container = container_init (gs, nameCont);
  hc_set_container_versioning (container, "test");

  gs_error_t *err = hc_del_container_versioning (container);
  g_assert_true (err == NULL);

  test_end (gs, nameRef, container);
}

static void
test_del_container_versioning_void (gs_grid_storage_t * gs)
{
  char *nameRef = test_init (gs, "Ref_linked", NULL);
  char *nameCont = gen_random (7);
  gs_container_t *container = container_init (gs, nameCont);

  gs_error_t *err = hc_del_container_versioning (container);
  g_assert_true (err == NULL);

  test_end (gs, nameRef, container);
}

static void
test_set_content_storage_policy (gs_grid_storage_t * gs)
{
  gs_error_t **err = NULL;

  char *nameRef = test_init (gs, "Ref_linked", NULL);
  char *nameCont = gen_random (7);
  gs_container_t *container = container_init (gs, nameCont);
  hc_ul_content_from_file (gs, nameCont, "Content", "file_test.txt",
			   err);
  gs_content_t *content =
    gs_get_content_from_path (container, "Content", err);

  hc_set_content_storage_policy (container, "Content", "TWOCOPIES", err);
  g_assert_true (err == NULL);

  gs_content_free (content);
  test_end (gs, nameRef, container);
}

static void
test_set_content_storage_policy_bad_path (gs_grid_storage_t * gs)	// to be improved
{
  gs_error_t **err = NULL;

  char *nameRef = test_init (gs, "Ref_linked", NULL);
  char *nameCont = gen_random (7);
  gs_container_t *container = container_init (gs, nameCont);

  hc_set_content_storage_policy (container, "Content", "TWOCOPIES", err);
  if (err == NULL)
    g_test_fail ();

  test_end (gs, nameRef, container);
}

static void
test_set_content_storage_policy_wrong (gs_grid_storage_t * gs)	// to be improved
{
  gs_error_t **err = NULL;

  char *nameRef = test_init (gs, "Ref_linked", NULL);
  char *nameCont = gen_random (7);
  gs_container_t *container = container_init (gs, nameCont);
  hc_ul_content_from_file (gs, nameCont, "Content", "file_test.txt",
			   err);
  gs_content_t *content =
    gs_get_content_from_path (container, "Content", err);

  hc_set_content_storage_policy (container, "Content", "Wrong_stgpol", err);
  if (err == NULL)
    g_test_fail ();

  gs_content_free (content);
  test_end (gs, nameRef, container);
}

static void
test_set_content_property (gs_grid_storage_t * gs)
{
  gs_error_t **err = NULL;
  gchar **result = NULL;

  char *nameRef = test_init (gs, "Ref_linked", NULL);
  char *nameCont = gen_random (7);
  gs_container_t *container = container_init (gs, nameCont);
  hc_ul_content_from_file (gs, nameCont, "Content", "file_test.txt",
			   err);
  gs_content_t *content =
    gs_get_content_from_path (container, "Content", err);

  char *props[] = { "key1=value1", "key2=value2" };

  hc_set_content_property (content, props, err);
  g_assert_true (err == NULL);

  hc_get_content_properties (content, &result, err);
  g_assert_true ((strcmp (result[0], "key1=value1") == 0
		  && strcmp (result[1], "key2=value2") == 0)
		 ||
		 (strcmp (result[1], "key1=value1") == 0
		  && strcmp (result[0], "key2=value2") == 0));

  gs_content_free (content);
  test_end (gs, nameRef, container);
}

static void
test_set_content_property_wrong (gs_grid_storage_t * gs)	// to be improved
{
  gs_error_t **err = NULL;
  gchar **result = NULL;

  char *nameRef = test_init (gs, "Ref_linked", NULL);
  char *nameCont = gen_random (7);
  gs_container_t *container = container_init (gs, nameCont);
  hc_ul_content_from_file (gs, nameCont, "Content", "file_test.txt",
			   err);
  gs_content_t *content =
    gs_get_content_from_path (container, "Content", err);

  char *props[] = { "wrong_property" };

  hc_set_content_property (content, props, err);
  if (err == NULL)
    g_test_fail ();

  hc_get_content_properties (content, &result, err);

  gs_content_free (content);
  test_end (gs, nameRef, container);
}

static void
test_set_content_property_again (gs_grid_storage_t * gs)
{
  gs_error_t **err = NULL;
  gchar **result = NULL;

  char *nameRef = test_init (gs, "Ref_linked", NULL);
  char *nameCont = gen_random (7);
  gs_container_t *container = container_init (gs, nameCont);
  hc_ul_content_from_file (gs, nameCont, "Content", "file_test.txt",
			   err);
  gs_content_t *content =
    gs_get_content_from_path (container, "Content", err);

  char *props = "key1=value1";
  char *props2 = "key1=value2";

  hc_set_content_property (content, &props, err);
  hc_set_content_property (content, &props2, err);
  g_assert_true (err == NULL);

  hc_get_content_properties (content, &result, err);
  if (strcmp (result[0], "key1=value2"))
    g_test_fail ();

  gs_content_free (content);
  test_end (gs, nameRef, container);
}

static void
test_get_content_properties (gs_grid_storage_t * gs)
{
  gs_error_t **err = NULL;
  gchar **result = NULL;

  char *nameRef = test_init (gs, "Ref_linked", NULL);
  char *nameCont = gen_random (7);
  gs_container_t *container = container_init (gs, nameCont);
  hc_ul_content_from_file (gs, nameCont, "Content", "file_test.txt",
			   err);
  gs_content_t *nameContent =
    gs_get_content_from_path (container, "Content", err);

  hc_get_content_properties (nameContent, &result, err);
  g_assert_true (err == NULL);

  gs_content_free (nameContent);
  test_end (gs, nameRef, container);
}

/*
static void
test_delete_content_property (gs_grid_storage_t * gs)
{
  gs_error_t **err = NULL;
  gchar **result = NULL;

  char *nameRef = test_init (gs, "Ref_linked", NULL);
  char *nameCont = gen_random (7);
  gs_container_t *container = container_init (gs, nameCont);
  hc_ul_content_from_file (gs, nameCont, "Content", "file_test.txt",
			   err);
  gs_content_t *nameContent =
    gs_get_content_from_path (container, "Content", err);

  char *props[] = { "key1=value1", "key2=value2" };
  char *propDel = "key1";
  hc_set_content_property (nameContent, props, err);

  hc_delete_content_property (nameContent, &propDel, err);
  g_assert_true (err == NULL);

  hc_get_content_properties (nameContent, &result, err);
  g_assert_true (err == NULL);
  if (result == NULL)
    g_test_fail ();
  else
    g_assert_true (strcmp (result[0], "key2=value2") == 0);

  gs_content_free (nameContent);
  test_end (gs, nameRef, container);
}
*/
static void
test_copy_content (gs_grid_storage_t * gs)
{
  gs_error_t **err = NULL;

  char *nameRef = test_init (gs, "Ref_linked", NULL);
  char *nameCont = gen_random (7);
  gs_container_t *container = container_init (gs, nameCont);

  hc_ul_content_from_file (gs, nameCont, "Content", "file_test.txt",
			   err);
  gs_content_t *nameContent =
    gs_get_content_from_path (container, "Content", err);

  hc_copy_content (container, "Content", "Content_copy", err);
  g_assert_true (err == NULL);

  gs_content_t *nameContent2 =
    gs_get_content_from_path (container, "Content_copy", err);
  g_assert_true (nameContent != NULL);

  gs_content_free (nameContent);
  gs_content_free (nameContent2);
  test_end (gs, nameRef, container);
}

int
main (int argc, char **argv)
{

  int i = init_file ();

  if (!i)
    {
      HC_TEST_INIT (argc, argv);

      const char *ns = "NS";

      gs_error_t *err = NULL;
      gs_grid_storage_t *gs = gs_grid_storage_init (ns, &err);
      if (!gs)
	{
	  fprintf (stderr, "OIO init error : (%d) %s\n", err->code, err->msg);
	  _gs_error_clear (&err);
	  abort ();
	}

      g_test_set_nonfatal_assertions ();

      g_test_add_data_func ("/client/lib/prop/set_ref_prop", gs,
			    (GTestDataFunc) test_set_reference_property);

      g_test_add_data_func ("/client/lib/prop/get_ref_prop", gs,
			    (GTestDataFunc) test_get_reference_property);
      g_test_add_data_func ("/client/lib/prop/get_ref_prop_v", gs,
			    (GTestDataFunc) test_get_reference_property_void);
      g_test_add_data_func ("/client/lib/prop/get_ref_prop_w", gs,
			    (GTestDataFunc)
			    test_get_reference_property_wrong_key);

      fprintf (stderr, "hc_delete_reference_property to be stabilized \n");
//  g_test_add_data_func ("/client/lib/prop/del_ref_prop", gs,
//                      (GTestDataFunc) test_delete_reference_property);

      g_test_add_data_func ("/client/lib/prop/set_cont_strpol", gs,
			    (GTestDataFunc)
			    test_set_container_storage_policy);
      g_test_add_data_func ("/client/lib/prop/set_cont_strpol_wrong", gs,
			    (GTestDataFunc)
			    test_set_container_storage_policy_wrong);

      g_test_add_data_func ("/client/lib/prop/set_cont_quot", gs,
			    (GTestDataFunc) test_set_container_quota);

      g_test_add_data_func ("/client/lib/prop/set_cont_vers", gs,
			    (GTestDataFunc) test_set_container_versioning);

      g_test_add_data_func ("/client/lib/prop/del_cont_vers", gs,
			    (GTestDataFunc) test_del_container_versioning);
      g_test_add_data_func ("/client/lib/prop/del_cont_vers_v", gs,
			    (GTestDataFunc)
			    test_del_container_versioning_void);

      g_test_add_data_func ("/client/lib/prop/set_content_strpol", gs,
			    (GTestDataFunc) test_set_content_storage_policy);
      g_test_add_data_func ("/client/lib/prop/set_content_strpol_w_path", gs,
			    (GTestDataFunc)
			    test_set_content_storage_policy_bad_path);
      g_test_add_data_func ("/client/lib/prop/set_content_strpol_w", gs,
			    (GTestDataFunc)
			    test_set_content_storage_policy_wrong);

      g_test_add_data_func ("/client/lib/prop/get_content_prop", gs,
			    (GTestDataFunc) test_get_content_properties);

      g_test_add_data_func ("/client/lib/prop/set_content_prop", gs,
			    (GTestDataFunc) test_set_content_property);
      g_test_add_data_func ("/client/lib/prop/set_content_prop_w", gs,
			    (GTestDataFunc) test_set_content_property_wrong);
      g_test_add_data_func ("/client/lib/prop/set_content_prop_again", gs,
			    (GTestDataFunc) test_set_content_property_again);

      fprintf (stderr, "hc_delete_content_property to be stabilized \n");
//  g_test_add_data_func ("/client/lib/prop/del_content_prop", gs,
//                      (GTestDataFunc) test_delete_content_property);

      g_test_add_data_func ("/client/lib/prop/copy_content", gs,
			    (GTestDataFunc) test_copy_content);

      int success = g_test_run ();

      remove ("file_test.txt");

      gs_grid_storage_free (gs);
      gs = NULL;

      return success;
    }
  else
    return 0;
}
