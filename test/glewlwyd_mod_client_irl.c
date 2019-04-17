/* Public domain, no copyright. Use at your own risk. */

/**
 * This test is used to validate one client backend module that will be created upon start and deleted after
 * The client backend must be in write mode
 * This backend must have the following data-format available:
 *
 * data-format: {
 *   data1: {multiple: false, read: true, write: true, profile-read: false, profile-write: false}
 *   data2: {multiple: true, read: true, write: true, profile-read: true, profile-write: false}
 *   data3: {multiple: false, read: false, write: false, profile-read: true, profile-write: true}
 *   data4: {multiple: true, read: false, write: false, profile-read: true, profile-write: true}
 * }
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <check.h>
#include <ulfius.h>
#include <orcania.h>
#include <yder.h>

#include "unit-tests.h"
#include "../src/glewlwyd-common.h"

#define SERVER_URI "http://localhost:4593/api"
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"
#define MOD_NAME "mod_irl"
#define CLIENT_PASSWORD "password"
#define CLIENT_NAME "Client test"
#define CLIENT_DESCRIPTION "Client test description"
#define CLIENT_SCOPE_1 "scope1"
#define CLIENT_SCOPE_2 "scope2"

struct _u_request admin_req;
json_t * j_params;
char * client_id = NULL, * client_id_case = NULL, * client_id_upper = NULL, * client_id_pattern = NULL;

START_TEST(test_glwd_mod_client_irl_module_add)
{
  char * url = SERVER_URI "/mod/client";
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_params, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_mod_client_irl_add_error_param)
{
  char * url = msprintf("%s/client?source=" MOD_NAME, SERVER_URI);
  json_t * j_parameters = json_pack("{ss}", "error", "error");

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("[{ss}]", "client_id", "test");
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  j_parameters = json_pack("{si}", "client_id", 42);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  
  o_free(url);
}
END_TEST

START_TEST(test_glwd_mod_client_irl_client_add)
{
  json_t * j_client = json_pack("{sssssssss[ss]so}", "client_id", client_id, "password", CLIENT_PASSWORD, "name", CLIENT_NAME, "description", CLIENT_DESCRIPTION, "scope", CLIENT_SCOPE_1, CLIENT_SCOPE_2, "confidential", json_true());
  char * url = SERVER_URI "/client?source=" MOD_NAME;
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_client, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_client);
}
END_TEST

START_TEST(test_glwd_mod_client_irl_client_add_case)
{
  json_t * j_client = json_pack("{sssssssss[ss]so}", "client_id", client_id_case, "password", CLIENT_PASSWORD, "name", CLIENT_NAME, "description", CLIENT_DESCRIPTION, "scope", CLIENT_SCOPE_1, CLIENT_SCOPE_2, "confidential", json_true());
  char * url = SERVER_URI "/client?source=" MOD_NAME;
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_client, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_client);
}
END_TEST

START_TEST(test_glwd_mod_client_irl_add_already_present)
{
  char * url = msprintf("%s/client?source=" MOD_NAME, SERVER_URI);
  json_t * j_parameters =json_pack("{sssssssss[ss]so}", "client_id", client_id, "password", CLIENT_PASSWORD, "name", CLIENT_NAME, "description", CLIENT_DESCRIPTION, "scope", CLIENT_SCOPE_1, CLIENT_SCOPE_2, "confidential", json_true());
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  o_free(url);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_mod_client_irl_add_case_already_present)
{
  char * url = msprintf("%s/client?source=" MOD_NAME, SERVER_URI);
  json_t * j_parameters = json_pack("{sssssssss[ss]so}", "client_id", client_id_upper, "password", CLIENT_PASSWORD, "name", CLIENT_NAME, "description", CLIENT_DESCRIPTION, "scope", CLIENT_SCOPE_1, CLIENT_SCOPE_2, "confidential", json_true());
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  o_free(url);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_mod_client_irl_delete_error)
{
  char * url = msprintf("%s/client/error?source=" MOD_NAME, SERVER_URI);

  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", url, NULL, NULL, NULL, NULL, 404, NULL, NULL, NULL), 1);
  o_free(url);
}
END_TEST

START_TEST(test_glwd_mod_client_irl_client_get_list)
{
  json_t * j_client = json_pack("{sssssssss[ss]so}", "client_id", client_id, "password", CLIENT_PASSWORD, "name", CLIENT_NAME, "description", CLIENT_DESCRIPTION, "scope", CLIENT_SCOPE_1, CLIENT_SCOPE_2, "confidential", json_true());
  char * url = SERVER_URI "/client?source=" MOD_NAME;
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_client, NULL, NULL), 1);
  json_decref(j_client);
}
END_TEST

START_TEST(test_glwd_mod_client_irl_client_get)
{
  json_t * j_client = json_pack("{sssssssss[ss]so}", "client_id", client_id, "password", CLIENT_PASSWORD, "name", CLIENT_NAME, "description", CLIENT_DESCRIPTION, "scope", CLIENT_SCOPE_1, CLIENT_SCOPE_2, "confidential", json_true());
  char * url = msprintf(SERVER_URI "/client/%s?source=" MOD_NAME, client_id);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_client, NULL, NULL), 1);
  json_decref(j_client);
  o_free(url);
}
END_TEST

START_TEST(test_glwd_mod_client_irl_client_get_case)
{
  json_t * j_client = json_pack("{sssssssss[ss]so}", "client_id", client_id_case, "password", CLIENT_PASSWORD, "name", CLIENT_NAME, "description", CLIENT_DESCRIPTION, "scope", CLIENT_SCOPE_1, CLIENT_SCOPE_2, "confidential", json_true());
  char * url = msprintf(SERVER_URI "/client/%s?source=" MOD_NAME, client_id_upper);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_client, NULL, NULL), 1);
  json_decref(j_client);
  o_free(url);
}
END_TEST

START_TEST(test_glwd_mod_client_irl_client_update)
{
  json_t * j_client = json_pack("{sssss[ss]}", "name", CLIENT_NAME "-updated", "email", CLIENT_DESCRIPTION "-updated", "scope", CLIENT_SCOPE_1, CLIENT_SCOPE_2);
  char * url = msprintf(SERVER_URI "/client/%s?source=" MOD_NAME, client_id);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", url, NULL, NULL, j_client, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_client);
  o_free(url);
}
END_TEST

START_TEST(test_glwd_mod_client_irl_client_update_case)
{
  json_t * j_client = json_pack("{sssss[ss]}", "name", CLIENT_NAME "-updated", "email", CLIENT_DESCRIPTION "-updated", "scope", CLIENT_SCOPE_1, CLIENT_SCOPE_2);
  char * url = msprintf(SERVER_URI "/client/%s?source=" MOD_NAME, client_id_upper);
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", url, NULL, NULL, j_client, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_client);
  o_free(url);
}
END_TEST

START_TEST(test_glwd_mod_client_irl_client_get_updated)
{
  json_t * j_client = json_pack("{sssssssss[ss]}", "client_id", client_id, "name", CLIENT_NAME "-updated", "email", CLIENT_DESCRIPTION "-updated", "source", MOD_NAME, "scope", CLIENT_SCOPE_1, CLIENT_SCOPE_2);
  char * url = msprintf(SERVER_URI "/client/%s?source=" MOD_NAME, client_id);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_client, NULL, NULL), 1);
  json_decref(j_client);
  o_free(url);
}
END_TEST

START_TEST(test_glwd_mod_client_irl_client_get_case_updated)
{
  json_t * j_client = json_pack("{sssssssss[ss]}", "client_id", client_id_upper, "name", CLIENT_NAME "-updated", "email", CLIENT_DESCRIPTION "-updated", "source", MOD_NAME, "scope", CLIENT_SCOPE_1, CLIENT_SCOPE_2);
  char * url = msprintf(SERVER_URI "/client/%s?source=" MOD_NAME, client_id_case);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_client, NULL, NULL), 1);
  json_decref(j_client);
  o_free(url);
}
END_TEST

START_TEST(test_glwd_mod_client_irl_client_delete)
{
  char * url = msprintf(SERVER_URI "/client/%s?source=" MOD_NAME, client_id);
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  o_free(url);
}
END_TEST

START_TEST(test_glwd_mod_client_irl_client_delete_case)
{
  char * url = msprintf(SERVER_URI "/client/%s?source=" MOD_NAME, client_id_upper);
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  o_free(url);
}
END_TEST

START_TEST(test_glwd_mod_client_irl_client_large_list_add)
{
  int i;
  char * cur_client_id;
  json_t * j_client;
  
  for (i=0; i < 100; i++) {
    cur_client_id = msprintf("%s%d", client_id_pattern, i);
    j_client = json_pack("{sssssssss[ss]}", "client_id", cur_client_id, "password", CLIENT_PASSWORD, "name", CLIENT_NAME, "email", CLIENT_DESCRIPTION, "scope", CLIENT_SCOPE_1, CLIENT_SCOPE_2);
    ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client?source=" MOD_NAME, NULL, NULL, j_client, NULL, 200, NULL, NULL, NULL), 1);
    json_decref(j_client);
    o_free(cur_client_id);
  }
}
END_TEST

START_TEST(test_glwd_mod_client_irl_client_large_list_get)
{
  json_t * j_client;
  struct _u_response resp;
  
  ulfius_init_response(&resp);
  
  o_free(admin_req.http_verb);
  o_free(admin_req.http_url);
  admin_req.http_verb = strdup("GET");
  admin_req.http_url = msprintf(SERVER_URI "/client?source=" MOD_NAME "&pattern=%s", client_id_pattern);
  ck_assert_int_eq(ulfius_send_http_request(&admin_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  j_client = ulfius_get_json_body_response(&resp, NULL);
  ck_assert_int_eq(json_array_size(j_client), 100);
  json_decref(j_client);
  ulfius_clean_response(&resp);
  
}
END_TEST

START_TEST(test_glwd_mod_client_irl_client_large_list_delete)
{
  int i;
  char * url;
  
  for (i=0; i < 100; i++) {
    url = msprintf(SERVER_URI "/client/%s%d?source=" MOD_NAME, client_id_pattern, i);
    ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
    o_free(url);
  }
}
END_TEST

START_TEST(test_glwd_mod_client_irl_module_delete)
{
  char * url = SERVER_URI "/mod/client/" MOD_NAME;
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd client irl");
  tc_core = tcase_create("test_glwd_mod_client_irl");
  tcase_add_test(tc_core, test_glwd_mod_client_irl_module_add);
  tcase_add_test(tc_core, test_glwd_mod_client_irl_client_add);
  tcase_add_test(tc_core, test_glwd_mod_client_irl_client_add_case);
  tcase_add_test(tc_core, test_glwd_mod_client_irl_add_error_param);
  tcase_add_test(tc_core, test_glwd_mod_client_irl_add_already_present);
  tcase_add_test(tc_core, test_glwd_mod_client_irl_add_case_already_present);
  tcase_add_test(tc_core, test_glwd_mod_client_irl_delete_error);
  tcase_add_test(tc_core, test_glwd_mod_client_irl_client_get_list);
  tcase_add_test(tc_core, test_glwd_mod_client_irl_client_get);
  tcase_add_test(tc_core, test_glwd_mod_client_irl_client_get_case);
  tcase_add_test(tc_core, test_glwd_mod_client_irl_client_update);
  tcase_add_test(tc_core, test_glwd_mod_client_irl_client_update_case);
  tcase_add_test(tc_core, test_glwd_mod_client_irl_client_get_updated);
  tcase_add_test(tc_core, test_glwd_mod_client_irl_client_get_case_updated);
  tcase_add_test(tc_core, test_glwd_mod_client_irl_client_delete);
  tcase_add_test(tc_core, test_glwd_mod_client_irl_client_delete_case);
  tcase_add_test(tc_core, test_glwd_mod_client_irl_client_large_list_add);
  tcase_add_test(tc_core, test_glwd_mod_client_irl_client_large_list_get);
  tcase_add_test(tc_core, test_glwd_mod_client_irl_client_large_list_delete);
  tcase_add_test(tc_core, test_glwd_mod_client_irl_module_delete);
  tcase_set_timeout(tc_core, 90);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed = 0, i;
  Suite *s;
  SRunner *sr;
  struct _u_request auth_req;
  struct _u_response auth_resp;
  int res, do_test = 0;
  json_t * j_body;
  char * cookie;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  srand(time(NULL));
  j_params = json_load_file(argv[1], JSON_DECODE_ANY, NULL);
  ulfius_init_request(&admin_req);
  if (j_params != NULL) {
    // Getting a valid session id for authenticated http requests
    ulfius_init_request(&auth_req);
    ulfius_init_response(&auth_resp);
    auth_req.http_verb = strdup("POST");
    auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
    j_body = json_pack("{ssss}", "username", ADMIN_USERNAME, "password", ADMIN_PASSWORD);
    ulfius_set_json_body_request(&auth_req, j_body);
    json_decref(j_body);
    res = ulfius_send_http_request(&auth_req, &auth_resp);
    if (res == U_OK && auth_resp.status == 200) {
      if (auth_resp.nb_cookies) {
        cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value);
        u_map_put(admin_req.map_header, "Cookie", cookie);
        o_free(cookie);
        client_id = msprintf("client_irl%4d", (rand()%1000));
        client_id_case = msprintf("client_irl_case%4d", (rand()%1000));
        client_id_upper = o_malloc(o_strlen(client_id_case) + sizeof(char));
        for (i=0; i<o_strlen(client_id_case); i++) {
          client_id_upper[i] = toupper(client_id_case[i]);
        }
        client_id_upper[o_strlen(client_id_case)] = '\0';
        client_id_pattern = msprintf("client_irl_list_%d_", (rand()%1000));
        do_test = 1;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication");
    }
    ulfius_clean_response(&auth_resp);
    ulfius_clean_request(&auth_req);
    
    if (do_test) {
      s = glewlwyd_suite();
      sr = srunner_create(s);

      srunner_run_all(sr, CK_VERBOSE);
      number_failed = srunner_ntests_failed(sr);
      srunner_free(sr);
    }
    
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error reading parameters file %s", argv[1]);
  }
  json_decref(j_params);
  ulfius_clean_request(&admin_req);
  y_close_logs();
  o_free(client_id);
  o_free(client_id_case);
  o_free(client_id_upper);
  o_free(client_id_pattern);
  
  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
