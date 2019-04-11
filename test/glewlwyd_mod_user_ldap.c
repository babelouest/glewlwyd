/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <check.h>
#include <ulfius.h>
#include <orcania.h>
#include <yder.h>

#include "unit-tests.h"
#include "../src/glewlwyd-common.h"

void * cls;
struct config_module config;
extern int cur_state;

static json_t * glewlwyd_module_callback_get_user(struct config_module * config, const char * username) {
  return NULL;
}

static int glewlwyd_module_callback_set_user(struct config_module * config, const char * username, json_t * j_user) {
  return G_OK;
}

static int glewlwyd_module_callback_check_user_password(struct config_module * config, const char * username, const char * password) {
  return G_OK;
}

START_TEST(test_glwd_mod_user_ldap_load)
{
  json_t * j_load = user_module_load(&config);
  ck_assert_ptr_ne(j_load, NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_load, "result")), G_OK);
  ck_assert_int_eq(json_is_string(json_object_get(j_load, "name")), 1);
  ck_assert_int_eq(json_is_string(json_object_get(j_load, "display_name")), 1);
  ck_assert_int_eq(json_is_string(json_object_get(j_load, "description")), 1);
  ck_assert_int_eq(json_is_object(json_object_get(j_load, "parameters")), 1);
  
  json_decref(j_load);
}
END_TEST

START_TEST(test_glwd_mod_user_ldap_unload)
{
  ck_assert_int_eq(user_module_unload(&config), G_OK);
}
END_TEST

START_TEST(test_glwd_mod_user_ldap_init)
{
  json_t * j_params = NULL;
  void * my_cls = NULL;
  
  j_params = json_pack("s", "error");
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("[s]", "error");
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{}");
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{ss}", "error", "error");
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{so}", "uri", json_false());
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{ssso}", "uri", "ldap://localhost/", "bind-dn", json_false());
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{ssssso}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", json_false());
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{ssssssso}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", json_false());
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{ssssssssso}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", json_false());
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{ssssssssso}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", json_false());
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{ssssssssssssso}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", "objectClass=*", "username-property", "cn", "scope-property", json_false());
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{ssssssssssss}", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", "objectClass=*", "username-property", "cn", "scope-property", "o");
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{ssssssssssss}", "uri", "ldap://localhost/", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", "objectClass=*", "username-property", "cn", "scope-property", "o");
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{ssssssssssss}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "base-search", "dn=base,dc=localhost", "filter", "objectClass=*", "username-property", "cn", "scope-property", "o");
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{ssssssssssss}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "filter", "objectClass=*", "username-property", "cn", "scope-property", "o");
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{ssssssssssss}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "username-property", "cn", "scope-property", "o");
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{ssssssssssss}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", "objectClass=*", "scope-property", "o");
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{ssssssssssss}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", "objectClass=*", "username-property", "cn");
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{sssssssssssssss{s[]}}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", "objectClass=*", "username-property", "cn", "scope-property", "o", "data-format", "data1");
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{sssssssssssssss{s{ss}}}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", "objectClass=*", "username-property", "cn", "scope-property", "o", "data-format", "data1", "multiple", "error");
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{sssssssssssssss{s{soss}}}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", "objectClass=*", "username-property", "cn", "scope-property", "o", "data-format", "data1", "multiple", json_false(), "read", "error");
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{sssssssssssssss{s{sososs}}}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", "objectClass=*", "username-property", "cn", "scope-property", "o", "data-format", "data1", "multiple", json_false(), "read", json_false(), "write", "error");
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{sssssssssssssss{s{sosososs}}}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", "objectClass=*", "username-property", "cn", "scope-property", "o", "data-format", "data1", "multiple", json_false(), "read", json_false(), "write", json_false(), "profile-read", "error");
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{sssssssssssssss{s{sososososs}}}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", "objectClass=*", "username-property", "cn", "scope-property", "o", "data-format", "data1", "multiple", json_false(), "read", json_false(), "write", json_false(), "profile-read", json_false(), "profile-write", "error");
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{ssssssssssssssss}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", "objectClass=*", "username-property", "cn", "scope-property", "o", "page-size", "error");
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{sssssssssssssssiso}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", "objectClass=*", "username-property", "cn", "scope-property", "o", "page-size", 50, "search-scope", json_false());
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{sssssssssssssssissss}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", "objectClass=*", "username-property", "cn", "scope-property", "o", "page-size", 50, "search-scope", "subtree", "scope-match", "error");
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{sssssssssssssssisss{ssssss}}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", "objectClass=*", "username-property", "cn", "scope-property", "o", "page-size", 50, "search-scope", "subtree", "scope-match", "ldap-value", "ldap-scope1", "scope-value", "scope1", "match", "equals");
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{sssssssssssssssisss[{sossss}]}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", "objectClass=*", "username-property", "cn", "scope-property", "o", "page-size", 50, "search-scope", "subtree", "scope-match", "ldap-value", json_false(), "scope-value", "scope1", "match", "equals");
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{sssssssssssssssisss[{sssoss}]}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", "objectClass=*", "username-property", "cn", "scope-property", "o", "page-size", 50, "search-scope", "subtree", "scope-match", "ldap-value", "ldap-scope1", "scope-value", json_false(), "match", "equals");
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{sssssssssssssssisss[{ssssso}]}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", "objectClass=*", "username-property", "cn", "scope-property", "o", "page-size", 50, "search-scope", "subtree", "scope-match", "ldap-value", "ldap-scope1", "scope-value", "scope1", "match", json_false());
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{sssssssssssssssisss[{ssssso}]}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", "objectClass=*", "username-property", "cn", "scope-property", "o", "page-size", 50, "search-scope", "subtree", "scope-match", "ldap-value", "ldap-scope1", "scope-value", "scope1", "match", "error");
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{sssssssssssssssisss[{ssssso}]so}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", "objectClass=*", "username-property", "cn", "scope-property", "o", "page-size", 50, "search-scope", "subtree", "scope-match", "ldap-value", "ldap-scope1", "scope-value", "scope1", "match", "equals", "name-property", json_false());
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{sssssssssssssssisss[{ssssso}]ssso}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", "objectClass=*", "username-property", "cn", "scope-property", "o", "page-size", 50, "search-scope", "subtree", "scope-match", "ldap-value", "ldap-scope1", "scope-value", "scope1", "match", "equals", "name-property", "sn", "email-property", json_false());
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{sssssssssssssssisss[{ssssso}]ssssso}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", "objectClass=*", "username-property", "cn", "scope-property", "o", "page-size", 50, "search-scope", "subtree", "scope-match", "ldap-value", "ldap-scope1", "scope-value", "scope1", "match", "equals", "name-property", "sn", "email-property", "mail", "rdn-property", json_false());
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{sssssssssssssssisss[{ssssso}]ssssssso}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", "objectClass=*", "username-property", "cn", "scope-property", "o", "page-size", 50, "search-scope", "subtree", "scope-match", "ldap-value", "ldap-scope1", "scope-value", "scope1", "match", "equals", "name-property", "sn", "email-property", "mail", "rdn-property", ",dc=localhost", "password-property", json_false());
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{sssssssssssssssisss[{ssssso}]ssssssssso}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", "objectClass=*", "username-property", "cn", "scope-property", "o", "page-size", 50, "search-scope", "subtree", "scope-match", "ldap-value", "ldap-scope1", "scope-value", "scope1", "match", "equals", "name-property", "sn", "email-property", "mail", "rdn-property", ",dc=localhost", "password-property", "password", "password-algorithm", json_false());
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{sssssssssssssssisss[{ssssso}]ssssssssss}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", "objectClass=*", "username-property", "cn", "scope-property", "o", "page-size", 50, "search-scope", "subtree", "scope-match", "ldap-value", "ldap-scope1", "scope-value", "scope1", "match", "equals", "name-property", "sn", "email-property", "mail", "rdn-property", ",dc=localhost", "password-property", "password", "password-algorithm", "error");
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{sssssssssssssssisss[{ssssso}]ssssssssssso}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", "objectClass=*", "username-property", "cn", "scope-property", "o", "page-size", 50, "search-scope", "subtree", "scope-match", "ldap-value", "ldap-scope1", "scope-value", "scope1", "match", "equals", "name-property", "sn", "email-property", "mail", "rdn-property", ",dc=localhost", "password-property", "password", "password-algorithm", "PLAIN", "object-class", json_false());
  ck_assert_int_ne(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_eq(my_cls, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{ssssssssssssss}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", "objectClass=*", "username-property", "cn", "scope-property", "o");
  ck_assert_int_eq(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_ne(my_cls, NULL);
  ck_assert_int_eq(user_module_close(&config, my_cls), G_OK);
  json_decref(j_params);

}
END_TEST

START_TEST(test_glwd_mod_user_ldap_close)
{
  ck_assert_int_eq(user_module_close(&config, NULL), G_ERROR_PARAM);
  
  void * my_cls = NULL;
  j_params = json_pack("{ssssssssssssss}", "uri", "ldap://localhost/", "bind-dn", "dn=test,dc=localhost", "bind-password", "password", "base-search", "dn=base,dc=localhost", "filter", "objectClass=*", "username-property", "cn", "scope-property", "o");
  ck_assert_int_eq(user_module_init(&config, j_params, &my_cls), G_OK);
  ck_assert_ptr_ne(cls, NULL);
  json_decref(j_params);
  
  ck_assert_int_eq(user_module_close(&config, my_cls), G_OK);
}
END_TEST

START_TEST(test_glwd_mod_user_ldap_count_total)
{
  cur_state = 0;
  ck_assert_int_eq(user_module_count_total(&config, NULL, cls), 0);
  cur_state = 1;
  ck_assert_int_eq(user_module_count_total(&config, NULL, cls), 0);
  cur_state = 2;
  ck_assert_int_eq(user_module_count_total(&config, NULL, cls), 0);
  cur_state = 3;
  ck_assert_int_eq(user_module_count_total(&config, NULL, cls), 0);
  cur_state = 4;
  ck_assert_int_eq(user_module_count_total(&config, NULL, cls), 2);
  cur_state = 5;
  ck_assert_int_eq(user_module_count_total(&config, "pattern", cls), 0);
}
END_TEST

START_TEST(test_glwd_mod_user_ldap_get_list)
{
  json_t * j_result;
  
  cur_state = 3;
  j_result = user_module_get_list(&config, NULL, 0, 100, cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_array_size(j_result), 2);
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "username")), "user1");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "name")), "Dave Lopper 1");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "email")), "dave1@glewlwyd");
  ck_assert_ptr_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "enabled")), json_true());
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(json_array_get(j_result, 0), "scope"), 0)), "g_profile");
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(json_array_get(j_result, 0), "scope"), 1)), "scope1");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "data1")), "value1");
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(json_array_get(j_result, 0), "data2"), 0)), "value2");
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(json_array_get(j_result, 0), "data2"), 1)), "value3");
  ck_assert_int_eq(json_array_size(json_object_get(json_array_get(j_result, 0), "data2")), 2);
  ck_assert_ptr_eq(json_object_get(json_array_get(j_result, 0), "data3"), NULL);
  ck_assert_ptr_eq(json_object_get(json_array_get(j_result, 0), "data4"), NULL);
  
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 1), "username")), "user2");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 1), "name")), "Dave Lopper 2");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 1), "email")), "dave2@glewlwyd");
  ck_assert_ptr_eq(json_string_value(json_object_get(json_array_get(j_result, 1), "enabled")), json_false());
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(json_array_get(j_result, 1), "scope"), 0)), "g_profile");
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(json_array_get(j_result, 1), "scope"), 1)), "scope2");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "data1")), "value7");
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(json_array_get(j_result, 0), "data2"), 0)), "value8");
  ck_assert_int_eq(json_array_size(json_object_get(json_array_get(j_result, 0), "data2")), 1);
  ck_assert_ptr_eq(json_object_get(json_array_get(j_result, 0), "data3"), NULL);
  ck_assert_ptr_eq(json_object_get(json_array_get(j_result, 0), "data4"), NULL);
  json_decref(j_result);
  
  cur_state = 4;
  j_result = user_module_get_list(&config, "user1", 0, 100, cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_array_size(j_result), 1);
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "username")), "user1");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "name")), "Dave Lopper 1");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "email")), "dave1@glewlwyd");
  ck_assert_ptr_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "enabled")), json_true());
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(json_array_get(j_result, 0), "scope"), 0)), "g_profile");
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(json_array_get(j_result, 0), "scope"), 1)), "scope1");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "data1")), "value1");
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(json_array_get(j_result, 0), "data2"), 0)), "value2");
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(json_array_get(j_result, 0), "data2"), 1)), "value3");
  ck_assert_int_eq(json_array_size(json_object_get(json_array_get(j_result, 0), "data2")), 2);
  ck_assert_ptr_eq(json_object_get(json_array_get(j_result, 0), "data3"), NULL);
  ck_assert_ptr_eq(json_object_get(json_array_get(j_result, 0), "data4"), NULL);
  json_decref(j_result);
  
  cur_state = 5;
  j_result = user_module_get_list(&config, "error", 0, 100, cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_array_size(j_result), 0);
  json_decref(j_result);
  
  cur_state = 6;
  j_result = user_module_get_list(&config, NULL, 1, 100, cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_array_size(j_result), 1);
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "username")), "user2");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "name")), "Dave Lopper 2");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "email")), "dave2@glewlwyd");
  ck_assert_ptr_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "enabled")), json_false());
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(json_array_get(j_result, 0), "scope"), 0)), "g_profile");
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(json_array_get(j_result, 0), "scope"), 1)), "scope2");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "data1")), "value7");
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(json_array_get(j_result, 0), "data2"), 0)), "value8");
  ck_assert_int_eq(json_array_size(json_object_get(json_array_get(j_result, 0), "data2")), 1);
  ck_assert_ptr_eq(json_object_get(json_array_get(j_result, 0), "data3"), NULL);
  ck_assert_ptr_eq(json_object_get(json_array_get(j_result, 0), "data4"), NULL);
  json_decref(j_result);
  
  cur_state = 7;
  j_result = user_module_get_list(&config, NULL, 0, 100, cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "result")), G_ERROR_DB);
  json_decref(j_result);
}
END_TEST

START_TEST(test_glwd_mod_user_ldap_get)
{
  json_t * j_result;
  
  cur_state = 8;
  j_result = user_module_get(&config, "user1", cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_array_size(j_result), 1);
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "username")), "user1");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "name")), "Dave Lopper 1");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "email")), "dave1@glewlwyd");
  ck_assert_ptr_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "enabled")), json_true());
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(json_array_get(j_result, 0), "scope"), 0)), "g_profile");
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(json_array_get(j_result, 0), "scope"), 1)), "scope1");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "data1")), "value1");
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(json_array_get(j_result, 0), "data2"), 0)), "value2");
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(json_array_get(j_result, 0), "data2"), 1)), "value3");
  ck_assert_int_eq(json_array_size(json_object_get(json_array_get(j_result, 0), "data2")), 2);
  ck_assert_ptr_eq(json_object_get(json_array_get(j_result, 0), "data3"), NULL);
  json_decref(j_result);
  
  cur_state = 9;
  j_result = user_module_get(&config, "error", cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "result")), G_ERROR_NOT_FOUND);
  json_decref(j_result);
  
  cur_state = 10;
  j_result = user_module_get(&config, "user1", cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "result")), G_ERROR_DB);
  json_decref(j_result);
}
END_TEST

START_TEST(test_glwd_mod_user_ldap_get_profile)
{
  json_t * j_result;
  
  cur_state = 8;
  j_result = user_module_get(&config, "user1", cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_array_size(j_result), 1);
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "username")), "user1");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "name")), "Dave Lopper 1");
  ck_assert_str_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "email")), "dave1@glewlwyd");
  ck_assert_ptr_eq(json_string_value(json_object_get(json_array_get(j_result, 0), "enabled")), json_true());
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(json_array_get(j_result, 0), "scope"), 0)), "g_profile");
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(json_array_get(j_result, 0), "scope"), 1)), "scope1");
  ck_assert_ptr_eq(json_object_get(json_array_get(j_result, 0), "data1"), NULL);
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(json_array_get(j_result, 0), "data2"), 0)), "value2");
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(json_array_get(j_result, 0), "data2"), 1)), "value3");
  ck_assert_int_eq(json_array_size(json_object_get(json_array_get(j_result, 0), "data2")), 2);
  ck_assert_ptr_eq(json_object_get(json_array_get(j_result, 0), "data3"), json_null());
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(json_array_get(j_result, 0), "data4"), 0)), "value4");
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(json_array_get(j_result, 0), "data4"), 1)), "value5");
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(json_array_get(j_result, 0), "data4"), 2)), "value6");
  ck_assert_int_eq(json_array_size(json_object_get(json_array_get(j_result, 0), "data4")), 3);
  json_decref(j_result);
  
  cur_state = 9;
  j_result = user_module_get(&config, "error", cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "result")), G_ERROR_NOT_FOUND);
  json_decref(j_result);
  
  cur_state = 10;
  j_result = user_module_get(&config, "user1", cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "result")), G_ERROR_DB);
  json_decref(j_result);
}
END_TEST

START_TEST(test_glwd_mod_user_ldap_is_valid)
{
  json_t * j_result, * j_user;
  char * long_value[(1024*1024*16)+128];
  
  cur_state = 8;
  memset(long_value, 'a', (1024*1024*16)+127);
  long_value[(1024*1024*16)+128] = '\0';
  
  j_user = json_pack("{ss}", "username", "user1");
  j_result = user_module_is_valid(&config, NULL, j_user, GLEWLWYD_IS_VALID_MODE_ADD, cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "result")), G_ERROR_PARAM);
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(j_result, "error"), 0)), "username already exist");
  ck_assert_int_eq(json_array_size(json_object_get(j_result, "error")), 1);
  json_decref(j_result);
  json_decref(j_user);
  
  j_user = json_pack("{ss}", "username", "user3-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789");
  j_result = user_module_is_valid(&config, NULL, j_user, GLEWLWYD_IS_VALID_MODE_ADD, cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "result")), G_ERROR_PARAM);
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(j_result, "error"), 0)), "username is mandatory and must be a string of at least 128 characters");
  ck_assert_int_eq(json_array_size(json_object_get(j_result, "error")), 1);
  json_decref(j_result);
  json_decref(j_user);
  
  j_user = json_pack("{ss}", "username", "user3-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789");
  j_result = user_module_is_valid(&config, NULL, j_user, GLEWLWYD_IS_VALID_MODE_UPDATE, cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "result")), G_OK);
  json_decref(j_result);
  json_decref(j_user);
  
  j_user = json_pack("{ss}", "username", "user3-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789");
  j_result = user_module_is_valid(&config, NULL, j_user, GLEWLWYD_IS_VALID_MODE_UPDATE_PROFILE, cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "result")), G_OK);
  json_decref(j_result);
  json_decref(j_user);
  
  j_user = json_pack("{sssi}", "username", "user3", "name", 42);
  j_result = user_module_is_valid(&config, NULL, j_user, GLEWLWYD_IS_VALID_MODE_ADD, cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "result")), G_ERROR_PARAM);
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(j_result, "error"), 0)), "name must be a string of at least 256 characters");
  ck_assert_int_eq(json_array_size(json_object_get(j_result, "error")), 1);
  json_decref(j_result);
  json_decref(j_user);
  
  j_user = json_pack("{ssss}", "username", "user3", "name", "123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789");
  j_result = user_module_is_valid(&config, NULL, j_user, GLEWLWYD_IS_VALID_MODE_ADD, cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "result")), G_ERROR_PARAM);
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(j_result, "error"), 0)), "name must be a string of at least 256 characters");
  ck_assert_int_eq(json_array_size(json_object_get(j_result, "error")), 1);
  json_decref(j_result);
  json_decref(j_user);
  
  j_user = json_pack("{sssi}", "username", "user3", "email", 42);
  j_result = user_module_is_valid(&config, NULL, j_user, GLEWLWYD_IS_VALID_MODE_ADD, cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "result")), G_ERROR_PARAM);
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(j_result, "error"), 0)), "email must be a string of at least 512 characters");
  ck_assert_int_eq(json_array_size(json_object_get(j_result, "error")), 1);
  json_decref(j_result);
  json_decref(j_user);
  
  j_user = json_pack("{ssss}", "username", "user3", "email", "123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789");
  j_result = user_module_is_valid(&config, NULL, j_user, GLEWLWYD_IS_VALID_MODE_ADD, cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "result")), G_ERROR_PARAM);
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(j_result, "error"), 0)), "email must be a string of at least 512 characters");
  ck_assert_int_eq(json_array_size(json_object_get(j_result, "error")), 1);
  json_decref(j_result);
  json_decref(j_user);
  
  j_user = json_pack("{sssi}", "username", "user3", "scope", 42);
  j_result = user_module_is_valid(&config, NULL, j_user, GLEWLWYD_IS_VALID_MODE_ADD, cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "result")), G_ERROR_PARAM);
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(j_result, "error"), 0)), "scope must be a JSON array of string");
  ck_assert_int_eq(json_array_size(json_object_get(j_result, "error")), 1);
  json_decref(j_result);
  json_decref(j_user);
  
  j_user = json_pack("{sss[i{}]}", "username", "user3", "scope", 42);
  j_result = user_module_is_valid(&config, NULL, j_user, GLEWLWYD_IS_VALID_MODE_ADD, cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "result")), G_ERROR_PARAM);
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(j_result, "error"), 0)), "scope must be a JSON array of string");
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(j_result, "error"), 1)), "scope must be a JSON array of string");
  ck_assert_int_eq(json_array_size(json_object_get(j_result, "error")), 2);
  json_decref(j_result);
  json_decref(j_user);
  
  j_user = json_pack("{sssi}", "username", "user3", "enabled", 42);
  j_result = user_module_is_valid(&config, NULL, j_user, GLEWLWYD_IS_VALID_MODE_ADD, cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "result")), G_ERROR_PARAM);
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(j_result, "error"), 0)), "enabled must be a boolean");
  ck_assert_int_eq(json_array_size(json_object_get(j_result, "error")), 1);
  json_decref(j_result);
  json_decref(j_user);
  
  j_user = json_pack("{sssisisisi}", "username", "user1", "name", 42, "email", 42, "enabled", 42, "scope", 42);
  j_result = user_module_is_valid(&config, NULL, j_user, GLEWLWYD_IS_VALID_MODE_ADD, cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "result")), G_ERROR_PARAM);
  ck_assert_int_eq(json_array_size(json_object_get(j_result, "error")), 5);
  json_decref(j_result);
  json_decref(j_user);
  
  j_user = json_pack("{sssisisisi}", "username", "user1", "name", 42, "email", 42, "enabled", 42, "scope", 42);
  j_result = user_module_is_valid(&config, NULL, j_user, GLEWLWYD_IS_VALID_MODE_UPDATE, cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "result")), G_ERROR_PARAM);
  ck_assert_int_eq(json_array_size(json_object_get(j_result, "error")), 4);
  json_decref(j_result);
  json_decref(j_user);
  
  j_user = json_pack("{sssisisisi}", "username", "user1", "name", 42, "email", 42, "enabled", 42, "scope", 42);
  j_result = user_module_is_valid(&config, NULL, j_user, GLEWLWYD_IS_VALID_MODE_UPDATE_PROFILE, cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "result")), G_ERROR_PARAM);
  ck_assert_int_eq(json_array_size(json_object_get(j_result, "error")), 1);
  json_decref(j_result);
  json_decref(j_user);
  
  j_user = json_pack("{sssi}", "username", "user3", "enabled", 42);
  j_result = user_module_is_valid(&config, NULL, j_user, GLEWLWYD_IS_VALID_MODE_ADD, cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "result")), G_ERROR_PARAM);
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(j_result, "error"), 0)), "enabled must be a boolean");
  ck_assert_int_eq(json_array_size(json_object_get(j_result, "error")), 1);
  json_decref(j_result);
  json_decref(j_user);
  
  j_user = json_pack("{sssi}", "username", "user3", "data1", 42);
  j_result = user_module_is_valid(&config, NULL, j_user, GLEWLWYD_IS_VALID_MODE_ADD, cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "result")), G_ERROR_PARAM);
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(j_result, "error"), 0)), "property 'data1' must be a string value of at least 16M characters");
  ck_assert_int_eq(json_array_size(json_object_get(j_result, "error")), 1);
  json_decref(j_result);
  json_decref(j_user);
  
  j_user = json_pack("{ssss}", "username", "user3", "data1", long_value);
  j_result = user_module_is_valid(&config, NULL, j_user, GLEWLWYD_IS_VALID_MODE_ADD, cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "result")), G_ERROR_PARAM);
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(j_result, "error"), 0)), "property 'data1' must be a string value of at least 16M characters");
  ck_assert_int_eq(json_array_size(json_object_get(j_result, "error")), 1);
  json_decref(j_result);
  json_decref(j_user);
  
  j_user = json_pack("{sssi}", "username", "user3", "data2", 42);
  j_result = user_module_is_valid(&config, NULL, j_user, GLEWLWYD_IS_VALID_MODE_ADD, cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "result")), G_ERROR_PARAM);
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(j_result, "error"), 0)), "property 'data2' must be a JSON array");
  ck_assert_int_eq(json_array_size(json_object_get(j_result, "error")), 1);
  json_decref(j_result);
  json_decref(j_user);
  
  j_user = json_pack("{ssss}", "username", "user3", "data2", "value");
  j_result = user_module_is_valid(&config, NULL, j_user, GLEWLWYD_IS_VALID_MODE_ADD, cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "result")), G_ERROR_PARAM);
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(j_result, "error"), 0)), "property 'data2' must be a JSON array");
  ck_assert_int_eq(json_array_size(json_object_get(j_result, "error")), 1);
  json_decref(j_result);
  json_decref(j_user);
  
  j_user = json_pack("{sss[i]}", "username", "user3", "data2", 42);
  j_result = user_module_is_valid(&config, NULL, j_user, GLEWLWYD_IS_VALID_MODE_ADD, cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "result")), G_ERROR_PARAM);
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(j_result, "error"), 0)), "property 'data2' must contain a string value of at least 16M characters");
  ck_assert_int_eq(json_array_size(json_object_get(j_result, "error")), 1);
  json_decref(j_result);
  json_decref(j_user);
  
  j_user = json_pack("{sss[s]}", "username", "user3", "data2", long_value);
  j_result = user_module_is_valid(&config, NULL, j_user, GLEWLWYD_IS_VALID_MODE_ADD, cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "result")), G_ERROR_PARAM);
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(j_result, "error"), 0)), "property 'data2' must contain a string value of at least 16M characters");
  ck_assert_int_eq(json_array_size(json_object_get(j_result, "error")), 1);
  json_decref(j_result);
  json_decref(j_user);
  
  j_user = json_pack("{ssss}", "username", "user3", "data3", long_value);
  j_result = user_module_is_valid(&config, NULL, j_user, GLEWLWYD_IS_VALID_MODE_ADD, cls);
  ck_assert_ptr_ne(j_result, 0);
  ck_assert_int_eq(json_integer_value(json_object_get(j_result, "result")), G_OK);
  json_decref(j_result);
  json_decref(j_user);
  
}
END_TEST

START_TEST(test_glwd_mod_user_ldap_add)
{
  json_t * j_user = json_pack("{ss}", "username", "user3");
  cur_state = 11;
  ck_assert_int_eq(user_module_add(&config, j_user, cls), G_OK);
  cur_state = 12;
  ck_assert_int_eq(user_module_add(&config, j_user, cls), G_ERROR_DB);
  cur_state = 13;
  ck_assert_int_eq(user_module_add(&config, j_user, cls), G_ERROR_DB);
  json_decref(j_user);
}
END_TEST

START_TEST(test_glwd_mod_user_ldap_update)
{
  json_t * j_user = json_pack("{ss}", "name", "Dave Lopper 3");
  cur_state = 11;
  ck_assert_int_eq(user_module_update(&config, "user3", j_user, cls), G_OK);
  cur_state = 12;
  ck_assert_int_eq(user_module_update(&config, "user3", j_user, cls), G_ERROR_DB);
  cur_state = 13;
  ck_assert_int_eq(user_module_update(&config, "user3", j_user, cls), G_ERROR_DB);
  json_decref(j_user);
}
END_TEST

START_TEST(test_glwd_mod_user_ldap_update_profile)
{
  json_t * j_user = json_pack("{ss}", "name", "Dave Lopper 3");
  cur_state = 11;
  ck_assert_int_eq(user_module_update(&config, "user3", j_user, cls), G_OK);
  cur_state = 12;
  ck_assert_int_eq(user_module_update(&config, "user3", j_user, cls), G_ERROR_DB);
  cur_state = 13;
  ck_assert_int_eq(user_module_update(&config, "user3", j_user, cls), G_ERROR_DB);
  json_decref(j_user);
}
END_TEST

START_TEST(test_glwd_mod_user_ldap_delete)
{
  cur_state = 14;
  ck_assert_int_eq(user_module_delete(&config, "user3", cls), G_OK);
  cur_state = 15;
  ck_assert_int_eq(user_module_delete(&config, "user3", cls), G_ERROR_DB);
}
END_TEST

START_TEST(test_glwd_mod_user_ldap_check_password)
{
  cur_state = 16;
  ck_assert_int_eq(user_module_check_password(&config, "user1", "password", cls), G_OK);
  cur_state = 17;
  ck_assert_int_eq(user_module_check_password(&config, "user1", "error", cls), G_ERROR_UNAUTHORIZED);
  cur_state = 18;
  ck_assert_int_eq(user_module_check_password(&config, "user1", "error", cls), G_ERROR_DB);
}
END_TEST

START_TEST(test_glwd_mod_user_ldap_update_password)
{
  cur_state = 19;
  ck_assert_int_eq(user_module_update_password(&config, "user1", "new_password", cls), G_OK);
  cur_state = 20;
  ck_assert_int_eq(user_module_update_password(&config, "user1", "error", cls), G_ERROR_DB);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd delete token");
  tc_core = tcase_create("test_glwd_mod_user_ldap");
  tcase_add_test(tc_core, test_glwd_mod_user_ldap_load);
  tcase_add_test(tc_core, test_glwd_mod_user_ldap_unload);
  tcase_add_test(tc_core, test_glwd_mod_user_ldap_init);
  tcase_add_test(tc_core, test_glwd_mod_user_ldap_close);
  tcase_add_test(tc_core, test_glwd_mod_user_ldap_count_total);
  tcase_add_test(tc_core, test_glwd_mod_user_ldap_get_list);
  tcase_add_test(tc_core, test_glwd_mod_user_ldap_get);
  tcase_add_test(tc_core, test_glwd_mod_user_ldap_get_profile);
  tcase_add_test(tc_core, test_glwd_mod_user_ldap_is_valid);
  tcase_add_test(tc_core, test_glwd_mod_user_ldap_add);
  tcase_add_test(tc_core, test_glwd_mod_user_ldap_update);
  tcase_add_test(tc_core, test_glwd_mod_user_ldap_update_profile);
  tcase_add_test(tc_core, test_glwd_mod_user_ldap_delete);
  tcase_add_test(tc_core, test_glwd_mod_user_ldap_check_password);
  tcase_add_test(tc_core, test_glwd_mod_user_ldap_update_password);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  json_t * j_params;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  config.external_url = o_strdup("http://localhost:8080");
  config.login_url = o_strdup("/login");
  config.admin_scope = o_strdup("g_admin");
  config.profile_scope = o_strdup("g_profile");
  cur_conn.type = HOEL_DB_TYPE_MARIADB;
  config.conn = &cur_conn;
  config.hash_algorithm = digest_SHA1;
  config.glewlwyd_config = NULL;
  config.glewlwyd_module_callback_get_user = &glewlwyd_module_callback_get_user;
  config.glewlwyd_module_callback_set_user = &glewlwyd_module_callback_set_user;
  config.glewlwyd_module_callback_check_user_password = &glewlwyd_module_callback_check_user_password;
  
  j_params = json_pack("{sssssssssssssssssss{s{sososososo}s{sososososo}s{sososososo}s{sososososo}}}", 
                        "uri", "ldap://localhost/", 
                        "bind-dn", "dn=test,dc=localhost", 
                        "bind-password", "password", 
                        "base-search", "dn=base,dc=localhost", 
                        "filter", "objectClass=*", 
                        "username-property", "cn", 
                        "scope-property", "o",
                        "name-property", "sn",
                        "email-property", "mail",
                        "data-format",
                          "data1", "multiple", json_false(), "read", json_true(), "write", json_true(), "profile-read", json_false(), "profile-write", json_false(),
                          "data2", "multiple", json_true(), "read", json_true(), "write", json_true(), "profile-read", json_true(), "profile-write", json_false(), 
                          "data3", "multiple", json_false(), "read", json_false(), "write", json_false(), "profile-read", json_true(), "profile-write", json_true(),
                          "data4", "multiple", json_true(), "read", json_false(), "write", json_false(), "profile-read", json_true(), "profile-write", json_true());

  if (user_module_init(&config, j_params, &cls) == G_OK) {
    s = glewlwyd_suite();
    sr = srunner_create(s);
    
    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error user_module_init");
  }
  
  json_decref(j_params);
  
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
