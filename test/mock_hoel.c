#include <stdio.h>
#include <string.h>
#include <jansson.h>
//#include <ldap.h>

#include "../src/glewlwyd-common.h"

extern int cur_state;

int check_result_value(json_t * result, const int value) {
  return (result != NULL && 
          json_is_object(result) && 
          json_object_get(result, "result") != NULL && 
          json_is_integer(json_object_get(result, "result")) && 
          json_integer_value(json_object_get(result, "result")) == value);
}

/**
 * Mock Hoel functions
 */
char * h_escape_string(const struct _h_connection * conn, const char * unsafe) {
  return o_strdup("safe");
}

json_t * h_last_insert_id(const struct _h_connection * conn) {
  return json_integer(42);
}

int h_select(const struct _h_connection * conn, const json_t * j_query, json_t ** j_result, char ** query) {
  switch (cur_state) {
    case 0:
      *j_result = json_pack("[{ss}{ss}]", "username", "user1", "username", "user2");
      return H_OK;
      break;
    case 1:
      *j_result = json_pack("[]");
      return H_OK;
      break;
    case 2:
      return H_ERROR;
      break;
    case 3:
      if (0 == o_strcmp("g_user", json_string_value(json_object_get(j_query, "table")))) {
        *j_result = json_pack("[{sisssssssi}{sisssssssi}]", "gu_id", 0, "username", "user1", "name", "Dave Lopper 1", "email", "dave1@glewlwyd", "gu_enabled", 1, "gu_id", 1, "username", "user2", "name", "Dave Lopper 2", "email", "dave2@glewlwyd", "gu_enabled", 0);
      } else if (0 == o_strcmp("g_user_property", json_string_value(json_object_get(j_query, "table")))) {
        if (json_integer_value(json_object_get(json_object_get(j_query, "where"), "gu_id")) == 0) {
          if (conn->type == HOEL_DB_TYPE_MARIADB) {
            *j_result = json_pack("[{sssssoso}{sssossso}{sssososs}{sssososo}{sssssoso}{sssssoso}{sssssoso}]", 
                                  "name", "data1", "value_tiny", "value1", "value_small", json_null(), "value_medium", json_null(),
                                  "name", "data2", "value_tiny", json_null(), "value_small", "value2", "value_medium", json_null(),
                                  "name", "data2", "value_tiny", json_null(), "value_small", json_null(), "value_medium", "value3",
                                  "name", "data3", "value_tiny", json_null(), "value_small", json_null(), "value_medium", json_null(),
                                  "name", "data4", "value_tiny", "value4", "value_small", json_null(), "value_medium", json_null(),
                                  "name", "data4", "value_tiny", "value5", "value_small", json_null(), "value_medium", json_null(),
                                  "name", "data4", "value_tiny", "value6", "value_small", json_null(), "value_medium", json_null());
          } else {
            *j_result = json_pack("[{ssss}{ssss}{ssss}{ssso}{ssss}{ssss}]", 
                                  "name", "data1", "value", "value1",
                                  "name", "data2", "value", "value2",
                                  "name", "data2", "value", "value3",
                                  "name", "data3", "value", json_null(),
                                  "name", "data4", "value", "value4",
                                  "name", "data4", "value", "value5",
                                  "name", "data4", "value", "value6");
          }
        } else {
          if (conn->type == HOEL_DB_TYPE_MARIADB) {
            *j_result = json_pack("[{sssssoso}{sssossso}{sssososo}]", 
                                  "name", "data1", "value_tiny", "value7", "value_small", json_null(), "value_medium", json_null(),
                                  "name", "data2", "value_tiny", json_null(), "value_small", "value8", "value_medium", json_null(),
                                  "name", "data3", "value_tiny", json_null(), "value_small", json_null(), "value_medium", json_null());
          } else {
            *j_result = json_pack("[{ssss}{ssss}{ssso}]", 
                                  "name", "data1", "value", "value7",
                                  "name", "data2", "value", "value8",
                                  "name", "data3", "value", json_null());
          }
        }
      } else {
        char * clause = msprintf("IN (SELECT gus_id from g_user_scope WHERE gu_id = 0)");
        if (o_strcmp(clause, json_string_value(json_object_get(json_object_get(j_query, "where"), "gus_id")))) {
          *j_result = json_pack("[ss]", "g_profile", "scope1");
        } else {
          *j_result = json_pack("[ss]", "g_profile", "scope2");
        }
      }
      return H_OK;
      break;
    case 4:
      if (0 == o_strcmp("g_user", json_string_value(json_object_get(j_query, "table")))) {
        *j_result = json_pack("[{sisssssssi}]", "gu_id", 0, "username", "user1", "name", "Dave Lopper 1", "email", "dave1@glewlwyd", "gu_enabled", 1);
      } else if (0 == o_strcmp("g_user_property", json_string_value(json_object_get(j_query, "table")))) {
        if (conn->type == HOEL_DB_TYPE_MARIADB) {
          *j_result = json_pack("[{sssssoso}{sssossso}{sssososs}{sssososo}{sssssoso}{sssssoso}{sssssoso}]", 
                                "name", "data1", "value_tiny", "value1", "value_small", json_null(), "value_medium", json_null(),
                                "name", "data2", "value_tiny", json_null(), "value_small", "value2", "value_medium", json_null(),
                                "name", "data2", "value_tiny", json_null(), "value_small", json_null(), "value_medium", "value3",
                                "name", "data3", "value_tiny", json_null(), "value_small", json_null(), "value_medium", json_null(),
                                "name", "data4", "value_tiny", "value4", "value_small", json_null(), "value_medium", json_null(),
                                "name", "data4", "value_tiny", "value5", "value_small", json_null(), "value_medium", json_null(),
                                "name", "data4", "value_tiny", "value6", "value_small", json_null(), "value_medium", json_null());
        } else {
          *j_result = json_pack("[{ssss}{ssss}{ssss}{ssso}{ssss}{ssss}]", 
                                "name", "data1", "value", "value1",
                                "name", "data2", "value", "value2",
                                "name", "data2", "value", "value3",
                                "name", "data3", "value", json_null(),
                                "name", "data4", "value", "value4",
                                "name", "data4", "value", "value5",
                                "name", "data4", "value", "value6");
        }
      } else {
        *j_result = json_pack("[ss]", "g_profile", "scope1");
      }
      return H_OK;
      break;
    case 5:
      *j_result = json_array();
      return H_OK;
      break;
    case 6:
      if (0 == o_strcmp("g_user", json_string_value(json_object_get(j_query, "table")))) {
        *j_result = json_pack("[{sisssssssi}]", "gu_id", 1, "username", "user2", "name", "Dave Lopper 2", "email", "dave2@glewlwyd", "gu_enabled", 0);
      } else if (0 == o_strcmp("g_user_property", json_string_value(json_object_get(j_query, "table")))) {
        if (conn->type == HOEL_DB_TYPE_MARIADB) {
          *j_result = json_pack("[{sssssoso}{sssossso}{sssososo}]", 
                                "name", "data1", "value_tiny", "value7", "value_small", json_null(), "value_medium", json_null(),
                                "name", "data2", "value_tiny", json_null(), "value_small", "value8", "value_medium", json_null(),
                                "name", "data3", "value_tiny", json_null(), "value_small", json_null(), "value_medium", json_null());
        } else {
          *j_result = json_pack("[{ssss}{ssss}{ssso}]", 
                                "name", "data1", "value", "value7",
                                "name", "data2", "value", "value8",
                                "name", "data3", "value", json_null());
        }
      } else {
        *j_result = json_pack("[ss]", "g_profile", "scope2");
      }
      return H_OK;
      break;
    case 7:
      return H_ERROR;
      break;
    case 8:
      if (0 == o_strcmp("g_user", json_string_value(json_object_get(j_query, "table")))) {
        *j_result = json_pack("[{sisssssssi}]", "gu_id", 0, "username", "user1", "name", "Dave Lopper 1", "email", "dave1@glewlwyd", "gu_enabled", 1);
      } else if (0 == o_strcmp("g_user_property", json_string_value(json_object_get(j_query, "table")))) {
        if (conn->type == HOEL_DB_TYPE_MARIADB) {
          *j_result = json_pack("[{sssssoso}{sssossso}{sssososs}{sssososo}{sssssoso}{sssssoso}{sssssoso}]", 
                                "name", "data1", "value_tiny", "value1", "value_small", json_null(), "value_medium", json_null(),
                                "name", "data2", "value_tiny", json_null(), "value_small", "value2", "value_medium", json_null(),
                                "name", "data2", "value_tiny", json_null(), "value_small", json_null(), "value_medium", "value3",
                                "name", "data3", "value_tiny", json_null(), "value_small", json_null(), "value_medium", json_null(),
                                "name", "data4", "value_tiny", "value4", "value_small", json_null(), "value_medium", json_null(),
                                "name", "data4", "value_tiny", "value5", "value_small", json_null(), "value_medium", json_null(),
                                "name", "data4", "value_tiny", "value6", "value_small", json_null(), "value_medium", json_null());
        } else {
          *j_result = json_pack("[{ssss}{ssss}{ssss}{ssso}{ssss}{ssss}]", 
                                "name", "data1", "value", "value1",
                                "name", "data2", "value", "value2",
                                "name", "data2", "value", "value3",
                                "name", "data3", "value", json_null(),
                                "name", "data4", "value", "value4",
                                "name", "data4", "value", "value5",
                                "name", "data4", "value", "value6");
        }
      } else {
        *j_result = json_pack("[ss]", "g_profile", "scope1");
      }
      return H_OK;
      break;
    case 9:
      *j_result = json_array();
      return H_OK;
      break;
    case 10:
      return H_ERROR;
      break;
    case 16:
      *j_result = json_pack("[{ss}]", "gu_id", "user1");
      return H_OK;
      break;
    case 17:
      *j_result = json_pack("[]");
      return H_OK;
      break;
    case 18:
      return H_ERROR;
      break;
    default:
      return H_ERROR;
      break;
  }
}

int h_insert(const struct _h_connection * conn, const json_t * j_query, char ** query) {
  switch (cur_state) {
    case 11:
      return H_OK;
      break;
    case 12:
      return H_ERROR;
      break;
    case 13:
      return H_OK;
      break;
    default:
      return H_ERROR;
      break;
  }
}

int h_update(const struct _h_connection * conn, const json_t * j_query, char ** query) {
  switch (cur_state) {
    case 11:
      return H_OK;
      break;
    case 12:
      return H_ERROR;
      break;
    case 13:
      return H_OK;
      break;
    case 19:
      return H_OK;
      break;
    case 20:
      return H_ERROR;
      break;
    default:
      return H_ERROR;
      break;
  }
}

int h_delete(const struct _h_connection * conn, const json_t * j_query, char ** query) {
  switch (cur_state) {
    case 11:
    case 12:
      return H_OK;
      break;
    case 13:
      return H_ERROR;
      break;
    case 14:
      return H_OK;
      break;
    case 15:
      return H_ERROR;
      break;
    default:
      return H_ERROR;
      break;
  }
}

int h_close_db(struct _h_connection * conn) {
  return H_OK;
}

int generate_digest(digest_algorithm digest, const char * password, int use_salt, char * out_digest) {
  strcpy(out_digest, "abcd");
  return 1;
}

struct _h_connection * h_connect_sqlite(const char * db_path) {
  return (struct _h_connection *)0x42;
}

struct _h_connection * h_connect_mariadb(const char * host, const char * user, const char * passwd, const char * db, const unsigned int port, const char * unix_socket) {
  return (struct _h_connection *)0x42;
}

struct _h_connection * h_connect_pgsql(const char * conninfo) {
  return (struct _h_connection *)0x42;
}

/**
 * Mock libldap functions
int ldap_unbind_ext(LDAP * ldap, LDAPControl *sctrls[], LDAPControl *cctrls[]) {
  return LDAP_SUCCESS;
}

int ldap_initialize(LDAP * ldap, const char * uri) {
  switch (cur_state) {
    case 0:
      return LDAP_ERROR;
      break;
    default:
      return LDAP_SUCCESS;
      break;
  }
}

int ldap_set_option(LDAP * ldap, int option, void * val) {
  switch (cur_state) {
    case 1:
      return LDAP_ERROR;
      break;
    default:
      return LDAP_OPT_SUCCESS;
      break;
  }
}

int ldap_simple_bind_s(LDAP * ldap, const char * dn, const char * passwd) {
  switch (cur_state) {
    case 2:
      return LDAP_ERROR;
      break;
    default:
      return LDAP_SUCCESS;
      break;
  }
}

int ldap_search_ext_s(LDAP *ld, char *base, int scope, char *filter, char *attrs[], int attrsonly, LDAPControl **serverctrls, LDAPControl **clientctrls, struct timeval *timeout, int sizelimit, LDAPMessage **res ) {
  switch (cur_state) {
    case 3:
    case 6:
      return LDAP_ERROR;
      break;
    default:
      return LDAP_SUCCESS;
      break;
  }
}

int ldap_count_entries( LDAP *ld, LDAPMessage *result ) {
  switch (cur_state) {
    case 4:
    case 10:
      return 2;
      break;
    case 11:
      return 1;
      break;
    default:
      return 0;
      break;
  }
}

int ldap_msgfree(LDAPMessage * message) {
  return LDAP_SUCCESS;
}

int ldap_create_page_control(LDAP * ld, unsigned long page_size, BerVal * cookie, int is_critical, LDAPControl ** control) {
  switch (cur_state) {
    case 5:
      return LDAP_ERROR;
      break;
    default:
      return LDAP_SUCCESS;
      break;
  }
}

int ldap_parse_result(LDAP *ld, LDAPMessage *result, int *errcodep, char **matcheddnp, char **errmsgp, char ***referralsp, LDAPControl ***serverctrlsp, int freeit ) {
  switch (cur_state) {
    case 6:
      return LDAP_ERROR;
      break;
    default:
      return LDAP_SUCCESS;
      break;
  }
}

int ber_bvfree(struct berval * berval) {
  return LDAP_SUCCESS;
}

int ldap_parse_pageresponse_control(LDAP *ld, LDAPControl * control, ber_int_t * count, struct berval * cookie) {
  switch (cur_state) {
    case 7:
      return LDAP_ERROR;
      break;
    case 9:
      cookie->bv_val = (void *)"test";
    default:
      return LDAP_SUCCESS;
      break;
  }
}

struct berval * ber_memalloc(size_t size) {
  static struct berval my_val;
  switch (cur_state) {
    case 8:
      return NULL;
      break;
    default:
      return &my_val;
      break;
  }
}

int ldap_controls_free(LDAPControl ** control) {
  return LDAP_SUCCESS;
}

int ldap_control_free(LDAPControl ** control) {
  return LDAP_SUCCESS;
}

LDAPMessage * ldap_first_entry( LDAP *ld, LDAPMessage *result ) {
  switch (cur_state) {
    case 12:
      return NULL;
      break;
    default:
      return (LDAPMessage *)0x42;
      break;
  }
}

LDAPMessage * ldap_next_entry( LDAP *ld, LDAPMessage *entry ) {
  switch (cur_state) {
    case 13:
      return NULL;
      break;
    default:
      return (LDAPMessage *)0x43;
      break;
  }
}

struct berval ** ldap_get_values_len(LDAP *ld, LDAPMessage *entry, char *attr) {
  switch (cur_state) {
    case 14:
      return NULL;
      break;
    default:
      if ((int)entry == 0x42) {
        if (0 == o_strcmp(attr, "username")) {
          return (struct berval **)0x42;
        } else if (0 == o_strcmp(attr, "name")) {
          return (struct berval **)0x43;
        } else if (0 == o_strcmp(attr, "email")) {
          return (struct berval **)0x44;
        } else if (0 == o_strcmp(attr, "scope")) {
          return (struct berval **)0x45;
        } else if (0 == o_strcmp(attr, "data1")) {
          return (struct berval **)0x46;
        } else if (0 == o_strcmp(attr, "data2")) {
          return (struct berval **)0x47;
        } else if (0 == o_strcmp(attr, "data3")) {
          return (struct berval **)0x48;
        } else if (0 == o_strcmp(attr, "data4")) {
          return (struct berval **)0x49;
        } else {
          return (struct berval **)0x50;
        }
      } else {
        if (0 == o_strcmp(attr, "username")) {
          return (struct berval **)0x51;
        } else if (0 == o_strcmp(attr, "name")) {
          return (struct berval **)0x52;
        } else if (0 == o_strcmp(attr, "email")) {
          return (struct berval **)0x53;
        } else if (0 == o_strcmp(attr, "scope")) {
          return (struct berval **)0x54;
        } else if (0 == o_strcmp(attr, "data1")) {
          return (struct berval **)0x55;
        } else if (0 == o_strcmp(attr, "data2")) {
          return (struct berval **)0x56;
        } else if (0 == o_strcmp(attr, "data3")) {
          return (struct berval **)0x57;
        } else if (0 == o_strcmp(attr, "data4")) {
          return (struct berval **)0x58;
        } else {
          return (struct berval **)0x59;
        }
      }
      break;
  }
}

size_t ldap_count_values_len(struct berval ** values) {
  switch (cur_state) {
    case 15:
      return 0;
    case 16:
      switch ((int)values) {
        case 
      }
      break;
    default:
      return 0;
      break;
  }
}
*/
