/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * Modules management functions definitions
 * 
 * Copyright 2016-2019 Nicolas Mora <mail@babelouest.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU GENERAL PUBLIC LICENSE
 * License as published by the Free Software Foundation;
 * version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU GENERAL PUBLIC LICENSE for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "glewlwyd.h"

json_t * get_module_type_list(struct config_elements * config) {
  struct _user_module * user_module;
  struct _client_module * client_module;
  struct _user_auth_scheme_module * scheme_module;
  struct _plugin_module * plugin_module;
  int i;
  json_t * j_parameters, * j_return;
  
  if ((j_return = json_pack("{sis{s[]s[]s[]s[]}}", "result", G_OK, "module", "user", "client", "scheme", "plugin")) != NULL) {
    // Gathering user modules
    for (i=0; i<pointer_list_size(config->user_module_list); i++) {
      user_module = (struct _user_module *)pointer_list_get_at(config->user_module_list, i);
      if (user_module != NULL) {
        if ((j_parameters = json_loads(user_module->parameters, JSON_DECODE_ANY, NULL)) != NULL) {
          json_array_append_new(json_object_get(json_object_get(j_return, "module"), "user"), json_pack("{sssssssO}",
                                                                                                        "name", user_module->name,
                                                                                                        "display_name", user_module->display_name,
                                                                                                        "description", user_module->description,
                                                                                                        "parameters", j_parameters));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_module_type_list - Error parsing json parameters for user module %s", user_module->name);
        }
        json_decref(j_parameters);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_module_type_list - Error pointer_list_get_at for user module at index %d", i);
      }
    }
    // Gathering client modules
    for (i=0; i<pointer_list_size(config->client_module_list); i++) {
      client_module = (struct _client_module *)pointer_list_get_at(config->client_module_list, i);
      if (client_module != NULL) {
        if ((j_parameters = json_loads(client_module->parameters, JSON_DECODE_ANY, NULL)) != NULL) {
          json_array_append_new(json_object_get(json_object_get(j_return, "module"), "client"), json_pack("{sssssssO}",
                                                                                                          "name", client_module->name,
                                                                                                          "display_name", client_module->display_name,
                                                                                                          "description", client_module->description,
                                                                                                          "parameters", j_parameters));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_module_type_list - Error parsing json parameters for client module %s", client_module->name);
        }
        json_decref(j_parameters);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_module_type_list - Error pointer_list_get_at for client module at index %d", i);
      }
    }
    // Gathering user auth scheme modules
    for (i=0; i<pointer_list_size(config->user_auth_scheme_module_list); i++) {
      scheme_module = (struct _user_auth_scheme_module *)pointer_list_get_at(config->user_auth_scheme_module_list, i);
      if (scheme_module != NULL) {
        if ((j_parameters = json_loads(scheme_module->parameters, JSON_DECODE_ANY, NULL)) != NULL) {
          json_array_append_new(json_object_get(json_object_get(j_return, "module"), "scheme"), json_pack("{sssssssO}",
                                                                                                          "name", scheme_module->name,
                                                                                                          "display_name", scheme_module->display_name,
                                                                                                          "description", scheme_module->description,
                                                                                                          "parameters", j_parameters));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_module_type_list - Error parsing json parameters for user auth scheme module %s", scheme_module->name);
        }
        json_decref(j_parameters);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_module_type_list - Error pointer_list_get_at for user auth scheme module at index %d", i);
      }
    }
    // Gathering plugin modules
    for (i=0; i<pointer_list_size(config->plugin_module_list); i++) {
      plugin_module = (struct _plugin_module *)pointer_list_get_at(config->plugin_module_list, i);
      if (plugin_module != NULL) {
        if ((j_parameters = json_loads(plugin_module->parameters, JSON_DECODE_ANY, NULL)) != NULL) {
          json_array_append_new(json_object_get(json_object_get(j_return, "module"), "plugin"), json_pack("{sssssssO}",
                                                                                                          "name", plugin_module->name,
                                                                                                          "display_name", plugin_module->display_name,
                                                                                                          "description", plugin_module->description,
                                                                                                          "parameters", j_parameters));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_module_type_list - Error parsing json parameters for plugin module %s", plugin_module->name);
        }
        json_decref(j_parameters);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_module_type_list - Error pointer_list_get_at for plugin module at index %d", i);
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_module_type_list - Error allocating resources for j_return");
  }
  return j_return;
}

json_t * get_user_module_list(struct config_elements * config) {
  int res;
  json_t * j_query, * j_result = NULL, * j_return, * j_parameters, * j_element;
  size_t index;
  struct _user_module_instance * cur_instance;
  
  j_query = json_pack("{sss[ssssss]ss}",
                      "table",
                      GLEWLWYD_TABLE_USER_MODULE_INSTANCE,
                      "columns",
                        "gumi_module AS module",
                        "gumi_name AS name",
                        "gumi_display_name AS display_name",
                        "gumi_parameters",
                        "gumi_order AS order_rank",
                        "gumi_readonly",
                      "order_by",
                      "gumi_order");
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    json_array_foreach(j_result, index, j_element) {
      j_parameters = json_loads(json_string_value(json_object_get(j_element, "gumi_parameters")), JSON_DECODE_ANY, NULL);
      if (j_parameters != NULL) {
        json_object_set_new(j_element, "parameters", j_parameters);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_user_module_list - Error parsing parameters for module %s %s", json_string_value(json_object_get(j_element, "name")), json_string_value(json_object_get(j_element, "gumi_parameters")));
        json_object_set_new(j_element, "parameters", json_null());
      }
      json_object_del(j_element, "gumi_parameters");
      
      json_object_set_new(j_element, "readonly", json_integer_value(json_object_get(j_element, "gumi_readonly"))?json_true():json_false());
      json_object_del(j_element, "gumi_readonly");
      
      cur_instance = get_user_module_instance(config, json_string_value(json_object_get(j_element, "name")));
      if (cur_instance != NULL) {
        json_object_set(j_element, "enabled", cur_instance->enabled?json_true():json_false());
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_user_module_list - Error instance %s not found in app config", json_string_value(json_object_get(j_element, "name")));
        json_object_set(j_element, "enabled", json_false());
      }
    }
    j_return = json_pack("{sisO}", "result", G_OK, "module", j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_user_module_list - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  json_decref(j_result);
  return j_return;
}

json_t * get_user_module(struct config_elements * config, const char * name) {
  int res;
  json_t * j_query, * j_result = NULL, * j_return, * j_parameters;
  struct _user_module_instance * cur_instance;
  
  j_query = json_pack("{sss[sssss]s{ss}}",
                      "table",
                      GLEWLWYD_TABLE_USER_MODULE_INSTANCE,
                      "columns",
                        "gumi_module AS module",
                        "gumi_name AS name",
                        "gumi_display_name AS display_name",
                        "gumi_parameters",
                        "gumi_order AS order_rank",
                      "where",
                        "gumi_name",
                        name);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result) > 0) {
      j_parameters = json_loads(json_string_value(json_object_get(json_array_get(j_result, 0), "gumi_parameters")), JSON_DECODE_ANY, NULL);
      if (j_parameters != NULL) {
        json_object_set_new(json_array_get(j_result, 0), "parameters", j_parameters);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_user_module - Error parsing parameters for module %s", json_string_value(json_object_get(json_array_get(j_result, 0), "name")));
        json_object_set_new(json_array_get(j_result, 0), "parameters", json_null());
      }
      json_object_del(json_array_get(j_result, 0), "gumi_parameters");
      
      json_object_set_new(json_array_get(j_result, 0), "readonly", json_integer_value(json_object_get(json_array_get(j_result, 0), "gumi_readonly"))?json_true():json_false());
      json_object_del(json_array_get(j_result, 0), "gumi_readonly");
      
      cur_instance = get_user_module_instance(config, name);
      if (cur_instance != NULL) {
        json_object_set(json_array_get(j_result, 0), "enabled", cur_instance->enabled?json_true():json_false());
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_user_module - Error instance %s not found in app config", name);
        json_object_set(json_array_get(j_result, 0), "enabled", json_false());
      }
      j_return = json_pack("{sisO}", "result", G_OK, "module", j_result);
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_user_module - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  json_decref(j_result);
  return j_return;
}

json_t * is_user_module_valid(struct config_elements * config, json_t * j_module, int add) {
  json_t * j_return, * j_cur_module, * j_error_list;
  int i, found;
  struct _user_module * module;
  char * parameters;
  
  if (j_module != NULL && json_is_object(j_module)) {
    if ((j_error_list = json_array()) != NULL) {
      if (add) {
        if (json_object_get(j_module, "name") != NULL && json_is_string(json_object_get(j_module, "name")) && json_string_length(json_object_get(j_module, "name")) > 0 && json_string_length(json_object_get(j_module, "name")) <= 128) {
          j_cur_module = get_user_module(config, json_string_value(json_object_get(j_module, "name")));
          if (check_result_value(j_cur_module, G_OK)) {
            json_array_append_new(j_error_list, json_string("A module instance with this name already exist"));
          } else if (!check_result_value(j_cur_module, G_ERROR_NOT_FOUND)) {
            y_log_message(Y_LOG_LEVEL_ERROR, "is_user_module_valid - Error json_array_append_new");
          }
          json_decref(j_cur_module);
        } else {
          json_array_append_new(j_error_list, json_string("Module instance name is mandatory and must be a non empty string of at least 128 characters"));
        }
        if (json_object_get(j_module, "module") != NULL && json_is_string(json_object_get(j_module, "module")) && json_string_length(json_object_get(j_module, "module")) > 0 && json_string_length(json_object_get(j_module, "module")) <= 128) {
          found = 0;
          for (i=0; i<pointer_list_size(config->user_module_list); i++) {
            module = (struct _user_module *)pointer_list_get_at(config->user_module_list, i);
            if (module != NULL) {
              if (0 == o_strcmp(module->name, json_string_value(json_object_get(j_module, "module")))) {
                found = 1;
                break;
              }
            }
          }
          if (!found) {
            json_array_append_new(j_error_list, json_string("Module name doesn't exist"));
          }
        } else {
          json_array_append_new(j_error_list, json_string("Module is mandatory and must be a non empty string of at least 128 characters"));
        }
      }
      if (json_object_get(j_module, "display_name") != NULL && (!json_is_string(json_object_get(j_module, "display_name")) || json_string_length(json_object_get(j_module, "display_name")) == 0 || json_string_length(json_object_get(j_module, "display_name")) > 256)) {
        json_array_append_new(j_error_list, json_string("display_name is optional and must be a non empty string of at least 256 characters"));
      }
      if (json_object_get(j_module, "parameters") == NULL || !json_is_object(json_object_get(j_module, "parameters"))) {
        json_array_append_new(j_error_list, json_string("Parameters is mandatory and must be a json object of at least 16k characters"));
      } else {
        parameters = json_dumps(json_object_get(j_module, "parameters"), JSON_COMPACT);
        if (parameters == NULL || o_strlen(parameters) > 16*1024) {
          json_array_append_new(j_error_list, json_string("Parameters is mandatory and must be a json object of at least 16k characters"));
        }
        o_free(parameters);
      }
      if (json_object_get(j_module, "order_rank") != NULL && (!json_is_integer(json_object_get(j_module, "order_rank")) || json_integer_value(json_object_get(j_module, "order_rank")) < 0)) {
        json_array_append_new(j_error_list, json_string("order_rank is optional and must be a positive integer"));
      }
      if (json_object_get(j_module, "readonly") != NULL && !json_is_boolean(json_object_get(j_module, "readonly"))) {
        json_array_append_new(j_error_list, json_string("readonly is optional and must be a boolean"));
      }
      if (json_array_size(j_error_list) > 0) {
        j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", j_error_list);
      } else {
        j_return = json_pack("{si}", "result", G_OK);
      }
      json_decref(j_error_list);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "is_user_module_valid - Error allocating resources for j_error_list");
      j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
    }
  } else {
    j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "errors", "module must be a JSON object");
  }
  return j_return;
}

int add_user_module(struct config_elements * config, json_t * j_module) {
  struct _user_module * module;
  struct _user_module_instance * cur_instance;
  json_t * j_query;
  int res, ret, i;
  char * parameters = json_dumps(json_object_get(j_module, "parameters"), JSON_COMPACT);
  
  j_query = json_pack("{sss{sOsOsOsOss}}",
                      "table",
                      GLEWLWYD_TABLE_USER_MODULE_INSTANCE,
                      "values",
                        "gumi_module",
                        json_object_get(j_module, "module"),
                        "gumi_name",
                        json_object_get(j_module, "name"),
                        "gumi_display_name",
                        json_object_get(j_module, "display_name")!=NULL?json_object_get(j_module, "display_name"):json_null(),
                        "gumi_readonly",
                        json_object_get(j_module, "readonly")!=NULL?json_object_get(j_module, "readonly"):json_false(),
                        "gumi_parameters",
                        parameters);
  if (json_object_get(j_module, "order_rank") != NULL) {
    json_object_set(json_object_get(j_query, "values"), "gumi_order", json_object_get(j_module, "order_rank"));
  } else {
    json_object_set_new(json_object_get(j_query, "values"), "gumi_order", json_integer(pointer_list_size(config->user_module_list)));
  }
  res = h_insert(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    module = NULL;
    for (i=0; i<pointer_list_size(config->user_module_list); i++) {
      module = (struct _user_module *)pointer_list_get_at(config->user_module_list, i);
      if (0 == o_strcmp(module->name, json_string_value(json_object_get(j_module, "module")))) {
        break;
      } else {
        module = NULL;
      }
    }
    if (module != NULL) {
      cur_instance = o_malloc(sizeof(struct _user_module_instance));
      if (cur_instance != NULL) {
        cur_instance->cls = NULL;
        cur_instance->name = o_strdup(json_string_value(json_object_get(j_module, "name")));
        cur_instance->module = module;
        cur_instance->enabled = 0;
        cur_instance->readonly = json_object_get(j_module, "readonly")==json_false()?0:1;
        if (pointer_list_append(config->user_module_instance_list, cur_instance)) {
          if (module->user_module_init(config->config_m, parameters, &cur_instance->cls) == G_OK) {
            cur_instance->enabled = 1;
            ret = G_OK;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "add_user_module - Error init module %s/%s", module->name, json_string_value(json_object_get(j_module, "name")));
            ret = G_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "add_user_module - Error reallocating resources for user_module_instance_list");
          o_free(cur_instance->name);
          ret = G_ERROR_MEMORY;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "add_user_module - Error allocating resources for cur_instance");
        ret = G_ERROR_MEMORY;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "add_user_module - Module '%s' not found", json_string_value(json_object_get(j_module, "module")));
      ret = G_ERROR;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "add_user_module - Error executing j_query");
    ret = G_ERROR_DB;
  }
  o_free(parameters);
  return ret;
}

int set_user_module(struct config_elements * config, const char * name, json_t * j_module) {
  json_t * j_query;
  int res, ret;
  char * parameters = json_dumps(json_object_get(j_module, "parameters"), JSON_COMPACT);
  
  j_query = json_pack("{sss{sOss}s{ss}}",
                      "table",
                      GLEWLWYD_TABLE_USER_MODULE_INSTANCE,
                      "set",
                        "gumi_display_name",
                        json_object_get(j_module, "display_name")!=NULL?json_object_get(j_module, "display_name"):json_null(),
                        "gumi_parameters",
                        parameters,
                      "where",
                        "gumi_name",
                        name);
  if (json_object_get(j_module, "order_rank") != NULL) {
    json_object_set(json_object_get(j_query, "set"), "gumi_order", json_object_get(j_module, "order_rank"));
  } else {
    json_object_set_new(json_object_get(j_query, "set"), "gumi_order", json_integer(pointer_list_size(config->user_module_list)));
  }
  if (json_object_get(j_module, "readonly") != NULL) {
    json_object_set_new(json_object_get(j_query, "set"), "gumi_readonly", json_object_get(j_module, "readonly")==json_true()?json_integer(1):json_integer(0));
  }
  res = h_update(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "add_user_module - Error executing j_query");
    ret = G_ERROR_DB;
  }
  o_free(parameters);
  return ret;
}

int delete_user_module(struct config_elements * config, const char * name) {
  int ret, res;
  json_t * j_query;
  struct _user_module_instance * instance;
  
  if (manage_user_module(config, name, GLEWLWYD_MODULE_ACTION_STOP) == G_OK) {
    instance = get_user_module_instance(config, name);
    if (pointer_list_remove_pointer(config->user_module_instance_list, instance)) {
      o_free(instance->name);
      o_free(instance);
      j_query = json_pack("{sss{ss}}",
                          "table",
                          GLEWLWYD_TABLE_USER_MODULE_INSTANCE,
                          "where",
                            "gumi_name",
                            name);
      res = h_delete(config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        ret = G_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "delete_user_module - Error executing j_query");
        ret = G_ERROR_DB;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "delete_user_module - Error pointer_list_remove_pointer");
      ret = G_ERROR;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "delete_user_module - Error action not found");
    ret = G_ERROR;
  }
  return ret;
}

int manage_user_module(struct config_elements * config, const char * name, int action) {
  struct _user_module_instance * instance = get_user_module_instance(config, name);
  json_t * j_module = get_user_module(config, name);
  int ret;
  
  if (check_result_value(j_module, G_OK) && instance != NULL) {
    if (action == GLEWLWYD_MODULE_ACTION_START) {
      if (!instance->enabled) {
        if (instance->module->user_module_init(config->config_m, json_string_value(json_object_get(j_module, "parameters")), &instance->cls) == G_OK) {
          instance->enabled = 1;
          ret = G_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "manage_user_module - Error init module %s/%s", instance->module->name, json_string_value(json_object_get(j_module, "name")));
          ret = G_ERROR;
        }
      } else {
        ret = G_ERROR_PARAM;
      }
    } else if (action == GLEWLWYD_MODULE_ACTION_STOP) {
      if (instance->enabled) {
        if (instance->module->user_module_close(config->config_m, instance->cls) == G_OK) {
          instance->enabled = 0;
          ret = G_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "manage_user_module - Error close module %s/%s", instance->module->name, json_string_value(json_object_get(j_module, "name")));
          ret = G_ERROR;
        }
      } else {
        ret = G_ERROR_PARAM;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "manage_user_module - Error action not found");
      ret = G_ERROR_PARAM;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "manage_user_module - Error module not found");
    ret = G_ERROR_PARAM;
  }
  json_decref(j_module);
  return ret;
}

json_t * get_user_auth_scheme_module_list(struct config_elements * config) {
  int res;
  json_t * j_query, * j_result = NULL, * j_return, * j_parameters, * j_element;
  size_t index;
  struct _user_auth_scheme_module_instance * cur_instance;
  
  j_query = json_pack("{sss[ssss]ss}",
                      "table",
                      GLEWLWYD_TABLE_USER_AUTH_SCHEME_MODULE_INSTANCE,
                      "columns",
                        "guasmi_module AS module",
                        "guasmi_name AS name",
                        "guasmi_display_name AS display_name",
                        "guasmi_parameters",
                      "order_by",
                      "guasmi_module,guasmi_name");
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    json_array_foreach(j_result, index, j_element) {
      j_parameters = json_loads(json_string_value(json_object_get(j_element, "guasmi_parameters")), JSON_DECODE_ANY, NULL);
      if (j_parameters != NULL) {
        json_object_set_new(j_element, "parameters", j_parameters);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_user_auth_scheme_module_list - Error parsing parameters for module %s", json_string_value(json_object_get(j_element, "name")));
        json_object_set_new(j_element, "parameters", json_null());
      }
      json_object_del(j_element, "guasmi_parameters");
      
      cur_instance = get_user_auth_scheme_module_instance(config, json_string_value(json_object_get(j_element, "name")));
      if (cur_instance != NULL) {
        json_object_set(j_element, "enabled", cur_instance->enabled?json_true():json_false());
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_user_auth_scheme_module_list - Error instance %s not found in app config", json_string_value(json_object_get(j_element, "name")));
        json_object_set(j_element, "enabled", json_false());
      }
    }
    j_return = json_pack("{sisO}", "result", G_OK, "module", j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_user_auth_scheme_module_list - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  json_decref(j_result);
  return j_return;
}

json_t * get_user_auth_scheme_module(struct config_elements * config, const char * name) {
  int res;
  json_t * j_query, * j_result = NULL, * j_return, * j_parameters;
  struct _user_auth_scheme_module_instance * cur_instance;
  
  j_query = json_pack("{sss[ssss]s{ss}}",
                      "table",
                      GLEWLWYD_TABLE_USER_AUTH_SCHEME_MODULE_INSTANCE,
                      "columns",
                        "guasmi_module AS module",
                        "guasmi_name AS name",
                        "guasmi_display_name AS display_name",
                        "guasmi_parameters",
                      "where",
                        "guasmi_name",
                        name);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result) > 0) {
      j_parameters = json_loads(json_string_value(json_object_get(json_array_get(j_result, 0), "guasmi_parameters")), JSON_DECODE_ANY, NULL);
      if (j_parameters != NULL) {
        json_object_set_new(json_array_get(j_result, 0), "parameters", j_parameters);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_user_auth_scheme_module_list - Error parsing parameters for module %s", json_string_value(json_object_get(json_array_get(j_result, 0), "name")));
        json_object_set_new(json_array_get(j_result, 0), "parameters", json_null());
      }
      json_object_del(json_array_get(j_result, 0), "guasmi_parameters");
      
      cur_instance = get_user_auth_scheme_module_instance(config, name);
      if (cur_instance != NULL) {
        json_object_set(json_array_get(j_result, 0), "enabled", cur_instance->enabled?json_true():json_false());
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_user_auth_scheme_module_list - Error instance %s not found in app config", name);
        json_object_set(json_array_get(j_result, 0), "enabled", json_false());
      }
      j_return = json_pack("{sisO}", "result", G_OK, "module", j_result);
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_user_auth_scheme_module_list - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  json_decref(j_result);
  return j_return;
}

json_t * is_user_auth_scheme_module_valid(struct config_elements * config, json_t * j_module, int add) {
  json_t * j_return, * j_cur_module, * j_error_list;
  int i, found;
  struct _user_auth_scheme_module * module;
  char * parameters;
  
  if (j_module != NULL && json_is_object(j_module)) {
    if ((j_error_list = json_array()) != NULL) {
      if (add) {
        if (json_object_get(j_module, "name") != NULL && json_is_string(json_object_get(j_module, "name")) && json_string_length(json_object_get(j_module, "name")) > 0 && json_string_length(json_object_get(j_module, "name")) <= 128) {
          j_cur_module = get_user_auth_scheme_module(config, json_string_value(json_object_get(j_module, "name")));
          if (check_result_value(j_cur_module, G_OK)) {
            json_array_append_new(j_error_list, json_string("A module instance with this name already exist"));
          } else if (!check_result_value(j_cur_module, G_ERROR_NOT_FOUND)) {
            y_log_message(Y_LOG_LEVEL_ERROR, "is_user_auth_scheme_module_valid - Error json_array_append_new");
          }
          json_decref(j_cur_module);
        } else {
          json_array_append_new(j_error_list, json_string("Module instance name is mandatory and must be a non empty string of at least 128 characters"));
        }
        if (json_object_get(j_module, "module") != NULL && json_is_string(json_object_get(j_module, "module")) && json_string_length(json_object_get(j_module, "module")) > 0 && json_string_length(json_object_get(j_module, "module")) <= 128) {
          found = 0;
          for (i=0; i<pointer_list_size(config->user_auth_scheme_module_list); i++) {
            module = (struct _user_auth_scheme_module *)pointer_list_get_at(config->user_auth_scheme_module_list, i);
            if (module != NULL) {
              if (0 == o_strcmp(module->name, json_string_value(json_object_get(j_module, "module")))) {
                found = 1;
                break;
              }
            }
          }
          if (!found) {
            json_array_append_new(j_error_list, json_string("Module name doesn't exist"));
          }
        } else {
          json_array_append_new(j_error_list, json_string("Module is mandatory and must be a non empty string of at least 128 characters"));
        }
      }
      if (json_object_get(j_module, "display_name") != NULL && (!json_is_string(json_object_get(j_module, "display_name")) || json_string_length(json_object_get(j_module, "display_name")) == 0 || json_string_length(json_object_get(j_module, "display_name")) > 256)) {
        json_array_append_new(j_error_list, json_string("display_name is optional and must be a non empty string of at least 256 characters"));
      }
      if (json_object_get(j_module, "parameters") == NULL || !json_is_object(json_object_get(j_module, "parameters"))) {
        json_array_append_new(j_error_list, json_string("Parameters is mandatory and must be a json object of at least 16k characters"));
      } else {
        parameters = json_dumps(json_object_get(j_module, "parameters"), JSON_COMPACT);
        if (parameters == NULL || o_strlen(parameters) > 16*1024) {
          json_array_append_new(j_error_list, json_string("Parameters is mandatory and must be a json object of at least 16k characters"));
        }
        o_free(parameters);
      }
      if (json_array_size(j_error_list) > 0) {
        j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", j_error_list);
      } else {
        j_return = json_pack("{si}", "result", G_OK);
      }
      json_decref(j_error_list);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "is_user_auth_scheme_module_valid - Error allocating resources for j_error_list");
      j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
    }
  } else {
    j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "errors", "module must be a JSON object");
  }
  return j_return;
}

int add_user_auth_scheme_module(struct config_elements * config, json_t * j_module) {
  struct _user_auth_scheme_module * module;
  struct _user_auth_scheme_module_instance * cur_instance;
  json_t * j_query;
  int res, ret, i;
  char * parameters = json_dumps(json_object_get(j_module, "parameters"), JSON_COMPACT);
  
  j_query = json_pack("{sss{sOsOsOss}}",
                      "table",
                      GLEWLWYD_TABLE_USER_AUTH_SCHEME_MODULE_INSTANCE,
                      "values",
                        "guasmi_module",
                        json_object_get(j_module, "module"),
                        "guasmi_name",
                        json_object_get(j_module, "name"),
                        "guasmi_display_name",
                        json_object_get(j_module, "display_name")!=NULL?json_object_get(j_module, "display_name"):json_null(),
                        "guasmi_parameters",
                        parameters);
  res = h_insert(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    module = NULL;
    for (i=0; i<pointer_list_size(config->user_auth_scheme_module_list); i++) {
      module = (struct _user_auth_scheme_module *)pointer_list_get_at(config->user_auth_scheme_module_list, i);
      if (0 == o_strcmp(module->name, json_string_value(json_object_get(j_module, "module")))) {
        break;
      } else {
        module = NULL;
      }
    }
    if (module != NULL) {
      cur_instance = o_malloc(sizeof(struct _user_auth_scheme_module_instance));
      if (cur_instance != NULL) {
        cur_instance->cls = NULL;
        cur_instance->name = o_strdup(json_string_value(json_object_get(j_module, "name")));
        cur_instance->module = module;
        cur_instance->enabled = 0;
        if (pointer_list_append(config->user_auth_scheme_module_instance_list, cur_instance)) {
          if (module->user_auth_scheme_module_init(config->config_m, parameters, &cur_instance->cls) == G_OK) {
            cur_instance->enabled = 1;
            ret = G_OK;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "manage_user_auth_scheme_module - Error init module %s/%s", module->name, json_string_value(json_object_get(j_module, "name")));
            ret = G_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "add_user_auth_scheme_module - Error reallocating resources for user_auth_scheme_module_instance_list");
          o_free(cur_instance->name);
          ret = G_ERROR_MEMORY;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "add_user_auth_scheme_module - Error allocating resources for cur_instance");
        ret = G_ERROR_MEMORY;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "add_user_auth_scheme_module - Module '%s' not found", json_string_value(json_object_get(j_module, "module")));
      ret = G_ERROR;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "add_user_auth_scheme_module - Error executing j_query");
    ret = G_ERROR_DB;
  }
  o_free(parameters);
  return ret;
}

int set_user_auth_scheme_module(struct config_elements * config, const char * name, json_t * j_module) {
  json_t * j_query;
  int res, ret;
  char * parameters = json_dumps(json_object_get(j_module, "parameters"), JSON_COMPACT);
  
  j_query = json_pack("{sss{sOss}s{ss}}",
                      "table",
                      GLEWLWYD_TABLE_USER_AUTH_SCHEME_MODULE_INSTANCE,
                      "set",
                        "guasmi_display_name",
                        json_object_get(j_module, "display_name")!=NULL?json_object_get(j_module, "display_name"):json_null(),
                        "guasmi_parameters",
                        parameters,
                      "where",
                        "guasmi_name",
                        name);
  o_free(parameters);
  res = h_update(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "add_user_auth_scheme_module - Error executing j_query");
    ret = G_ERROR_DB;
  }
  return ret;
}

int delete_user_auth_scheme_module(struct config_elements * config, const char * name) {
  int ret, res;
  json_t * j_query;
  struct _user_auth_scheme_module_instance * instance;
  
  if (manage_user_auth_scheme_module(config, name, GLEWLWYD_MODULE_ACTION_STOP) == G_OK) {
    instance = get_user_auth_scheme_module_instance(config, name);
    if (pointer_list_remove_pointer(config->user_auth_scheme_module_instance_list, instance)) {
      o_free(instance->name);
      o_free(instance);
      j_query = json_pack("{sss{ss}}",
                          "table",
                          GLEWLWYD_TABLE_USER_AUTH_SCHEME_MODULE_INSTANCE,
                          "where",
                            "guasmi_name",
                            name);
      res = h_delete(config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        ret = G_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "delete_user_auth_scheme_module - Error executing j_query");
        ret = G_ERROR_DB;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "delete_user_auth_scheme_module - Error pointer_list_remove_pointer");
      ret = G_ERROR;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "delete_user_auth_scheme_module - Error action not found");
    ret = G_ERROR;
  }
  return ret;
}

int manage_user_auth_scheme_module(struct config_elements * config, const char * name, int action) {
  struct _user_auth_scheme_module_instance * instance = get_user_auth_scheme_module_instance(config, name);
  json_t * j_module = get_user_auth_scheme_module(config, name);
  int ret;
  
  if (check_result_value(j_module, G_OK) && instance != NULL) {
    if (action == GLEWLWYD_MODULE_ACTION_START) {
      if (!instance->enabled) {
        if (instance->module->user_auth_scheme_module_init(config->config_m, json_string_value(json_object_get(j_module, "parameters")), &instance->cls) == G_OK) {
          instance->enabled = 1;
          ret = G_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "manage_user_auth_scheme_module - Error init module %s/%s", instance->module->name, json_string_value(json_object_get(j_module, "name")));
          ret = G_ERROR;
        }
      } else {
        ret = G_ERROR_PARAM;
      }
    } else if (action == GLEWLWYD_MODULE_ACTION_STOP) {
      if (instance->enabled) {
        if (instance->module->user_auth_scheme_module_close(config->config_m, instance->cls) == G_OK) {
          instance->enabled = 0;
          ret = G_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "manage_user_auth_scheme_module - Error close module %s/%s", instance->module->name, json_string_value(json_object_get(j_module, "name")));
          ret = G_ERROR;
        }
      } else {
        ret = G_ERROR_PARAM;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "manage_user_auth_scheme_module - Error action not found");
      ret = G_ERROR_PARAM;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "manage_user_auth_scheme_module - Error module not found");
    ret = G_ERROR_PARAM;
  }
  json_decref(j_module);
  return ret;
}

json_t * get_client_module_list(struct config_elements * config) {
  int res;
  json_t * j_query, * j_result = NULL, * j_return, * j_parameters, * j_element;
  size_t index;
  struct _client_module_instance * cur_instance;
  
  j_query = json_pack("{sss[ssssss]ss}",
                      "table",
                      GLEWLWYD_TABLE_CLIENT_MODULE_INSTANCE,
                      "columns",
                        "gcmi_module AS module",
                        "gcmi_name AS name",
                        "gcmi_display_name AS display_name",
                        "gcmi_parameters",
                        "gcmi_order AS order_rank",
                        "gcmi_order AS order_rank",
                      "order_by",
                      "gcmi_order");
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    json_array_foreach(j_result, index, j_element) {
      j_parameters = json_loads(json_string_value(json_object_get(j_element, "gcmi_parameters")), JSON_DECODE_ANY, NULL);
      if (j_parameters != NULL) {
        json_object_set_new(j_element, "parameters", j_parameters);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_client_module_list - Error parsing parameters for module %s", json_string_value(json_object_get(j_element, "name")));
        json_object_set_new(j_element, "parameters", json_null());
      }
      json_object_del(j_element, "gcmi_parameters");
      
      json_object_set_new(j_element, "readonly", json_integer_value(json_object_get(j_element, "gcmi_readonly"))?json_true():json_false());
      json_object_del(j_element, "gcmi_readonly");
      
      cur_instance = get_client_module_instance(config, json_string_value(json_object_get(j_element, "name")));
      if (cur_instance != NULL) {
        json_object_set(j_element, "enabled", cur_instance->enabled?json_true():json_false());
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_client_module_list - Error instance %s not found in app config", json_string_value(json_object_get(j_element, "name")));
        json_object_set(j_element, "enabled", json_false());
      }
    }
    j_return = json_pack("{sisO}", "result", G_OK, "module", j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_client_module_list - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  json_decref(j_result);
  return j_return;
}

json_t * get_client_module(struct config_elements * config, const char * name) {
  int res;
  json_t * j_query, * j_result = NULL, * j_return, * j_parameters;
  struct _client_module_instance * cur_instance;
  
  j_query = json_pack("{sss[ssssss]s{ss}}",
                      "table",
                      GLEWLWYD_TABLE_CLIENT_MODULE_INSTANCE,
                      "columns",
                        "gcmi_module AS module",
                        "gcmi_name AS name",
                        "gcmi_display_name AS display_name",
                        "gcmi_parameters",
                        "gcmi_order AS order_rank",
                        "gcmi_order AS order_rank",
                      "where",
                        "gcmi_name",
                        name);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result) > 0) {
      j_parameters = json_loads(json_string_value(json_object_get(json_array_get(j_result, 0), "gcmi_parameters")), JSON_DECODE_ANY, NULL);
      if (j_parameters != NULL) {
        json_object_set_new(json_array_get(j_result, 0), "parameters", j_parameters);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_client_module_list - Error parsing parameters for module %s", json_string_value(json_object_get(json_array_get(j_result, 0), "name")));
        json_object_set_new(json_array_get(j_result, 0), "parameters", json_null());
      }
      json_object_del(json_array_get(j_result, 0), "gcmi_parameters");
      
      json_object_set_new(json_array_get(j_result, 0), "readonly", json_integer_value(json_object_get(json_array_get(j_result, 0), "gcmi_readonly"))?json_true():json_false());
      json_object_del(json_array_get(j_result, 0), "gcmi_readonly");
      
      cur_instance = get_client_module_instance(config, name);
      if (cur_instance != NULL) {
        json_object_set(json_array_get(j_result, 0), "enabled", cur_instance->enabled?json_true():json_false());
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_client_module_list - Error instance %s not found in app config", name);
        json_object_set(json_array_get(j_result, 0), "enabled", json_false());
      }
      j_return = json_pack("{sisO}", "result", G_OK, "module", j_result);
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_client_module_list - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  json_decref(j_result);
  return j_return;
}

json_t * is_client_module_valid(struct config_elements * config, json_t * j_module, int add) {
  json_t * j_return, * j_cur_module, * j_error_list;
  int i, found;
  struct _client_module * module;
  char * parameters;
  
  if (j_module != NULL && json_is_object(j_module)) {
    if ((j_error_list = json_array()) != NULL) {
      if (add) {
        if (json_object_get(j_module, "name") != NULL && json_is_string(json_object_get(j_module, "name")) && json_string_length(json_object_get(j_module, "name")) > 0 && json_string_length(json_object_get(j_module, "name")) <= 128) {
          j_cur_module = get_client_module(config, json_string_value(json_object_get(j_module, "name")));
          if (check_result_value(j_cur_module, G_OK)) {
            json_array_append_new(j_error_list, json_string("A module instance with this name already exist"));
          } else if (!check_result_value(j_cur_module, G_ERROR_NOT_FOUND)) {
            y_log_message(Y_LOG_LEVEL_ERROR, "is_client_module_valid - Error json_array_append_new");
          }
          json_decref(j_cur_module);
        } else {
          json_array_append_new(j_error_list, json_string("Module instance name is mandatory and must be a non empty string of at least 128 characters"));
        }
        if (json_object_get(j_module, "module") != NULL && json_is_string(json_object_get(j_module, "module")) && json_string_length(json_object_get(j_module, "module")) > 0 && json_string_length(json_object_get(j_module, "module")) <= 128) {
          found = 0;
          for (i=0; i<pointer_list_size(config->client_module_list); i++) {
            module = (struct _client_module *)pointer_list_get_at(config->client_module_list, i);
            if (module != NULL) {
              if (0 == o_strcmp(module->name, json_string_value(json_object_get(j_module, "module")))) {
                found = 1;
                break;
              }
            }
          }
          if (!found) {
            json_array_append_new(j_error_list, json_string("Module name doesn't exist"));
          }
        } else {
          json_array_append_new(j_error_list, json_string("Module is mandatory and must be a non empty string of at least 128 characters"));
        }
      }
      if (json_object_get(j_module, "display_name") != NULL && (!json_is_string(json_object_get(j_module, "display_name")) || json_string_length(json_object_get(j_module, "display_name")) == 0 || json_string_length(json_object_get(j_module, "display_name")) > 256)) {
        json_array_append_new(j_error_list, json_string("display_name is optional and must be a non empty string of at least 256 characters"));
      }
      if (json_object_get(j_module, "parameters") == NULL || !json_is_object(json_object_get(j_module, "parameters"))) {
        json_array_append_new(j_error_list, json_string("Parameters is mandatory and must be a json object of at least 16k characters"));
      } else {
        parameters = json_dumps(json_object_get(j_module, "parameters"), JSON_COMPACT);
        if (parameters == NULL || o_strlen(parameters) > 16*1024) {
          json_array_append_new(j_error_list, json_string("Parameters is mandatory and must be a json object of at least 16k characters"));
        }
        o_free(parameters);
      }
      if (json_object_get(j_module, "order_rank") != NULL && (!json_is_integer(json_object_get(j_module, "order_rank")) || json_integer_value(json_object_get(j_module, "order_rank")) < 0)) {
        json_array_append_new(j_error_list, json_string("order_rank is optional and must be a positive integer"));
      }
      if (json_object_get(j_module, "readonly") != NULL && !json_is_boolean(json_object_get(j_module, "readonly"))) {
        json_array_append_new(j_error_list, json_string("readonly is optional and must be a boolean"));
      }
      if (json_array_size(j_error_list) > 0) {
        j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", j_error_list);
      } else {
        j_return = json_pack("{si}", "result", G_OK);
      }
      json_decref(j_error_list);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "is_client_module_valid - Error allocating resources for j_error_list");
      j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
    }
  } else {
    j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "errors", "module must be a JSON object");
  }
  return j_return;
}

int add_client_module(struct config_elements * config, json_t * j_module) {
  struct _client_module * module;
  struct _client_module_instance * cur_instance;
  json_t * j_query;
  int res, ret, i;
  char * parameters = json_dumps(json_object_get(j_module, "parameters"), JSON_COMPACT);
  
  j_query = json_pack("{sss{sOsOsOsOss}}",
                      "table",
                      GLEWLWYD_TABLE_CLIENT_MODULE_INSTANCE,
                      "values",
                        "gcmi_module",
                        json_object_get(j_module, "module"),
                        "gcmi_name",
                        json_object_get(j_module, "name"),
                        "gcmi_display_name",
                        json_object_get(j_module, "display_name")!=NULL?json_object_get(j_module, "display_name"):json_null(),
                        "gcmi_readonly",
                        json_object_get(j_module, "readonly")!=NULL?json_object_get(j_module, "readonly"):json_false(),
                        "gcmi_parameters",
                        parameters);
  if (json_object_get(j_module, "order_rank") != NULL) {
    json_object_set(json_object_get(j_query, "values"), "gcmi_order", json_object_get(j_module, "order_rank"));
  } else {
    json_object_set_new(json_object_get(j_query, "values"), "gcmi_order", json_integer(pointer_list_size(config->client_module_list)));
  }
  res = h_insert(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    module = NULL;
    for (i=0; i<pointer_list_size(config->client_module_list); i++) {
      module = (struct _client_module *)pointer_list_get_at(config->client_module_list, i);
      if (0 == o_strcmp(module->name, json_string_value(json_object_get(j_module, "module")))) {
        break;
      } else {
        module = NULL;
      }
    }
    if (module != NULL) {
      cur_instance = o_malloc(sizeof(struct _client_module_instance));
      if (cur_instance != NULL) {
        cur_instance->cls = NULL;
        cur_instance->name = o_strdup(json_string_value(json_object_get(j_module, "name")));
        cur_instance->module = module;
        cur_instance->enabled = 0;
        cur_instance->readonly = json_object_get(j_module, "readonly")==json_false()?0:1;
        if (pointer_list_append(config->client_module_instance_list, cur_instance)) {
          if (module->client_module_init(config->config_m, parameters, &cur_instance->cls) == G_OK) {
            cur_instance->enabled = 1;
            ret = G_OK;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "manage_client_module - Error init module %s/%s", module->name, json_string_value(json_object_get(j_module, "name")));
            ret = G_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "add_client_module - Error reallocating resources for client_module_instance_list");
          o_free(cur_instance->name);
          ret = G_ERROR_MEMORY;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "add_client_module - Error allocating resources for cur_instance");
        ret = G_ERROR_MEMORY;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "add_client_module - Module '%s' not found", json_string_value(json_object_get(j_module, "module")));
      ret = G_ERROR;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "add_client_module - Error executing j_query");
    ret = G_ERROR_DB;
  }
  o_free(parameters);
  return ret;
}

int set_client_module(struct config_elements * config, const char * name, json_t * j_module) {
  json_t * j_query;
  int res, ret;
  char * parameters = json_dumps(json_object_get(j_module, "parameters"), JSON_COMPACT);
  
  j_query = json_pack("{sss{sOss}s{ss}}",
                      "table",
                      GLEWLWYD_TABLE_CLIENT_MODULE_INSTANCE,
                      "set",
                        "gcmi_display_name",
                        json_object_get(j_module, "display_name")!=NULL?json_object_get(j_module, "display_name"):json_null(),
                        "gcmi_parameters",
                        parameters,
                      "where",
                        "gcmi_name",
                        name);
  if (json_object_get(j_module, "order_rank") != NULL) {
    json_object_set(json_object_get(j_query, "set"), "gcmi_order", json_object_get(j_module, "order_rank"));
  } else {
    json_object_set_new(json_object_get(j_query, "set"), "gcmi_order", json_integer(pointer_list_size(config->client_module_list)));
  }
  if (json_object_get(j_module, "readonly") != NULL) {
    json_object_set_new(json_object_get(j_query, "set"), "gcmi_readonly", json_object_get(j_module, "readonly")==json_true()?json_integer(1):json_integer(0));
  }
  o_free(parameters);
  res = h_update(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "add_client_module - Error executing j_query");
    ret = G_ERROR_DB;
  }
  return ret;
}

int delete_client_module(struct config_elements * config, const char * name) {
  int ret, res;
  json_t * j_query;
  struct _client_module_instance * instance;
  
  if (manage_client_module(config, name, GLEWLWYD_MODULE_ACTION_STOP) == G_OK) {
    instance = get_client_module_instance(config, name);
    if (pointer_list_remove_pointer(config->client_module_instance_list, instance)) {
      o_free(instance->name);
      o_free(instance);
      j_query = json_pack("{sss{ss}}",
                          "table",
                          GLEWLWYD_TABLE_CLIENT_MODULE_INSTANCE,
                          "where",
                            "gcmi_name",
                            name);
      res = h_delete(config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        ret = G_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "delete_client_module - Error executing j_query");
        ret = G_ERROR_DB;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "delete_client_module - Error pointer_list_remove_pointer");
      ret = G_ERROR;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "delete_client_module - Error action not found");
    ret = G_ERROR;
  }
  return ret;
}

int manage_client_module(struct config_elements * config, const char * name, int action) {
  struct _client_module_instance * instance = get_client_module_instance(config, name);
  json_t * j_module = get_client_module(config, name);
  int ret;
  
  if (check_result_value(j_module, G_OK) && instance != NULL) {
    if (action == GLEWLWYD_MODULE_ACTION_START) {
      if (!instance->enabled) {
        if (instance->module->client_module_init(config->config_m, json_string_value(json_object_get(j_module, "parameters")), &instance->cls) == G_OK) {
          instance->enabled = 1;
          ret = G_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "manage_client_module - Error init module %s/%s", instance->module->name, json_string_value(json_object_get(j_module, "name")));
          ret = G_ERROR;
        }
      } else {
        ret = G_ERROR_PARAM;
      }
    } else if (action == GLEWLWYD_MODULE_ACTION_STOP) {
      if (instance->enabled) {
        if (instance->module->client_module_close(config->config_m, instance->cls) == G_OK) {
          instance->enabled = 0;
          ret = G_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "manage_client_module - Error close module %s/%s", instance->module->name, json_string_value(json_object_get(j_module, "name")));
          ret = G_ERROR;
        }
      } else {
        ret = G_ERROR_PARAM;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "manage_client_module - Error action not found");
      ret = G_ERROR_PARAM;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "manage_client_module - Error module not found");
    ret = G_ERROR_PARAM;
  }
  json_decref(j_module);
  return ret;
}

json_t * get_plugin_module_list(struct config_elements * config) {
  int res;
  json_t * j_query, * j_result = NULL, * j_return, * j_parameters, * j_element;
  size_t index;
  struct _plugin_module_instance * cur_instance;
  
  j_query = json_pack("{sss[ssss]ss}",
                      "table",
                      GLEWLWYD_TABLE_PLUGIN_MODULE_INSTANCE,
                      "columns",
                        "gpmi_module AS module",
                        "gpmi_name AS name",
                        "gpmi_display_name AS display_name",
                        "gpmi_parameters",
                      "order_by",
                      "gpmi_module,gpmi_name");
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    json_array_foreach(j_result, index, j_element) {
      j_parameters = json_loads(json_string_value(json_object_get(j_element, "gpmi_parameters")), JSON_DECODE_ANY, NULL);
      if (j_parameters != NULL) {
        json_object_set_new(j_element, "parameters", j_parameters);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_plugin_module_list - Error parsing parameters for module %s", json_string_value(json_object_get(j_element, "name")));
        json_object_set_new(j_element, "parameters", json_null());
      }
      json_object_del(j_element, "gpmi_parameters");
      
      cur_instance = get_plugin_module_instance(config, json_string_value(json_object_get(j_element, "name")));
      if (cur_instance != NULL) {
        json_object_set(j_element, "enabled", cur_instance->enabled?json_true():json_false());
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_plugin_module_list - Error instance %s not found in app config", json_string_value(json_object_get(j_element, "name")));
        json_object_set(j_element, "enabled", json_false());
      }
    }
    j_return = json_pack("{sisO}", "result", G_OK, "module", j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_plugin_module_list - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  json_decref(j_result);
  return j_return;
}

json_t * get_plugin_module(struct config_elements * config, const char * name) {
  int res;
  json_t * j_query, * j_result = NULL, * j_return, * j_parameters;
  struct _plugin_module_instance * cur_instance;
  
  j_query = json_pack("{sss[ssss]s{ss}}",
                      "table",
                      GLEWLWYD_TABLE_PLUGIN_MODULE_INSTANCE,
                      "columns",
                        "gpmi_module AS module",
                        "gpmi_name AS name",
                        "gpmi_display_name AS display_name",
                        "gpmi_parameters",
                      "where",
                        "gpmi_name",
                        name);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result) > 0) {
      j_parameters = json_loads(json_string_value(json_object_get(json_array_get(j_result, 0), "gpmi_parameters")), JSON_DECODE_ANY, NULL);
      if (j_parameters != NULL) {
        json_object_set_new(json_array_get(j_result, 0), "parameters", j_parameters);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_plugin_module_list - Error parsing parameters for module %s", json_string_value(json_object_get(json_array_get(j_result, 0), "name")));
        json_object_set_new(json_array_get(j_result, 0), "parameters", json_null());
      }
      json_object_del(json_array_get(j_result, 0), "gpmi_parameters");
      
      cur_instance = get_plugin_module_instance(config, name);
      if (cur_instance != NULL) {
        json_object_set(json_array_get(j_result, 0), "enabled", cur_instance->enabled?json_true():json_false());
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_plugin_module_list - Error instance %s not found in app config", name);
        json_object_set(json_array_get(j_result, 0), "enabled", json_false());
      }
      j_return = json_pack("{sisO}", "result", G_OK, "module", j_result);
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_plugin_module_list - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  json_decref(j_result);
  return j_return;
}

json_t * is_plugin_module_valid(struct config_elements * config, json_t * j_module, int add) {
  json_t * j_return, * j_cur_module, * j_error_list;
  int i, found;
  struct _plugin_module * module;
  char * parameters;
  
  if (j_module != NULL && json_is_object(j_module)) {
    if ((j_error_list = json_array()) != NULL) {
      if (add) {
        if (json_object_get(j_module, "name") != NULL && json_is_string(json_object_get(j_module, "name")) && json_string_length(json_object_get(j_module, "name")) > 0 && json_string_length(json_object_get(j_module, "name")) <= 128) {
          j_cur_module = get_plugin_module(config, json_string_value(json_object_get(j_module, "name")));
          if (check_result_value(j_cur_module, G_OK)) {
            json_array_append_new(j_error_list, json_string("A module instance with this name already exist"));
          } else if (!check_result_value(j_cur_module, G_ERROR_NOT_FOUND)) {
            y_log_message(Y_LOG_LEVEL_ERROR, "is_plugin_module_valid - Error json_array_append_new");
          }
          json_decref(j_cur_module);
        } else {
          json_array_append_new(j_error_list, json_string("Module instance name is mandatory and must be a non empty string of at least 128 characters"));
        }
        if (json_object_get(j_module, "module") != NULL && json_is_string(json_object_get(j_module, "module")) && json_string_length(json_object_get(j_module, "module")) > 0 && json_string_length(json_object_get(j_module, "module")) <= 128) {
          found = 0;
          for (i=0; i<pointer_list_size(config->plugin_module_list); i++) {
            module = (struct _plugin_module *)pointer_list_get_at(config->plugin_module_list, i);
            if (module != NULL) {
              if (0 == o_strcmp(module->name, json_string_value(json_object_get(j_module, "module")))) {
                found = 1;
                break;
              }
            }
          }
          if (!found) {
            json_array_append_new(j_error_list, json_string("Module name doesn't exist"));
          }
        } else {
          json_array_append_new(j_error_list, json_string("Module is mandatory and must be a non empty string of at least 128 characters"));
        }
      }
      if (json_object_get(j_module, "display_name") != NULL && (!json_is_string(json_object_get(j_module, "display_name")) || json_string_length(json_object_get(j_module, "display_name")) == 0 || json_string_length(json_object_get(j_module, "display_name")) > 256)) {
        json_array_append_new(j_error_list, json_string("display_name is optional and must be a non empty string of at least 256 characters"));
      }
      if (json_object_get(j_module, "parameters") == NULL || !json_is_object(json_object_get(j_module, "parameters"))) {
        json_array_append_new(j_error_list, json_string("Parameters is mandatory and must be a json object of at least 16k characters"));
      } else {
        parameters = json_dumps(json_object_get(j_module, "parameters"), JSON_COMPACT);
        if (parameters == NULL || o_strlen(parameters) > 16*1024) {
          json_array_append_new(j_error_list, json_string("Parameters is mandatory and must be a json object of at least 16k characters"));
        }
        o_free(parameters);
      }
      if (json_array_size(j_error_list) > 0) {
        j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", j_error_list);
      } else {
        j_return = json_pack("{si}", "result", G_OK);
      }
      json_decref(j_error_list);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "is_plugin_module_valid - Error allocating resources for j_error_list");
      j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
    }
  } else {
    j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "errors", "module must be a JSON object");
  }
  return j_return;
}

int add_plugin_module(struct config_elements * config, json_t * j_module) {
  struct _plugin_module * module;
  struct _plugin_module_instance * cur_instance;
  json_t * j_query;
  int res, ret, i;
  char * parameters = json_dumps(json_object_get(j_module, "parameters"), JSON_COMPACT);
  
  j_query = json_pack("{sss{sOsOsOss}}",
                      "table",
                      GLEWLWYD_TABLE_PLUGIN_MODULE_INSTANCE,
                      "values",
                        "gpmi_module",
                        json_object_get(j_module, "module"),
                        "gpmi_name",
                        json_object_get(j_module, "name"),
                        "gpmi_display_name",
                        json_object_get(j_module, "display_name")!=NULL?json_object_get(j_module, "display_name"):json_null(),
                        "gpmi_parameters",
                        parameters);
  res = h_insert(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    module = NULL;
    for (i=0; i<pointer_list_size(config->plugin_module_list); i++) {
      module = (struct _plugin_module *)pointer_list_get_at(config->plugin_module_list, i);
      if (0 == o_strcmp(module->name, json_string_value(json_object_get(j_module, "module")))) {
        break;
      } else {
        module = NULL;
      }
    }
    if (module != NULL) {
      cur_instance = o_malloc(sizeof(struct _plugin_module_instance));
      if (cur_instance != NULL) {
        cur_instance->cls = NULL;
        cur_instance->name = o_strdup(json_string_value(json_object_get(j_module, "name")));
        cur_instance->module = module;
        cur_instance->enabled = 0;
        if (pointer_list_append(config->plugin_module_instance_list, cur_instance)) {
          if (module->plugin_module_init(config->config_p, parameters, &cur_instance->cls) == G_OK) {
            cur_instance->enabled = 1;
            ret = G_OK;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "manage_plugin_module - Error init module %s/%s", module->name, json_string_value(json_object_get(j_module, "name")));
            ret = G_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "add_plugin_module - Error reallocating resources for plugin_module_instance_list");
          o_free(cur_instance->name);
          ret = G_ERROR_MEMORY;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "add_plugin_module - Error allocating resources for cur_instance");
        ret = G_ERROR_MEMORY;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "add_plugin_module - Module '%s' not found", json_string_value(json_object_get(j_module, "module")));
      ret = G_ERROR;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "add_plugin_module - Error executing j_query");
    ret = G_ERROR_DB;
  }
  o_free(parameters);
  return ret;
}

int set_plugin_module(struct config_elements * config, const char * name, json_t * j_module) {
  json_t * j_query;
  int res, ret;
  char * parameters = json_dumps(json_object_get(j_module, "parameters"), JSON_COMPACT);
  
  j_query = json_pack("{sss{sOss}s{ss}}",
                      "table",
                      GLEWLWYD_TABLE_PLUGIN_MODULE_INSTANCE,
                      "set",
                        "gpmi_display_name",
                        json_object_get(j_module, "display_name")!=NULL?json_object_get(j_module, "display_name"):json_null(),
                        "gpmi_parameters",
                        parameters,
                      "where",
                        "gpmi_name",
                        name);
  o_free(parameters);
  res = h_update(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "add_plugin_module - Error executing j_query");
    ret = G_ERROR_DB;
  }
  return ret;
}

int delete_plugin_module(struct config_elements * config, const char * name) {
  int ret, res;
  json_t * j_query;
  struct _plugin_module_instance * instance;
  
  if (manage_plugin_module(config, name, GLEWLWYD_MODULE_ACTION_STOP) == G_OK) {
    instance = get_plugin_module_instance(config, name);
    if (pointer_list_remove_pointer(config->plugin_module_instance_list, instance)) {
      o_free(instance->name);
      o_free(instance);
      j_query = json_pack("{sss{ss}}",
                          "table",
                          GLEWLWYD_TABLE_PLUGIN_MODULE_INSTANCE,
                          "where",
                            "gpmi_name",
                            name);
      res = h_delete(config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        ret = G_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "delete_plugin_module - Error executing j_query");
        ret = G_ERROR_DB;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "delete_plugin_module - Error pointer_list_remove_pointer");
      ret = G_ERROR;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "delete_plugin_module - Error action not found");
    ret = G_ERROR;
  }
  return ret;
}

int manage_plugin_module(struct config_elements * config, const char * name, int action) {
  struct _plugin_module_instance * instance = get_plugin_module_instance(config, name);
  json_t * j_module = get_plugin_module(config, name);
  int ret;
  
  if (check_result_value(j_module, G_OK) && instance != NULL) {
    if (action == GLEWLWYD_MODULE_ACTION_START) {
      if (!instance->enabled) {
        if (instance->module->plugin_module_init(config->config_p, json_string_value(json_object_get(j_module, "parameters")), &instance->cls) == G_OK) {
          instance->enabled = 1;
          ret = G_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "manage_plugin_module - Error init module %s/%s", instance->module->name, json_string_value(json_object_get(j_module, "name")));
          ret = G_ERROR;
        }
      } else {
        ret = G_ERROR_PARAM;
      }
    } else if (action == GLEWLWYD_MODULE_ACTION_STOP) {
      if (instance->enabled) {
        if (instance->module->plugin_module_close(config->config_p, instance->cls) == G_OK) {
          instance->enabled = 0;
          ret = G_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "manage_plugin_module - Error close module %s/%s", instance->module->name, json_string_value(json_object_get(j_module, "name")));
          ret = G_ERROR;
        }
      } else {
        ret = G_ERROR_PARAM;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "manage_plugin_module - Error action not found");
      ret = G_ERROR_PARAM;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "manage_plugin_module - Error module not found");
    ret = G_ERROR_PARAM;
  }
  json_decref(j_module);
  return ret;
}
