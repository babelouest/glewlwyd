/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * user management functions definition
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

json_t * auth_check_user_credentials(struct config_elements * config, const char * username, const char * password) {
  int res;
  json_t * j_return = NULL, * j_module_list = get_user_module_list(config), * j_module;
  struct _user_module_instance * user_module;
  size_t index;
  
  if (check_result_value(j_module_list, G_OK)) {
    json_array_foreach(json_object_get(j_module_list, "module"), index, j_module) {
      user_module = get_user_module_instance(config, json_string_value(json_object_get(j_module, "name")));
      if (user_module != NULL) {
        if (user_module->enabled) {
          res = user_module->module->user_module_check_password(username, password, user_module->cls);
          if (res == G_OK) {
            j_return = json_pack("{si}", "result", G_OK);
          } else if (res == G_ERROR_UNAUTHORIZED) {
            j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
          } else if (res != G_ERROR_NOT_FOUND) {
            y_log_message(Y_LOG_LEVEL_ERROR, "auth_check_user_credentials - Error, user_module_check_password for module '%s', skip", user_module->name);
          }
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "auth_check_user_credentials - Error, user_module_instance %s is NULL", json_string_value(json_object_get(j_module, "name")));
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "auth_check_user_credentials - Error get_user_module_list");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  if (j_return == NULL) {
    j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  }
  json_decref(j_module_list);
  return j_return;
}

json_t * auth_check_user_scheme(struct config_elements * config, const char * scheme_type, const char * scheme_name, const char * username, json_t * scheme_value) {
  struct _user_auth_scheme_module_instance * scheme_instance;
  json_t * j_return = NULL;
  char * str_scheme_value = json_dumps(scheme_value, JSON_COMPACT);
  int res;
  
  if (NULL != str_scheme_value) {
    scheme_instance = get_user_auth_scheme_module_instance(config, scheme_name);
    if (scheme_instance != NULL && 0 == o_strcmp(scheme_type, scheme_instance->module->name)) {
      res = scheme_instance->module->user_auth_scheme_module_validate(username, str_scheme_value, scheme_instance->cls);
      if (res == G_OK || res == G_ERROR_UNAUTHORIZED || res == G_ERROR_PARAM || res == G_ERROR_NOT_FOUND) {
        j_return = json_pack("{si}", "result", res);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "auth_check_user_scheme - Error unrecognize return value for user_auth_scheme_module_validate: %d", res);
        j_return = json_pack("{si}", "result", G_ERROR);
      }
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
    }
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  o_free(str_scheme_value);
  return j_return;
}

json_t * auth_trigger_user_scheme(struct config_elements * config, const char * scheme_type, const char * scheme_name, const char * username, json_t * trigger_parameters) {
  struct _user_auth_scheme_module_instance * scheme_instance;
  json_t * j_return = NULL, * j_response = NULL;
  char * str_trigger_parameters = json_dumps(trigger_parameters, JSON_COMPACT), * str_trigger_response = NULL;
  int res;
  
  if (NULL != str_trigger_parameters) {
    scheme_instance = get_user_auth_scheme_module_instance(config, scheme_name);
    if (scheme_instance != NULL && 0 == o_strcmp(scheme_type, scheme_instance->module->name)) {
      res = scheme_instance->module->user_auth_scheme_module_trigger(username, str_trigger_parameters, &str_trigger_response, scheme_instance->cls);
      if (res == G_OK) {
        j_response = json_loads(str_trigger_response, JSON_DECODE_ANY, NULL);
        if (j_response != NULL) {
          j_return = json_pack("{sisO}", "result", res, "trigger", j_response);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "auth_trigger_user_scheme - Error parsing trigger response into JSON format: %s", str_trigger_response);
        }
        json_decref(j_response);
      } else if (res != G_ERROR) {
        j_return = json_pack("{si}", "result", res);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "auth_trigger_user_scheme - Error unrecognize return value for user_auth_scheme_module_trigger: %d", res);
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      o_free(str_trigger_response);
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
    }
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  o_free(str_trigger_parameters);
  return j_return;
}

int user_has_scope(json_t * j_user, const char * scope) {
  json_t * j_element;
  size_t index;
  
  json_array_foreach(json_object_get(j_user, "scope"), index, j_element) {
    if (0 == o_strcmp(scope, json_string_value(j_element))) {
      return 1;
    }
  }
  return 0;
}

json_t * get_user(struct config_elements * config, const char * username, const char * source) {
  int found = 0, result;
  char * str_user;
  json_t * j_return = NULL, * j_user, * j_module_list, * j_module;
  struct _user_module_instance * user_module;
  size_t index;
  
  if (source != NULL) {
    user_module = get_user_module_instance(config, source);
    if (user_module != NULL) {
      result = G_ERROR;
      str_user = user_module->module->user_module_get(username, &result, user_module->cls);
      if (result == G_OK && str_user != NULL) {
        j_user = json_loads(str_user, JSON_DECODE_ANY, NULL);
        if (j_user != NULL) {
          j_return = json_pack("{sisO}", "result", G_OK, "user", j_user);
          json_decref(j_user);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_user - Error json_loads");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
      } else if (result != G_OK && result != G_ERROR_NOT_FOUND) {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_user - Error, user_module_get for module %s", user_module->name);
        j_return = json_pack("{si}", "result", G_ERROR);
      } else {
        j_return = json_pack("{si}", "result", result);
      }
      o_free(str_user);
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
  } else {
    j_module_list = get_user_module_list(config);
    if (check_result_value(j_module_list, G_OK)) {
      json_array_foreach(json_object_get(j_module_list, "module"), index, j_module) {
        if (!found) {
          user_module = get_user_module_instance(config, json_string_value(json_object_get(j_module, "name")));
          if (user_module != NULL) {
            if (user_module->enabled) {
              result = G_ERROR;
              str_user = user_module->module->user_module_get(username, &result, user_module->cls);
              if (result == G_OK && str_user != NULL) {
                j_user = json_loads(str_user, JSON_DECODE_ANY, NULL);
                if (j_user != NULL) {
                  found = 1;
                  j_return = json_pack("{sisO}", "result", G_OK, "user", j_user);
                  json_decref(j_user);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "get_user - Error json_loads");
                }
                found = 1;
              } else if (result != G_OK && result != G_ERROR_NOT_FOUND) {
                y_log_message(Y_LOG_LEVEL_ERROR, "get_user - Error, user_module_get for module %s", user_module->name);
              }
              o_free(str_user);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_user - Error, user_module_instance %s is NULL", json_string_value(json_object_get(j_module, "name")));
          }
        }
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_user - Error get_user_module_list");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_module_list);
  }
  if (j_return == NULL) {
    j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
  }
  return j_return;
}

json_t * get_user_list(struct config_elements * config, const char * pattern, size_t offset, size_t limit, const char * source) {
  json_t * j_return, * j_module_list, * j_module, * j_list_parsed;
  struct _user_module_instance * user_module;
  char * list_result = NULL;
  int result;
  size_t cur_offset, cur_limit, count_total, index;
  
  if (source != NULL) {
    user_module = get_user_module_instance(config, source);
    if (user_module != NULL && user_module->enabled) {
      result = G_ERROR;
      list_result = user_module->module->user_module_get_list(pattern, offset, limit, &result, user_module->cls);
      if (result == G_OK) {
        j_list_parsed = json_loads(list_result, JSON_DECODE_ANY, NULL);
        if (j_list_parsed && json_is_array(j_list_parsed)) {
          j_return = json_pack("{sisO}", "result", G_OK, "user", j_list_parsed);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_user_list - Error parsing user_module_get_list result into a JSON array");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
        json_decref(j_list_parsed);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_user_list - Error user_module_get_list");
        j_return = json_pack("{si}", "result", result);
      }
      o_free(list_result);
    } else if (user_module != NULL && !user_module->enabled) {
      j_return = json_pack("{si}", "result", G_ERROR_PARAM);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_user_list - Error get_user_module_instance");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
  } else {
    j_module_list = get_user_module_list(config);
    if (check_result_value(j_module_list, G_OK)) {
      cur_offset = offset;
      cur_limit = limit;
      j_return = json_pack("{sis[]}", "result", G_OK, "user");
      if (j_return != NULL) {
        json_array_foreach(json_object_get(j_module_list, "module"), index, j_module) {
          user_module = get_user_module_instance(config, json_string_value(json_object_get(j_module, "name")));
          if (user_module != NULL && user_module->enabled) {
            result = G_ERROR;
            if ((count_total = user_module->module->user_module_count_total(user_module->cls)) > cur_offset) {
              list_result = user_module->module->user_module_get_list(pattern, cur_offset, cur_limit, &result, user_module->cls);
              if (result == G_OK) {
                j_list_parsed = json_loads(list_result, JSON_DECODE_ANY, NULL);
                if (j_list_parsed && json_is_array(j_list_parsed)) {
                  cur_offset = 0;
                  if (cur_limit > json_array_size(j_list_parsed)) {
                    cur_limit -= json_array_size(j_list_parsed);
                  } else {
                    cur_limit = 0;
                  }
                  json_array_extend(json_object_get(j_return, "user"), j_list_parsed);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "get_user_list - Error parsing user_module_get_list result into a JSON array for module %s", json_string_value(json_object_get(j_module, "name")));
                  j_return = json_pack("{si}", "result", G_ERROR);
                }
                json_decref(j_list_parsed);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "get_user_list - Error user_module_get_list for module %s", json_string_value(json_object_get(j_module, "name")));
              }
              o_free(list_result);
            } else {
              cur_offset -= count_total;
            }
          } else if (user_module == NULL) {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_user_list - Error, user_module_instance %s is NULL", json_string_value(json_object_get(j_module, "name")));
          }
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_user_list - Error allocating resources for j_return");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_user_list - Error get_user_module_list");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_module_list);
  }
  return j_return;
}

json_t * is_user_valid(struct config_elements * config, const char * username, json_t * j_user, int add, const char * source) {
  int found = 0, result;
  char * str_error, * str_user;
  json_t * j_return = NULL, * j_error_list, * j_module_list, * j_module;
  struct _user_module_instance * user_module;
  size_t index;
  
  if (source != NULL) {
    user_module = get_user_module_instance(config, source);
    if (user_module != NULL && user_module->enabled && !user_module->readonly) {
      str_user = json_dumps(j_user, JSON_COMPACT);
      result = G_ERROR;
      str_error = user_module->module->user_is_valid(username, str_user, add?GLEWLWYD_IS_VALID_MODE_ADD:GLEWLWYD_IS_VALID_MODE_UPDATE, &result, user_module->cls);
      if (result == G_ERROR_PARAM && str_error != NULL) {
        j_error_list = json_loads(str_error, JSON_DECODE_ANY, NULL);
        if (j_error_list != NULL) {
          j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", j_error_list);
          json_decref(j_error_list);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "is_user_valid - Error json_loads");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
      } else if (result == G_OK) {
        j_return = json_pack("{si}", "result", G_OK);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "is_user_valid - Error user_is_valid");
        j_return = json_pack("{si}", "result", result);
      }
      o_free(str_error);
      o_free(str_user);
    } else if (user_module != NULL && (user_module->readonly || !user_module->enabled)) {
      j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "module is unavailable");
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "is_user_valid - Error get_user_module_instance");
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
  } else {
    j_module_list = get_user_module_list(config);
    if (check_result_value(j_module_list, G_OK)) {
      json_array_foreach(json_object_get(j_module_list, "module"), index, j_module) {
        if (!found) {
          user_module = get_user_module_instance(config, json_string_value(json_object_get(j_module, "name")));
          if (user_module != NULL && user_module->enabled && !user_module->readonly) {
            found = 1;
            str_user = json_dumps(j_user, JSON_COMPACT);
            result = G_ERROR;
            str_error = user_module->module->user_is_valid(username, str_user, add?GLEWLWYD_IS_VALID_MODE_ADD:GLEWLWYD_IS_VALID_MODE_UPDATE, &result, user_module->cls);
            if (result == G_ERROR_PARAM && str_error != NULL) {
              j_error_list = json_loads(str_error, JSON_DECODE_ANY, NULL);
              if (j_error_list != NULL) {
                j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "user", j_error_list);
                json_decref(j_error_list);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "is_user_valid - Error json_loads");
              }
            } else if (result == G_OK) {
              j_return = json_pack("{si}", "result", G_OK);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "is_user_valid - Error, user_is_valid for module %s", user_module->name);
              j_return = json_pack("{si}", "result", result);
            }
            o_free(str_error);
            o_free(str_user);
          } else if (user_module == NULL) {
            y_log_message(Y_LOG_LEVEL_ERROR, "is_user_valid - Error, user_module_instance %s is NULL", json_string_value(json_object_get(j_module, "name")));
          }
        }
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "is_user_valid - Error get_user_module_list");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_module_list);
    if (j_return == NULL) {
      j_return = json_pack("{si}", "result", G_ERROR_PARAM);
    }
  }
  return j_return;
}

int add_user(struct config_elements * config, json_t * j_user, const char * source) {
  int found = 0, result, ret;
  char * str_user;
  json_t * j_module_list, * j_module;
  struct _user_module_instance * user_module;
  size_t index;
  
  if (source != NULL) {
    user_module = get_user_module_instance(config, source);
    if (user_module != NULL && user_module->enabled && !user_module->readonly) {
      str_user = json_dumps(j_user, JSON_COMPACT);
      result = user_module->module->user_module_add(str_user, user_module->cls);
      if (result == G_OK) {
        ret = G_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "add_user - Error user_module_add");
        ret = result;
      }
      o_free(str_user);
    } else if (user_module != NULL && (user_module->readonly || !user_module->enabled)) {
      ret = G_ERROR_PARAM;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "add_user - Error get_user_module_instance");
      ret = G_ERROR;
    }
  } else {
    j_module_list = get_user_module_list(config);
    if (check_result_value(j_module_list, G_OK)) {
      json_array_foreach(json_object_get(j_module_list, "module"), index, j_module) {
        if (!found) {
          user_module = get_user_module_instance(config, json_string_value(json_object_get(j_module, "name")));
          if (user_module != NULL && user_module->enabled && !user_module->readonly) {
            found = 1;
            str_user = json_dumps(j_user, JSON_COMPACT);
            result = user_module->module->user_module_add(str_user, user_module->cls);
            if (result == G_OK) {
              ret = G_OK;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "add_user - Error user_module_add");
              ret = result;
            }
            o_free(str_user);
          } else if (user_module == NULL) {
            y_log_message(Y_LOG_LEVEL_ERROR, "add_user - Error, user_module_instance %s is NULL", json_string_value(json_object_get(j_module, "name")));
          }
        }
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "add_user - Error get_user_module_list");
      ret = G_ERROR;
    }
    json_decref(j_module_list);
  }
  if (!found) {
    ret = G_ERROR_NOT_FOUND;
  }
  return ret;
}

int set_user(struct config_elements * config, const char * username, json_t * j_user, const char * source) {
  int found = 0, result, ret;
  char * str_user;
  json_t * j_module_list, * j_module;
  struct _user_module_instance * user_module;
  size_t index;
  
  if (source != NULL) {
    user_module = get_user_module_instance(config, source);
    if (user_module != NULL && user_module->enabled && !user_module->readonly) {
      o_free(user_module->module->user_module_get(username, &result, user_module->cls));
      if (result == G_OK) {
        str_user = json_dumps(j_user, JSON_COMPACT);
        result = user_module->module->user_module_update(username, str_user, user_module->cls);
        if (result == G_OK) {
          ret = G_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "set_user - Error user_module_update");
          ret = result;
        }
        o_free(str_user);
      } else if (result != G_ERROR_NOT_FOUND) {
        y_log_message(Y_LOG_LEVEL_ERROR, "set_user - Error user_module_get");
        ret = result;
      } else {
        ret = G_ERROR_NOT_FOUND;
      }
    } else if (user_module != NULL && (user_module->readonly || !user_module->enabled)) {
      ret = G_ERROR_PARAM;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "set_user - Error get_user_module_instance");
      ret = G_ERROR;
    }
  } else {
    j_module_list = get_user_module_list(config);
    if (check_result_value(j_module_list, G_OK)) {
      json_array_foreach(json_object_get(j_module_list, "module"), index, j_module) {
        if (!found) {
          user_module = get_user_module_instance(config, json_string_value(json_object_get(j_module, "name")));
          if (user_module != NULL && user_module->enabled && !user_module->readonly) {
            found = 1;
            o_free(user_module->module->user_module_get(username, &result, user_module->cls));
            if (result == G_OK) {
              str_user = json_dumps(j_user, JSON_COMPACT);
              result = user_module->module->user_module_update(username, str_user, user_module->cls);
              if (result == G_OK) {
                ret = G_OK;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "set_user - Error user_module_update");
                ret = result;
              }
              o_free(str_user);
            } else if (result != G_ERROR_NOT_FOUND) {
              y_log_message(Y_LOG_LEVEL_ERROR, "set_user - Error user_module_get");
            }
          } else if (user_module == NULL) {
            y_log_message(Y_LOG_LEVEL_ERROR, "set_user - Error, user_module_instance %s is NULL", json_string_value(json_object_get(j_module, "name")));
          }
        }
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "set_user - Error get_user_module_list");
      ret = G_ERROR;
    }
    json_decref(j_module_list);
  }
  if (!found) {
    ret = G_ERROR_NOT_FOUND;
  }
  return ret;
}

int delete_user(struct config_elements * config, const char * username, const char * source) {
  int found = 0, result, ret;
  json_t * j_module_list, * j_module;
  struct _user_module_instance * user_module;
  size_t index;
  
  if (source != NULL) {
    user_module = get_user_module_instance(config, source);
    if (user_module != NULL && user_module->enabled && !user_module->readonly) {
      o_free(user_module->module->user_module_get(username, &result, user_module->cls));
      if (result == G_OK) {
        result = user_module->module->user_module_delete(username, user_module->cls);
        if (result == G_OK) {
          ret = G_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "delete_user - Error user_module_delete");
          ret = result;
        }
      } else if (result != G_ERROR_NOT_FOUND) {
        y_log_message(Y_LOG_LEVEL_ERROR, "delete_user - Error user_module_get");
        ret = result;
      } else {
        ret = G_ERROR_NOT_FOUND;
      }
    } else if (user_module != NULL && (user_module->readonly || !user_module->enabled)) {
      ret = G_ERROR_PARAM;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "delete_user - Error get_user_module_instance");
      ret = G_ERROR;
    }
  } else {
    j_module_list = get_user_module_list(config);
    if (check_result_value(j_module_list, G_OK)) {
      json_array_foreach(json_object_get(j_module_list, "module"), index, j_module) {
        if (!found) {
          user_module = get_user_module_instance(config, json_string_value(json_object_get(j_module, "name")));
          if (user_module != NULL && user_module->enabled && !user_module->readonly) {
            found = 1;
            o_free(user_module->module->user_module_get(username, &result, user_module->cls));
            if (result == G_OK) {
              result = user_module->module->user_module_delete(username, user_module->cls);
              if (result == G_OK) {
                ret = G_OK;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "delete_user - Error user_module_delete");
                ret = result;
              }
            } else if (result != G_ERROR_NOT_FOUND) {
              y_log_message(Y_LOG_LEVEL_ERROR, "delete_user - Error user_module_get");
            }
          } else if (user_module == NULL) {
            y_log_message(Y_LOG_LEVEL_ERROR, "delete_user - Error, user_module_instance %s is NULL", json_string_value(json_object_get(j_module, "name")));
          }
        }
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "delete_user - Error get_user_module_list");
      ret = G_ERROR;
    }
    json_decref(j_module_list);
  }
  if (!found) {
    ret = G_ERROR_NOT_FOUND;
  }
  return ret;
}
