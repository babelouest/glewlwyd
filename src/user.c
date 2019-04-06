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
          res = user_module->module->user_module_check_password(config->config_m, username, password, user_module->cls);
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

json_t * auth_check_user_scheme(struct config_elements * config, const char * scheme_type, const char * scheme_name, const char * username, json_t * j_scheme_value, const struct _u_request * request) {
  struct _user_auth_scheme_module_instance * scheme_instance;
  json_t * j_return = NULL;
  int res;
  
  scheme_instance = get_user_auth_scheme_module_instance(config, scheme_name);
  if (scheme_instance != NULL && 0 == o_strcmp(scheme_type, scheme_instance->module->name)) {
    res = scheme_instance->module->user_auth_scheme_module_validate(config->config_m, request, username, j_scheme_value, scheme_instance->cls);
    if (res == G_OK || res == G_ERROR_UNAUTHORIZED || res == G_ERROR_PARAM || res == G_ERROR_NOT_FOUND) {
      j_return = json_pack("{si}", "result", res);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "auth_check_user_scheme - Error unrecognize return value for user_auth_scheme_module_validate: %d", res);
      j_return = json_pack("{si}", "result", G_ERROR);
    }
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  }
  return j_return;
}

json_t * auth_trigger_user_scheme(struct config_elements * config, const char * scheme_type, const char * scheme_name, const char * username, json_t * j_trigger_parameters, const struct _u_request * request) {
  struct _user_auth_scheme_module_instance * scheme_instance;
  json_t * j_return = NULL, * j_response = NULL;
  
  scheme_instance = get_user_auth_scheme_module_instance(config, scheme_name);
  if (scheme_instance != NULL && 0 == o_strcmp(scheme_type, scheme_instance->module->name)) {
    j_response = scheme_instance->module->user_auth_scheme_module_trigger(config->config_m, request, username, j_trigger_parameters, scheme_instance->cls);
    if (check_result_value(j_response, G_OK)) {
      j_return = json_pack("{sisO}", "result", G_OK, "trigger", json_object_get(j_response, "response"));
    } else if (!check_result_value(j_response, G_ERROR)) {
      j_return = json_incref(j_response);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "auth_trigger_user_scheme - Error user_auth_scheme_module_trigger");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_response);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  }
  return j_return;
}

json_t * auth_register_user_scheme(struct config_elements * config, const char * scheme_type, const char * scheme_name, const char * username, json_t * j_register_parameters, const struct _u_request * request) {
  struct _user_auth_scheme_module_instance * scheme_instance;
  json_t * j_return = NULL, * j_response = NULL;
  
  scheme_instance = get_user_auth_scheme_module_instance(config, scheme_name);
  if (scheme_instance != NULL && 0 == o_strcmp(scheme_type, scheme_instance->module->name)) {
    j_response = scheme_instance->module->user_auth_scheme_module_register(config->config_m, request, username, j_register_parameters, scheme_instance->cls);
    if (check_result_value(j_response, G_OK)) {
      j_return = json_pack("{sisO}", "result", G_OK, "register", json_object_get(j_response, "response"));
    } else if (!check_result_value(j_response, G_ERROR)) {
      j_return = json_incref(j_response);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "auth_register_user_scheme - Error user_auth_scheme_module_register");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_response);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  }
  return j_return;
}

json_t * auth_register_get_user_scheme(struct config_elements * config, const char * scheme_type, const char * scheme_name, const char * username, const struct _u_request * request) {
  struct _user_auth_scheme_module_instance * scheme_instance;
  json_t * j_return = NULL, * j_response = NULL;
  
  scheme_instance = get_user_auth_scheme_module_instance(config, scheme_name);
  if (scheme_instance != NULL && 0 == o_strcmp(scheme_type, scheme_instance->module->name)) {
    j_response = scheme_instance->module->user_auth_scheme_module_register_get(config->config_m, request, username, scheme_instance->cls);
    if (check_result_value(j_response, G_OK)) {
      j_return = json_pack("{sisO}", "result", G_OK, "register", json_object_get(j_response, "response"));
    } else if (!check_result_value(j_response, G_ERROR)) {
      j_return = json_incref(j_response);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "auth_register_get_user_scheme - Error user_auth_scheme_module_register_get");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_response);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  }
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
  int found = 0;
  json_t * j_return = NULL, * j_user, * j_module_list, * j_module;
  struct _user_module_instance * user_module;
  size_t index;
  
  if (source != NULL) {
    user_module = get_user_module_instance(config, source);
    if (user_module != NULL) {
      j_user = user_module->module->user_module_get(config->config_m, username, user_module->cls);
      if (check_result_value(j_user, G_OK)) {
        json_object_set_new(j_user, "source", json_string(source));
        j_return = json_pack("{sisO}", "result", G_OK, "user", json_object_get(j_user, "user"));
      } else if (check_result_value(j_user, G_ERROR_NOT_FOUND)) {
        j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_user - Error, user_module_get for module %s", user_module->name);
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      json_decref(j_user);
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
              j_user = user_module->module->user_module_get(config->config_m, username, user_module->cls);
              if (check_result_value(j_user, G_OK)) {
                json_object_set_new(j_user, "source", json_string(source));
                j_return = json_pack("{sisO}", "result", G_OK, "user", json_object_get(j_user, "user"));
              } else if (check_result_value(j_user, G_ERROR_NOT_FOUND)) {
                j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "get_user - Error, user_module_get for module %s", user_module->name);
                j_return = json_pack("{si}", "result", G_ERROR);
              }
              json_decref(j_user);
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

json_t * get_user_profile(struct config_elements * config, const char * username, const char * source) {
  int found = 0;
  json_t * j_return = NULL, * j_module_list, * j_module, * j_profile;
  struct _user_module_instance * user_module;
  size_t index;
  
  if (source != NULL) {
    user_module = get_user_module_instance(config, source);
    if (user_module != NULL) {
      j_profile = user_module->module->user_module_get_profile(config->config_m, username, user_module->cls);
      if (check_result_value(j_profile, G_OK)) {
        j_return = json_pack("{sisO}", "result", G_OK, "profile", j_profile);
      } else if (check_result_value(j_profile, G_ERROR_NOT_FOUND)) {
        j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_get_profile - Error user_module_get_profile");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      json_decref(j_profile);
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
              j_profile = user_module->module->user_module_get_profile(config->config_m, username, user_module->cls);
              if (check_result_value(j_profile, G_OK)) {
                j_return = json_pack("{sisO}", "result", G_OK, "profile", j_profile);
              } else if (check_result_value(j_profile, G_ERROR_NOT_FOUND)) {
                j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "user_get_profile - Error user_module_get_profile");
                j_return = json_pack("{si}", "result", G_ERROR);
              }
              json_decref(j_profile);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_user_profile - Error, user_module_instance %s is NULL", json_string_value(json_object_get(j_module, "name")));
          }
        }
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_user_profile - Error get_user_module_list");
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
  json_t * j_return, * j_module_list, * j_module, * j_element, * j_result;
  struct _user_module_instance * user_module;
  size_t cur_offset, cur_limit, count_total, index, index_u;
  
  if (source != NULL) {
    user_module = get_user_module_instance(config, source);
    if (user_module != NULL && user_module->enabled) {
      j_result = user_module->module->user_module_get_list(config->config_m, pattern, offset, limit, user_module->cls);
      if (check_result_value(j_result, G_OK)) {
        json_array_foreach(json_object_get(j_result, "list"), index, j_element) {
          json_object_set_new(j_element, "source", json_string(source));
        }
        j_return = json_pack("{sisO}", "result", G_OK, "user", json_object_get(j_result, "list"));
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_user_list - Error user_module_get_list");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      json_decref(j_result);
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
            if ((count_total = user_module->module->user_module_count_total(config->config_m, pattern, user_module->cls)) > cur_offset && cur_limit) {
              j_result = user_module->module->user_module_get_list(config->config_m, pattern, offset, limit, user_module->cls);
              if (check_result_value(j_result, G_OK)) {
                json_array_foreach(json_object_get(j_result, "list"), index_u, j_element) {
                  json_object_set_new(j_element, "source", json_string(user_module->name));
                }
                cur_offset = 0;
                if (cur_limit > json_array_size(json_object_get(j_result, "list"))) {
                  cur_limit -= json_array_size(json_object_get(j_result, "list"));
                } else {
                  cur_limit = 0;
                }
                json_array_extend(json_object_get(j_return, "user"), json_object_get(j_result, "list"));
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "get_user_list - Error user_module_get_list for module %s", json_string_value(json_object_get(j_module, "name")));
              }
              json_decref(j_result);
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
  int found = 0;
  json_t * j_return = NULL, * j_error_list, * j_module_list, * j_module;
  struct _user_module_instance * user_module;
  size_t index;
  
  if (source != NULL) {
    user_module = get_user_module_instance(config, source);
    if (user_module != NULL && user_module->enabled && !user_module->readonly) {
      j_error_list = user_module->module->user_is_valid(config->config_m, username, j_user, add?GLEWLWYD_IS_VALID_MODE_ADD:GLEWLWYD_IS_VALID_MODE_UPDATE, user_module->cls);
      if (check_result_value(j_error_list, G_ERROR_PARAM)) {
        j_return = json_incref(j_error_list);
      } else if (check_result_value(j_error_list, G_OK)) {
        j_return = json_pack("{si}", "result", G_OK);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "is_user_valid - Error user_is_valid");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      json_decref(j_error_list);
    } else if (user_module != NULL && (user_module->readonly || !user_module->enabled)) {
      j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "module is unavailable");
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "is_user_valid - Error get_user_module_instance");
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
  } else if (add) {
    j_module_list = get_user_module_list(config);
    if (check_result_value(j_module_list, G_OK)) {
      json_array_foreach(json_object_get(j_module_list, "module"), index, j_module) {
        if (!found) {
          user_module = get_user_module_instance(config, json_string_value(json_object_get(j_module, "name")));
          if (user_module != NULL && user_module->enabled && !user_module->readonly) {
            found = 1;
            j_error_list = user_module->module->user_is_valid(config->config_m, username, j_user, add?GLEWLWYD_IS_VALID_MODE_ADD:GLEWLWYD_IS_VALID_MODE_UPDATE, user_module->cls);
            if (check_result_value(j_error_list, G_ERROR_PARAM)) {
              j_return = json_incref(j_error_list);
            } else if (check_result_value(j_error_list, G_OK)) {
              j_return = json_pack("{si}", "result", G_OK);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "is_user_valid - Error user_is_valid");
              j_return = json_pack("{si}", "result", G_ERROR);
            }
            json_decref(j_error_list);
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
      j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "user", "no writeable source");
    }
  } else {
    j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "user", "source parameter is mandatory");
  }
  return j_return;
}

int add_user(struct config_elements * config, json_t * j_user, const char * source) {
  int found = 0, result, ret;
  json_t * j_module_list, * j_module;
  struct _user_module_instance * user_module;
  size_t index;
  
  if (source != NULL) {
    user_module = get_user_module_instance(config, source);
    if (user_module != NULL && user_module->enabled && !user_module->readonly) {
      result = user_module->module->user_module_add(config->config_m, j_user, user_module->cls);
      if (result == G_OK) {
        ret = G_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "add_user - Error user_module_add");
        ret = result;
      }
    } else if (user_module != NULL && (user_module->readonly || !user_module->enabled)) {
      y_log_message(Y_LOG_LEVEL_ERROR, "add_user - Error module %s not allowed", user_module->name);
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
            result = user_module->module->user_module_add(config->config_m, j_user, user_module->cls);
            if (result == G_OK) {
              ret = G_OK;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "add_user - Error user_module_add");
              ret = result;
            }
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
    if (!found) {
      ret = G_ERROR_NOT_FOUND;
    }
  }
  return ret;
}

int set_user(struct config_elements * config, const char * username, json_t * j_user, const char * source) {
  int ret;
  struct _user_module_instance * user_module;
  json_t * j_cur_user;
  
  if (source != NULL) {
    user_module = get_user_module_instance(config, source);
    if (user_module != NULL && user_module->enabled && !user_module->readonly) {
      j_cur_user = user_module->module->user_module_get(config->config_m, username, user_module->cls);
      if (check_result_value(j_cur_user, G_OK)) {
        ret = user_module->module->user_module_update(config->config_m, username, j_user, user_module->cls);
        if (ret != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "set_user - Error user_module_update");
          ret = G_OK;
        }
      } else if (check_result_value(j_cur_user, G_ERROR_NOT_FOUND)) {
        ret = G_ERROR_NOT_FOUND;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "set_user - Error user_module_get");
        ret = G_ERROR;
      }
      json_decref(j_cur_user);
    } else if (user_module != NULL && (user_module->readonly || !user_module->enabled)) {
      ret = G_ERROR_PARAM;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "set_user - Error get_user_module_instance");
      ret = G_ERROR;
    }
  } else {
    ret = G_ERROR_PARAM;
  }
  return ret;
}

int delete_user(struct config_elements * config, const char * username, const char * source) {
  int ret;
  struct _user_module_instance * user_module;
  json_t * j_cur_user;
  int result;
  
  if (source != NULL) {
    user_module = get_user_module_instance(config, source);
    if (user_module != NULL && user_module->enabled && !user_module->readonly) {
      j_cur_user = user_module->module->user_module_get(config->config_m, username, user_module->cls);
      if (check_result_value(j_cur_user, G_OK)) {
        result = user_module->module->user_module_delete(config->config_m, username, user_module->cls);
        if (result == G_OK) {
          ret = G_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "delete_user - Error user_module_delete");
          ret = result;
        }
      } else if (check_result_value(j_cur_user, G_ERROR_NOT_FOUND)) {
        ret = G_ERROR_NOT_FOUND;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "set_user - Error user_module_get");
        ret = G_ERROR;
      }
      json_decref(j_cur_user);
    } else if (user_module != NULL && (user_module->readonly || !user_module->enabled)) {
      ret = G_ERROR_PARAM;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "delete_user - Error get_user_module_instance");
      ret = G_ERROR;
    }
  } else {
    ret = G_ERROR_PARAM;
  }
  return ret;
}

json_t * user_get_profile(struct config_elements * config, const char * username) {
  json_t * j_user = get_user(config, username, NULL), * j_return, * j_profile;
  struct _user_module_instance * user_module;

  if (check_result_value(j_user, G_OK)) {
    user_module = get_user_module_instance(config, json_string_value(json_object_get(json_object_get(j_user, "user"), "source")));
    if (user_module != NULL && user_module->enabled) {
      j_profile = user_module->module->user_module_get_profile(config->config_m, username, user_module->cls);
      if (check_result_value(j_profile, G_OK)) {
        j_return = json_pack("{sisO}", "result", G_OK, "profile", j_profile);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_get_profile - Error user_module_get_profile");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      json_decref(j_profile);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_get_profile - Error get_user_module_instance");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
  } else if (check_result_value(j_user, G_ERROR_NOT_FOUND)) {
    j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_get_profile - Error get_user");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  json_decref(j_user);
  return j_return;
}

json_t * user_set_profile(struct config_elements * config, const char * username, json_t * j_profile) {
  json_t * j_user = get_user(config, username, NULL), * j_return;
  struct _user_module_instance * user_module;
  int ret;

  if (check_result_value(j_user, G_OK)) {
    user_module = get_user_module_instance(config, json_string_value(json_object_get(json_object_get(j_user, "user"), "source")));
    if (user_module != NULL && user_module->enabled && !user_module->readonly) {
      ret = user_module->module->user_module_update_profile(config->config_m, username, j_profile, user_module->cls);
      j_return = json_pack("{si}", "result", ret);
    } else if (user_module != NULL && (user_module->readonly || !user_module->enabled)) {
      j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "profile update is not allowed");
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_set_profile - Error get_user_module_instance");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
  } else if (check_result_value(j_user, G_ERROR_NOT_FOUND)) {
    j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_set_profile - Error get_user");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  json_decref(j_user);
  return j_return;
}

int user_update_password(struct config_elements * config, const char * username, const char * old_password, const char * new_password) {
  json_t * j_user = get_user(config, username, NULL);
  struct _user_module_instance * user_module;
  int ret;

  if (check_result_value(j_user, G_OK)) {
    user_module = get_user_module_instance(config, json_string_value(json_object_get(json_object_get(j_user, "user"), "source")));
    if (user_module != NULL && user_module->enabled && !user_module->readonly) {
      if ((ret = user_module->module->user_module_check_password(config->config_m, username, old_password, user_module->cls)) == G_OK) {
        ret = user_module->module->user_module_update_password(config->config_m, username, new_password, user_module->cls);
      } else if (ret == G_ERROR_UNAUTHORIZED) {
        ret = G_ERROR_PARAM;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "user_set_profile - Error user_module_check_password");
        ret = G_ERROR;
      }
    } else if (user_module != NULL && (user_module->readonly || !user_module->enabled)) {
      ret = G_ERROR_PARAM;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_set_profile - Error get_user_module_instance");
      ret = G_ERROR;
    }
  } else if (check_result_value(j_user, G_ERROR_NOT_FOUND)) {
    ret = G_ERROR_NOT_FOUND;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_set_profile - Error get_user");
    ret = G_ERROR;
  }
  json_decref(j_user);
  return ret;
}

json_t * glewlwyd_module_callback_get_user(struct config_module * config, const char * username) {
  return get_user(config->glewlwyd_config, username, NULL);
}

int glewlwyd_module_callback_set_user(struct config_module * config, const char * username, json_t * j_user_data) {
  json_t * j_user;
  int ret;
  
  j_user = get_user(config->glewlwyd_config, username, NULL);
  if (check_result_value(j_user, G_OK)) {
    ret = set_user(config->glewlwyd_config, username, j_user_data, json_string_value(json_object_get(json_object_get(j_user, "user"), "source")));
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_callback_set_user - Error get_user");
    ret = G_ERROR;
  }
  json_decref(j_user);
  return ret;
}

int glewlwyd_module_callback_check_user_password(struct config_module * config, const char * username, const char * password) {
  int ret;
  json_t * j_user, * j_result;
  
  j_user = get_user(config->glewlwyd_config, username, NULL);
  if (check_result_value(j_user, G_OK)) {
    j_result = auth_check_user_credentials(config->glewlwyd_config, username, password);
    if (json_is_integer(json_object_get(j_result, "result"))) {
      ret = json_integer_value(json_object_get(j_result, "result"));
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_module_callback_check_user_password - Error auth_check_user_credentials");
      ret = G_ERROR;
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_module_callback_check_user_password - Error get_user");
    ret = G_ERROR;
  }
  json_decref(j_user);
  return ret;
}
