/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * Prometheus metrics functions definitions
 * 
 * Copyright 2016-2021 Nicolas Mora <mail@babelouest.org>
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

struct _glwd_increment_counter_data {
  struct config_elements * config;
  char                   * name;
  char                   * label;
  size_t                   inc;
};

void * glewlwyd_metrics_increment_counter_thread(void * args) {
  struct _glwd_increment_counter_data * data = (struct _glwd_increment_counter_data *)args;
  struct _glwd_metric * metric;
  size_t i, j;
  int found;
  
  if (!pthread_mutex_lock(&data->config->metrics_lock)) {
    for (i=0; i<pointer_list_size(&data->config->metrics_list); i++) {
      metric = (struct _glwd_metric *)pointer_list_get_at(&data->config->metrics_list, i);
      if (0 == o_strcmp(data->name, metric->name)) {
        found = 0;
        for (j=0; j<metric->data_size; j++) {
          if ((data->label == NULL && metric->data[j].label == NULL) || 0 == o_strcasecmp(data->label, metric->data[j].label)) {
            metric->data[j].counter += data->inc;
            found = 1;
          }
        }
        if (!found) {
          if ((metric->data = o_realloc(metric->data, (metric->data_size+1)*sizeof(struct _glwd_metrics_data))) != NULL) {
            metric->data[metric->data_size].label = o_strdup(data->label);
            metric->data[metric->data_size].counter = data->inc;
            metric->data_size++;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_metrics_increment_counter_thread - Error realloc metric->data");
          }
        }
      }
    }
    pthread_mutex_unlock(&data->config->metrics_lock);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_metrics_increment_counter_thread - Error lock");
  }
  o_free(data->name);
  o_free(data->label);
  o_free(data);
  pthread_exit(NULL);
}

int glewlwyd_metrics_increment_counter(struct config_elements * config, const char * name, size_t inc, ...) {
  va_list vl;
  const char * label_arg;
  char * label = NULL;
  int ret = G_OK, flag = 0;
  struct _glwd_increment_counter_data * data;
  pthread_t thread_metrics;
  int thread_ret, thread_detach;

  if (config != NULL && o_strlen(name)) {
    va_start(vl, inc);
    for (label_arg = va_arg(vl, const char *); label_arg != NULL && ret == G_OK; label_arg = va_arg(vl, const char *)) {
      if (!flag) {
        if (label == NULL) {
          label = msprintf("%s=", label_arg);
        } else {
          label = mstrcatf(label, ", %s=", label_arg);
        }
      } else {
        label = mstrcatf(label, "%s", label_arg);
      }
      flag = !flag;
    }
    va_end(vl);
    
    if ((data = o_malloc(sizeof(struct _glwd_increment_counter_data))) != NULL) {
      data->config = config;
      data->name = o_strdup(name);
      data->label = label;
      data->inc = inc;
      thread_ret = pthread_create(&thread_metrics, NULL, glewlwyd_metrics_increment_counter_thread, (void *)data);
      thread_detach = pthread_detach(thread_metrics);
      if (thread_ret || thread_detach) {
        y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_module_metrics_increment_counter - Error thread");
        ret = G_ERROR_MEMORY;
        o_free(data->name);
        o_free(data->label);
        o_free(data);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_module_metrics_increment_counter - Error allocating resources for struct _glwd_increment_counter_data");
      ret = G_ERROR_MEMORY;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "glewlwyd_module_metrics_increment_counter - Error input values");
    ret = G_ERROR_PARAM;
  }
  return ret;
}

void free_glwd_metrics(void * data) {
  struct _glwd_metric * glwd_metrics = (struct _glwd_metric *)data;
  size_t i;
  
  y_log_message(Y_LOG_LEVEL_DEBUG, "Close metric %s", glwd_metrics->name);
  if (glwd_metrics != NULL) {
    o_free(glwd_metrics->name);
    o_free(glwd_metrics->help);
    for (i=0; i<glwd_metrics->data_size; i++) {
      o_free(glwd_metrics->data[i].label);
    }
    o_free(glwd_metrics->data);
    o_free(glwd_metrics);
  }
}

int glewlwyd_metrics_add_metric(struct config_elements * config, const char * name, const char * help) {
  struct _glwd_metric * glwd_metrics;
  int ret;
  
  if (config->metrics_endpoint) {
    if (o_strlen(name)) {
      if ((glwd_metrics = o_malloc(sizeof(struct _glwd_metric))) != NULL) {
        glwd_metrics->name = o_strdup(name);
        glwd_metrics->help = o_strdup(help);
        glwd_metrics->data_size = 0;
        glwd_metrics->data = NULL;
        pointer_list_append(&config->metrics_list, glwd_metrics);
      } else {
        ret = G_ERROR_MEMORY;
      }
    } else {
      ret = G_ERROR_PARAM;
    }
  } else {
    ret = G_OK;
  }
  return ret;
}

int glewlwyd_metrics_init(struct config_elements * config) {
  pthread_mutexattr_t mutexattr;
  int ret = G_OK;
  
  pointer_list_init(&config->metrics_list);
  pthread_mutexattr_init ( &mutexattr );
  pthread_mutexattr_settype( &mutexattr, PTHREAD_MUTEX_RECURSIVE );
  if (pthread_mutex_init(&config->metrics_lock, &mutexattr) != 0) {
    ret = GLEWLWYD_ERROR;
  }
  pthread_mutexattr_destroy(&mutexattr);
  return ret;
}

void glewlwyd_metrics_close(struct config_elements * config) {
  if (config->metrics_endpoint) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "Close metrics");
    pointer_list_clean_free(&config->metrics_list, &free_glwd_metrics);
    pthread_mutex_destroy(&config->metrics_lock);
  }
}
