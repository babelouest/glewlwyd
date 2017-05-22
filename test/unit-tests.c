
#include <string.h>
#include <ctype.h>
#include <jansson.h>
#include <ulfius.h>
#include <orcania.h>

#include "unit-tests.h"

/**
 * decode a u_map into a string
 */
char * print_map(const struct _u_map * map) {
  char * line, * to_return = NULL;
  const char **keys;
  int len, i;
  if (map != NULL) {
    keys = u_map_enum_keys(map);
    for (i=0; keys[i] != NULL; i++) {
      len = snprintf(NULL, 0, "key is %s, value is %s\n", keys[i], u_map_get(map, keys[i]));
      line = malloc((len+1)*sizeof(char));
      snprintf(line, (len+1), "key is %s, value is %s\n", keys[i], u_map_get(map, keys[i]));
      if (to_return != NULL) {
        len = strlen(to_return) + strlen(line) + 1;
        to_return = realloc(to_return, (len+1)*sizeof(char));
      } else {
        to_return = malloc((strlen(line) + 1)*sizeof(char));
        to_return[0] = 0;
      }
      strcat(to_return, line);
      free(line);
    }
    return to_return;
  } else {
    return NULL;
  }
}

/**
 * Developper-friendly response print
 */
void print_response(struct _u_response * response) {
  char * dump_json = NULL;
  json_t * json_body;
  
  if (response != NULL) {
    printf("Status: %ld\n\n", response->status);
    json_body = ulfius_get_json_body_response(response, NULL);
    if (json_body != NULL) {
      dump_json = json_dumps(json_body, JSON_INDENT(2));
      printf("Json body:\n%s\n\n", dump_json);
      free(dump_json);
    } else {
      printf("String body: %.*s\n\n", (int)response->binary_body_length, (char *)response->binary_body);
    }
    json_decref(json_body);
  }
}

int test_request(struct _u_request * req, long int expected_status, json_t * expected_json_body, const char * exptected_string_body, const char * expected_redirect_uri_contains) {
  int res, to_return = 0;
  struct _u_response response;
  json_t * json_body;
  
  ulfius_init_response(&response);
  res = ulfius_send_http_request(req, &response);
  if (res == U_OK) {
    if (response.status != expected_status) {
      printf("##########################\nError status (%s %s %ld)\n", req->http_verb, req->http_url, expected_status);
      print_response(&response);
      printf("##########################\n\n");
    } else if (expected_json_body != NULL) {
      json_body = ulfius_get_json_body_response(&response, NULL);
      if (json_body == NULL || json_search(json_body, expected_json_body) == NULL) {
        char * dump_expected = json_dumps(expected_json_body, JSON_ENCODE_ANY), * dump_response = json_dumps(json_body, JSON_ENCODE_ANY);
        printf("##########################\nError json (%s %s)\n", req->http_verb, req->http_url);
        printf("Expected result in response:\n%s\nWhile response is:\n%s\n", dump_expected, dump_response);
        printf("##########################\n\n");
        free(dump_expected);
        free(dump_response);
      } else {
        to_return = 1;
      }
      json_decref(json_body);
    } else if (exptected_string_body != NULL && o_strnstr((const char *)response.binary_body, exptected_string_body, response.binary_body_length) == NULL) {
      printf("##########################\nError (%s %s)\n", req->http_verb, req->http_url);
      printf("Expected result in response:\n%s\nWhile response is:\n%s\n", exptected_string_body, (const char *)response.binary_body);
      printf("##########################\n\n");
    } else if (expected_redirect_uri_contains != NULL && o_strstr(u_map_get(response.map_header, "Location"), expected_redirect_uri_contains) == NULL) {
      printf("##########################\nError (%s %s)\n", req->http_verb, req->http_url);
      printf("expected_redirect_uri_contains is %s\nwhile redirect_uri is %s\n", expected_redirect_uri_contains, u_map_get(response.map_header, "Location"));
      printf("##########################\n\n");
    } else {
      to_return = 1;
    }
  } else {
    printf("Error in http request: %d\n", res);
  }
  ulfius_clean_response(&response);
  return to_return;
}

int run_simple_test(struct _u_request * req, const char * method, const char * url, const char * auth_basic_user, const char * auth_basic_password, json_t * json_body, const struct _u_map * body, int expected_status, json_t * expected_json_body, const char * exptected_string_body, const char * expected_redirect_uri_contains) {
  struct _u_request * request;
  int res;
  
  if (req != NULL) {
    request = ulfius_duplicate_request(req);
    free(request->http_verb);
    free(request->http_url);
  } else {
    request = malloc(sizeof (struct _u_request));
    ulfius_init_request(request);
  }
  request->http_verb = o_strdup(method);
  request->http_url = strdup(url);
  if (body != NULL) {
    u_map_copy_into(request->map_post_body, body);
  } else if (json_body != NULL) {
    ulfius_set_json_body_request(request, json_body);
  }
  free(request->auth_basic_user);
  free(request->auth_basic_password);
  request->auth_basic_user = o_strdup(auth_basic_user);
  request->auth_basic_password = o_strdup(auth_basic_password);
  
  res = test_request(request, expected_status, expected_json_body, exptected_string_body, expected_redirect_uri_contains);
  
  ulfius_clean_request_full(request);
  
  return res;
}

/**
 * Converts a hex character to its integer value
 */
char from_hex(char ch) {
  return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

/**
 * Converts an integer value to its hex character
 */
char to_hex(char code) {
  static char hex[] = "0123456789abcdef";
  return hex[code & 15];
}

/**
 * Returns a url-encoded version of str
 * IMPORTANT: be sure to free() the returned string after use 
 * Thanks Geek Hideout!
 * http://www.geekhideout.com/urlcode.shtml
 */
char * url_encode(const char * str) {
  char * pstr = (char*)str, * buf = malloc(strlen(str) * 3 + 1), * pbuf = buf;
  while (* pstr) {
    if (isalnum(* pstr) || * pstr == '-' || * pstr == '_' || * pstr == '.' || * pstr == '~') 
      * pbuf++ = * pstr;
    else if (* pstr == ' ') 
      * pbuf++ = '+';
    else 
      * pbuf++ = '%', * pbuf++ = to_hex(* pstr >> 4), * pbuf++ = to_hex(* pstr & 15);
    pstr++;
  }
  * pbuf = '\0';
  return buf;
}

/**
 * Returns a url-decoded version of str
 * IMPORTANT: be sure to free() the returned string after use
 * Thanks Geek Hideout!
 * http://www.geekhideout.com/urlcode.shtml
 */
char * url_decode(const char * str) {
  char * pstr = (char*)str, * buf = malloc(strlen(str) + 1), * pbuf = buf;
  while (* pstr) {
    if (* pstr == '%') {
      if (pstr[1] && pstr[2]) {
        * pbuf++ = from_hex(pstr[1]) << 4 | from_hex(pstr[2]);
        pstr += 2;
      }
    } else if (* pstr == '+') { 
      * pbuf++ = ' ';
    } else {
      * pbuf++ = * pstr;
    }
    pstr++;
  }
  * pbuf = '\0';
  return buf;
}
