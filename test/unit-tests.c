
#include <string.h>
#include <ctype.h>
#include <jansson.h>
#include <ulfius.h>
#include <orcania.h>

#include "unit-tests.h"

/**
 * Developper-friendly response print
 */
void print_response(struct _u_response * response) {
  char * dump_json = NULL;
  json_t * json_body;
  
  if (response != NULL) {
    fprintf(stderr,"Status: %ld\n\n", response->status);
    json_body = ulfius_get_json_body_response(response, NULL);
    if (json_body != NULL) {
      dump_json = json_dumps(json_body, JSON_INDENT(2));
      fprintf(stderr,"Json body:\n%s\n\n", dump_json);
      o_free(dump_json);
    } else {
      fprintf(stderr,"String body: %.*s\n\n", (int)response->binary_body_length, (char *)response->binary_body);
    }
    json_decref(json_body);
  }
}

/**
 * json_t * json_search(json_t * haystack, json_t * needle)
 * jansson library addon
 * Look for an occurence of needle within haystack
 * If needle is present in haystack, return the reference to the json_t * that is equal to needle
 * If needle is not found, return NULL
 */
json_t * json_search(json_t * haystack, json_t * needle) {
  json_t * value1 = NULL, * value2 = NULL;
  size_t index = 0;
  const char * key = NULL;

  if (!haystack || !needle)
    return NULL;

  if (haystack == needle)
    return haystack;

  // If both haystack and needle are the same type, test them
  if (json_typeof(haystack) == json_typeof(needle) && !json_is_object(haystack))
    if (json_equal(haystack, needle))
      return haystack;

  // If they are not equals, test json_search in haystack elements recursively if it's an array or an object
  if (json_is_array(haystack)) {
    json_array_foreach(haystack, index, value1) {
      if (json_equal(value1, needle)) {
        return value1;
      } else {
        value2 = json_search(value1, needle);
        if (value2 != NULL) {
          return value2;
        }
      }
    }
  } else if (json_is_object(haystack) && json_is_object(needle)) {
    int same = 1;
    json_object_foreach(needle, key, value1) {
      value2 = json_object_get(haystack, key);
      if (!json_equal(value1, value2)) {
        same = 0;
      }
    }
    if (same) {
      return haystack;
    }
  } else if (json_is_object(haystack)) {
    json_object_foreach(haystack, key, value1) {
      if (json_equal(value1, needle)) {
        return value1;
      } else {
        value2 = json_search(value1, needle);
        if (value2 != NULL) {
          return value2;
        }
      }
    }
  }
  return NULL;
}

int test_request(struct _u_request * req, long int expected_status, json_t * expected_json_body, const char * exptected_string_body, const char * expected_redirect_uri_contains) {
  int res, to_return = 0;
  struct _u_response response;
  json_t * json_body;
  
  ulfius_init_response(&response);
  res = ulfius_send_http_request(req, &response);
  if (res == U_OK) {
    if (response.status != expected_status) {
      fprintf(stderr,"##########################\nError status (%s %s %ld)\n", req->http_verb, req->http_url, expected_status);
      print_response(&response);
      fprintf(stderr,"##########################\n\n");
    } else if (expected_json_body != NULL) {
      json_body = ulfius_get_json_body_response(&response, NULL);
      if (json_body == NULL || json_search(json_body, expected_json_body) == NULL) {
        char * dump_expected = json_dumps(expected_json_body, JSON_ENCODE_ANY), * dump_response = json_dumps(json_body, JSON_ENCODE_ANY);
        fprintf(stderr,"##########################\nError json (%s %s)\n", req->http_verb, req->http_url);
        fprintf(stderr,"Expected result in response:\n%s\nWhile response is:\n%s\n", dump_expected, dump_response);
        fprintf(stderr,"##########################\n\n");
        o_free(dump_expected);
        o_free(dump_response);
      } else {
        to_return = 1;
      }
      json_decref(json_body);
    } else if (exptected_string_body != NULL && o_strnstr((const char *)response.binary_body, exptected_string_body, response.binary_body_length) == NULL) {
      fprintf(stderr,"##########################\nError (%s %s)\n", req->http_verb, req->http_url);
      fprintf(stderr,"Expected result in response:\n%s\nWhile response is:\n%s\n", exptected_string_body, (const char *)response.binary_body);
      fprintf(stderr,"##########################\n\n");
    } else if (expected_redirect_uri_contains != NULL && o_strstr(u_map_get(response.map_header, "Location"), expected_redirect_uri_contains) == NULL) {
      fprintf(stderr,"##########################\nError (%s %s)\n", req->http_verb, req->http_url);
      fprintf(stderr,"expected_redirect_uri_contains is %s\nwhile redirect_uri is %s\n", expected_redirect_uri_contains, u_map_get(response.map_header, "Location"));
      fprintf(stderr,"##########################\n\n");
    } else {
      to_return = 1;
    }
  } else {
    fprintf(stderr,"Error in http request: %d\n", res);
  }
  ulfius_clean_response(&response);
  return to_return;
}

int run_simple_test(struct _u_request * req, const char * method, const char * url, const char * auth_basic_user, const char * auth_basic_password, json_t * json_body, const struct _u_map * body, int expected_status, json_t * expected_json_body, const char * exptected_string_body, const char * expected_redirect_uri_contains) {
  struct _u_request * request;
  int res;
  
  if (req != NULL) {
    request = ulfius_duplicate_request(req);
    o_free(request->http_verb);
    o_free(request->http_url);
  } else {
    request = o_malloc(sizeof (struct _u_request));
    ulfius_init_request(request);
  }
  request->http_verb = o_strdup(method);
  request->http_url = o_strdup(url);
  if (body != NULL) {
    u_map_copy_into(request->map_post_body, body);
  } else if (json_body != NULL) {
    ulfius_set_json_body_request(request, json_body);
  }
  o_free(request->auth_basic_user);
  o_free(request->auth_basic_password);
  request->auth_basic_user = o_strdup(auth_basic_user);
  request->auth_basic_password = o_strdup(auth_basic_password);
  
  res = test_request(request, expected_status, expected_json_body, exptected_string_body, expected_redirect_uri_contains);
  
  ulfius_clean_request_full(request);
  request = NULL;
  
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
