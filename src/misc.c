/**
 *
 * Glewlwyd OAuth2 Authorization Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * Provides Json Web Tokens (jwt)
 * 
 * Miscellaneous functions definitions
 *
 * Copyright 2018 Nicolas Mora <mail@babelouest.org>
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <string.h>

#include "glewlwyd.h"

/**
 *
 * Read the content of a file and return it as a char *
 * returned value must be o_free'd after use
 *
 */
char * get_file_content(const char * file_path) {
  char * buffer = NULL;
  size_t length, res;
  FILE * f;

  f = fopen (file_path, "rb");
  if (f) {
    fseek (f, 0, SEEK_END);
    length = ftell (f);
    fseek (f, 0, SEEK_SET);
    buffer = o_malloc((length+1)*sizeof(char));
    if (buffer) {
      res = fread (buffer, 1, length, f);
      if (res != length) {
        fprintf(stderr, "fread warning, reading %zu while expecting %zu", res, length);
      }
      // Add null character at the end of buffer, just in case
      buffer[length] = '\0';
    }
    fclose (f);
  }
  
  return buffer;
}

/**
 * Return the source ip address of the request
 * Based on the header value "X-Forwarded-For" if set, which means the request is forwarded by a proxy
 * otherwise the call is direct, return the client_address
 */
const char * get_ip_source(const struct _u_request * request) {
  const char * ip_source = u_map_get(request->map_header, "X-Forwarded-For");
  
  if (ip_source == NULL) {
    struct sockaddr_in * in_source = (struct sockaddr_in *)request->client_address;
    if (in_source != NULL) {
      ip_source = inet_ntoa(in_source->sin_addr);
    } else {
      ip_source = "NOT_FOUND";
    }
  }
  
  return ip_source;
};

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
 * IMPORTANT: be sure to o_free() the returned string after use 
 * Thanks Geek Hideout!
 * http://www.geekhideout.com/urlcode.shtml
 */
char * url_encode(char * str) {
  char * pstr = str, * buf = o_malloc(strlen(str) * 3 + 1), * pbuf = buf;
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
 * IMPORTANT: be sure to o_free() the returned string after use
 * Thanks Geek Hideout!
 * http://www.geekhideout.com/urlcode.shtml
 */
char * url_decode(char * str) {
  char * pstr = str, * buf = o_malloc(strlen(str) + 1), * pbuf = buf;
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

/**
 *
 * Generates a query string based on url and post parameters of a request
 * Returned value must be o_free'd after use
 *
 */
char * generate_query_parameters(const struct _u_request * request) {
  char * query = NULL, * param, * tmp, * value;
  const char ** keys;
  struct _u_map params;
  int i;
  
  u_map_init(&params);
  
  keys = u_map_enum_keys(request->map_url);
  for (i=0; keys[i] != NULL; i++) {
    u_map_put(&params, keys[i], u_map_get(request->map_url, keys[i]));
  }
  
  keys = u_map_enum_keys(request->map_post_body);
  for (i=0; keys[i] != NULL; i++) {
    u_map_put(&params, keys[i], u_map_get(request->map_post_body, keys[i]));
  }
  
  keys = u_map_enum_keys(&params);
  for (i=0; keys[i] != NULL; i++) {
    value = url_encode((char *)u_map_get(request->map_url, keys[i]));
    param = msprintf("%s=%s", keys[i], value);
    o_free(value);
    if (query == NULL) {
      query = o_strdup(param);
    } else {
      tmp = msprintf("%s&%s", query, param);
      o_free(query);
      query = tmp;
    }
    o_free(param);
  }
  
  u_map_clean(&params);
  
  return query;
}

/**
 *
 * Generates a random long integer between 0 and max
 *
 */
long random_at_most(long max) {
  unsigned long
  // max <= RAND_MAX < ULONG_MAX, so this is okay.
  num_bins = (unsigned long) max + 1,
  num_rand = (unsigned long) RAND_MAX + 1,
  bin_size = num_rand / num_bins,
  defect   = num_rand % num_bins;

  long x;
  do {
   x = random();
  }
  // This is carefully written not to overflow
  while (num_rand - defect <= (unsigned long)x);

  // Truncated division is intentional
  return x/bin_size;
}

/**
 * Generates a random string and store it in str
 */
char * rand_string(char * str, size_t str_size) {
  const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  size_t n;
  
  if (str_size > 0 && str != NULL) {
    for (n = 0; n < str_size; n++) {
      long key = random_at_most((sizeof(charset)) - 2);
      str[n] = charset[key];
    }
    str[str_size] = '\0';
    return str;
  } else {
    return NULL;
  }
}
