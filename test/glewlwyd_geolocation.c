/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <ctype.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include <check.h>
#include <ulfius.h>
#include <orcania.h>
#include <yder.h>

#include "unit-tests.h"

#define SERVER_URI "http://localhost:4593/api"
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"

#define SCOPE "openid"

#define USER1 "mail1"
#define MAIL1 "mail1@mail.tld"
#define USER_PASSWORD "password"

#define CLIENT "client1_id"
#define REDIRECT_URI "..%2f..%2ftest-oauth2.html?param=client1_cb1"
#define CLIENT_REDIRECT "../../test-oauth2.html?param=client1_cb1"
#define RESPONSE_TYPE_CODE "code"

#define CONFIG_TYPE_MAIL "mail-on-connexion"
#define CONFIG_NAME_MAIL "cur-mail-on-connexion"
#define CONFIG_TYPE_GEOLOC "ip-geolocation-api"
#define CONFIG_NAME_GEOLOC "cur-ip-geolocation-api"
#define HOST "localhost"
#define PORT_2525 2525
#define CONTENT_TYPE "text/plain; charset=utf-8"
#define FROM "glewlwyd@mail.tld"
#define LANG_PROPERTY "lang"
#define SUBJECT "New connexion"
#define BODY_PATTERN_GEOLOCATION "New connexion from "
#define PORT_GEOLOCATION 5622
#define PORT_GEOLOCATION_STR "5622"
#define GEOLOCATION_CITY "Cair Paravel"
#define GEOLOCATION_COUNTRY "Narnia"

char user_agent[33];

struct _u_request admin_req;

struct _u_instance instance;

#define BACKLOG_MAX  (10)
#define BUF_SIZE     4096
#define STREQU(a,b)  (strcmp(a, b) == 0)

static int callback_geolocation (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_resp = json_pack("{ssss}", "city", GEOLOCATION_CITY, "country_name", GEOLOCATION_COUNTRY);
  ulfius_set_json_body_response(response, 200, j_resp);
  json_decref(j_resp);
  return U_CALLBACK_CONTINUE;
}

static int callback_geolocation_incomplete (const struct _u_request * request, struct _u_response * response, void * user_data) {
  ulfius_set_json_body_response(response, 200, (json_t *)user_data);
  return U_CALLBACK_CONTINUE;
}

struct smtp_manager {
  char       * mail_data;
  unsigned int port;
  int          sockfd;
  const char * body_pattern;
};

/**
 *
 * Function that emulates a very simple SMTP server
 * Taken from Kenneth Finnegan's ccsmtp program
 * https://gist.github.com/PhirePhly/2914635
 * This function is under the GPL2 license
 *
 */
static void handle_smtp (struct smtp_manager * manager) {
  int rc, i;
  char buffer[BUF_SIZE], bufferout[BUF_SIZE];
  int buffer_offset = 0;
  buffer[BUF_SIZE-1] = '\0';

  // Flag for being inside of DATA verb
  int inmessage = 0;

  sprintf(bufferout, "220 ulfius.tld SMTP CCSMTP\r\n");
  send(manager->sockfd, bufferout, strlen(bufferout), 0);

  while (1) {
    fd_set sockset;
    struct timeval tv;

    FD_ZERO(&sockset);
    FD_SET(manager->sockfd, &sockset);
    tv.tv_sec = 120; // Some SMTP servers pause for ~15s per message
    tv.tv_usec = 0;

    // Wait tv timeout for the server to send anything.
    select(manager->sockfd+1, &sockset, NULL, NULL, &tv);

    if (!FD_ISSET(manager->sockfd, &sockset)) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "%d: Socket timed out", manager->sockfd);
      break;
    }

    int buffer_left = BUF_SIZE - buffer_offset - 1;
    if (buffer_left == 0) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "%d: Command line too long", manager->sockfd);
      sprintf(bufferout, "500 Too long\r\n");
      send(manager->sockfd, bufferout, strlen(bufferout), 0);
      buffer_offset = 0;
      continue;
    }

    rc = recv(manager->sockfd, buffer + buffer_offset, buffer_left, 0);
    if (rc == 0) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "%d: Remote host closed socket", manager->sockfd);
      break;
    }
    if (rc == -1) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "%d: Error on socket", manager->sockfd);
      break;
    }

    buffer_offset += rc;

    char *eol;

    // Only process one line of the received buffer at a time
    // If multiple lines were received in a single recv(), goto
    // back to here for each line
    //
processline:
    eol = strstr(buffer, "\r\n");
    if (eol == NULL) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "%d: Haven't found EOL yet", manager->sockfd);
      continue;
    }

    // Null terminate each line to be processed individually
    eol[0] = '\0';

    if (!inmessage) { // Handle system verbs
      // Replace all lower case letters so verbs are all caps
      for (i=0; i<4; i++) {
        if (islower(buffer[i])) {
          buffer[i] += 'A' - 'a';
        }
      }
      // Null-terminate the verb for strcmp
      buffer[4] = '\0';

      // Respond to each verb accordingly.
      // You should replace these with more meaningful
      // actions than simply printing everything.
      //
      if (STREQU(buffer, "HELO")) { // Initial greeting
        sprintf(bufferout, "250 Ok\r\n");
        send(manager->sockfd, bufferout, strlen(bufferout), 0);
      } else if (STREQU(buffer, "MAIL")) { // New mail from...
        sprintf(bufferout, "250 Ok\r\n");
        send(manager->sockfd, bufferout, strlen(bufferout), 0);
      } else if (STREQU(buffer, "RCPT")) { // Mail addressed to...
        sprintf(bufferout, "250 Ok recipient\r\n");
        send(manager->sockfd, bufferout, strlen(bufferout), 0);
      } else if (STREQU(buffer, "DATA")) { // Message contents...
        sprintf(bufferout, "354 Continue\r\n");
        send(manager->sockfd, bufferout, strlen(bufferout), 0);
        inmessage = 1;
      } else if (STREQU(buffer, "RSET")) { // Reset the connection
        sprintf(bufferout, "250 Ok reset\r\n");
        send(manager->sockfd, bufferout, strlen(bufferout), 0);
      } else if (STREQU(buffer, "NOOP")) { // Do nothing.
        sprintf(bufferout, "250 Ok noop\r\n");
        send(manager->sockfd, bufferout, strlen(bufferout), 0);
      } else if (STREQU(buffer, "QUIT")) { // Close the connection
        sprintf(bufferout, "221 Ok\r\n");
        send(manager->sockfd, bufferout, strlen(bufferout), 0);
        break;
      } else { // The verb used hasn't been implemented.
        sprintf(bufferout, "502 Command Not Implemented\r\n");
        send(manager->sockfd, bufferout, strlen(bufferout), 0);
      }
    } else { // We are inside the message after a DATA verb.
      if (0 == o_strncmp(manager->body_pattern, buffer, o_strlen(manager->body_pattern))) {
        manager->mail_data = o_strdup(buffer+o_strlen(manager->body_pattern));
      }
      if (STREQU(buffer, ".")) { // A single "." signifies the end
        sprintf(bufferout, "250 Ok\r\n");
        send(manager->sockfd, bufferout, strlen(bufferout), 0);
        inmessage = 0;
      }
    }

    // Shift the rest of the buffer to the front
    memmove(buffer, eol+2, BUF_SIZE - (eol + 2 - buffer));
    buffer_offset -= (eol - buffer) + 2;

    // Do we already have additional lines to process? If so,
    // commit a horrid sin and goto the line processing section again.
    if (strstr(buffer, "\r\n"))
      goto processline;
  }

  // All done. Clean up everything and exit.
  shutdown(manager->sockfd, SHUT_WR);
  close(manager->sockfd);
}

static void * simple_smtp(void * args) {
  struct smtp_manager * manager = (struct smtp_manager *)args;
  int server_fd;
  struct sockaddr_in address;
  int opt = 1;
  int addrlen = sizeof(address);

  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) != 0) {
    if (!setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
      address.sin_family = AF_INET;
      address.sin_addr.s_addr = INADDR_ANY;
      address.sin_port = htons( manager->port );

      if (!bind(server_fd, (struct sockaddr *)&address, sizeof(address))) {
        if (listen(server_fd, 3) >= 0) {
          if ((manager->sockfd = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) >= 0) {
            handle_smtp(manager);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "simple_smtp - Error accept");
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "simple_smtp - Error listen");
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "simple_smtp - Error bind");
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "simple_smtp - Error setsockopt");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "simple_smtp - Error socket");
  }

  shutdown(server_fd, SHUT_RDWR);
  close(server_fd);

  pthread_exit(NULL);
}

START_TEST(test_glwd_geolocation_add_user)
{
  json_t * j_body = json_pack("{sss{so ss si ss ss ss s{s{sossss}}}}",
                              "type", CONFIG_TYPE_MAIL,
                              "value",
                                "enabled", json_true(),
                                "host", HOST,
                                "port", PORT_2525,
                                "content-type", CONTENT_TYPE,
                                "from", FROM,
                                "user-lang-property", LANG_PROPERTY,
                                "templates",
                                  "en",
                                    "defaultLang", json_true(),
                                    "subject", SUBJECT,
                                    "body-pattern", BODY_PATTERN_GEOLOCATION "{LOCATION}");
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/misc/" CONFIG_NAME_MAIL, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  j_body = json_pack("{sss{so ss ss}}",
                     "type", CONFIG_TYPE_GEOLOC,
                     "value",
                       "enabled", json_true(),
                       "url", "http://localhost:" PORT_GEOLOCATION_STR "/",
                       "output-properties", "city, country_name");
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/misc/" CONFIG_NAME_GEOLOC, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  ck_assert_ptr_ne(NULL, (j_body = json_pack("{sssssss[s]so}", "username", USER1, "password", USER_PASSWORD, "email", MAIL1, "scope", SCOPE, "enabled", json_true())));
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/user", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

}
END_TEST

START_TEST(test_glwd_geolocation_remove_user)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/user/" USER1, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/misc/" CONFIG_NAME_MAIL, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/misc/" CONFIG_NAME_GEOLOC, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_geolocation_email_location_ok)
{
  struct smtp_manager manager;
  pthread_t thread;

  json_t * j_body;

  manager.mail_data = NULL;
  manager.port = PORT_2525;
  manager.sockfd = 0;
  manager.body_pattern = BODY_PATTERN_GEOLOCATION;
  pthread_create(&thread, NULL, simple_smtp, &manager);

  j_body = json_pack("{ssss}", "username", USER1, "password", USER_PASSWORD);
  ck_assert_int_eq(run_simple_test(NULL, "POST", SERVER_URI "/auth/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  pthread_join(thread, NULL);

  ck_assert_str_eq(manager.mail_data, GEOLOCATION_CITY " - " GEOLOCATION_COUNTRY);

  o_free(manager.mail_data);
}
END_TEST

START_TEST(test_glwd_geolocation_session_ok)
{
  struct _u_request req, admin_req_copy;
  struct _u_response resp;
  int counter = 10;
  
  json_t * j_body = json_pack("{ssss}", "username", USER1, "password", USER_PASSWORD), * j_response;

  ulfius_init_request(&req);
  u_map_put(req.map_header, "User-Agent", user_agent);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/auth/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  ulfius_clean_request(&req);
  json_decref(j_body);

  ulfius_init_request(&admin_req_copy);
  
  do {
    ulfius_init_response(&resp);
    ck_assert_int_eq(ulfius_copy_request(&admin_req_copy, &admin_req), U_OK);
    ck_assert_int_eq(ulfius_set_request_properties(&admin_req_copy, U_OPT_HTTP_VERB, "GET",
                                                                    U_OPT_HTTP_URL, SERVER_URI "/delegate/" USER1 "/profile/session",
                                                                    U_OPT_URL_PARAMETER, "pattern", user_agent,
                                                                    U_OPT_NONE), U_OK);
    ck_assert_int_eq(ulfius_send_http_request(&admin_req_copy, &resp), U_OK);
    ck_assert_int_eq(resp.status, 200);
    ck_assert_ptr_ne(NULL, j_response = ulfius_get_json_body_response(&resp, NULL));
    ck_assert_int_gt(json_array_size(j_response), 0);
    if (o_strstr(json_string_value(json_object_get(json_array_get(j_response, 0), "issued_for")), GEOLOCATION_CITY " - " GEOLOCATION_COUNTRY) != NULL) {
      json_decref(j_response);
      ulfius_clean_response(&resp);
      break;
    }
    json_decref(j_response);
    ulfius_clean_response(&resp);
    usleep(50000);
  } while (counter--);
  ck_assert_int_ne(0, counter);
  ulfius_clean_request(&admin_req_copy);
}
END_TEST

START_TEST(test_glwd_geolocation_oidc_ok)
{
  struct _u_request req, admin_req_copy;
  struct _u_response resp;
  json_t * j_body, * j_response;
  char * code;
  int counter = 10;

  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  
  // Authenticate with password
  j_body = json_pack("{ssss}", "username", USER1, "password", USER_PASSWORD);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/auth",
                                                       U_OPT_JSON_BODY, j_body,
                                                       U_OPT_NONE), U_OK);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_int_eq(resp.nb_cookies, 1);

  // Get session cookie

  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_HTTP_URL, SERVER_URI "/oidc/auth?response_type=" RESPONSE_TYPE_CODE "&g_continue&client_id=" CLIENT "&redirect_uri=" REDIRECT_URI "&state=xyzabcd&nonce=abcdxyz&scope=" SCOPE " openid&g_continue",
                                                       U_OPT_COOKIE_PARAMETER, "GLEWLWYD2_SESSION_ID", resp.map_cookie[0].value,
                                                       U_OPT_NONE), U_OK);
  ulfius_clean_response(&resp);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ulfius_clean_request(&req);
  ck_assert_int_eq(resp.status, 302);
  code = o_strstr(u_map_get(resp.map_header, "Location"), "code=") + o_strlen("code=");
  if (o_strchr(code, '&') != NULL) {
    *o_strchr(code, '&') = '\0';
  }

  ulfius_init_request(&req);
  ck_assert_int_eq(U_OK, ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                             U_OPT_HTTP_URL, SERVER_URI "/oidc/token",
                                                             U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT,
                                                             U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                             U_OPT_POST_BODY_PARAMETER, "code", code,
                                                             U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT,
                                                             U_OPT_HEADER_PARAMETER, "User-Agent", user_agent,
                                                             U_OPT_NONE));
  ulfius_clean_response(&resp);
  ulfius_init_response(&resp);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);

  ulfius_init_request(&admin_req_copy);
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_copy_request(&admin_req_copy, &admin_req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&admin_req_copy, U_OPT_HTTP_VERB, "GET",
                                                                  U_OPT_HTTP_URL, SERVER_URI "/oidc/token",
                                                                  U_OPT_URL_PARAMETER, "impersonate", USER1,
                                                                  U_OPT_URL_PARAMETER, "pattern", user_agent,
                                                                  U_OPT_NONE), U_OK);

  do {
    ck_assert_int_eq(ulfius_send_http_request(&admin_req_copy, &resp), U_OK);
    ck_assert_int_eq(resp.status, 200);
    ck_assert_ptr_ne(NULL, j_response = ulfius_get_json_body_response(&resp, NULL));
    ck_assert_int_gt(json_array_size(j_response), 0);
    if (o_strstr(json_string_value(json_object_get(json_array_get(j_response, 0), "issued_for")), GEOLOCATION_CITY " - " GEOLOCATION_COUNTRY) != NULL) {
      json_decref(j_response);
      ulfius_clean_response(&resp);
      break;
    }
    json_decref(j_response);
    ulfius_clean_response(&resp);
    usleep(50000);
  } while (counter--);
  ck_assert_int_ne(0, counter);
  ulfius_clean_request(&admin_req_copy);
}
END_TEST

START_TEST(test_glwd_geolocation_invalid_url)
{
  json_t * j_body, * j_response;
  struct _u_request req, admin_req_copy;
  struct _u_response resp;

  j_body = json_pack("{sss{so ss ss}}",
                     "type", CONFIG_TYPE_GEOLOC,
                     "value",
                       "enabled", json_true(),
                       "url", "http://localhost:" PORT_GEOLOCATION_STR "0/",
                       "output-properties", "city, country_name");
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/misc/" CONFIG_NAME_GEOLOC, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  ck_assert_ptr_ne(NULL, (j_body = json_pack("{sssssss[s]so}", "username", USER1, "password", USER_PASSWORD, "email", MAIL1, "scope", SCOPE, "enabled", json_true())));
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/user", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  j_body = json_pack("{ssss}", "username", USER1, "password", USER_PASSWORD);

  ulfius_init_request(&req);
  user_agent[0] = 'O';
  u_map_put(req.map_header, "User-Agent", user_agent);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/auth/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  ulfius_clean_request(&req);
  json_decref(j_body);

  ulfius_init_request(&admin_req_copy);
  
  ulfius_init_response(&resp);
  ck_assert_int_eq(ulfius_copy_request(&admin_req_copy, &admin_req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&admin_req_copy, U_OPT_HTTP_VERB, "GET",
                                                                  U_OPT_HTTP_URL, SERVER_URI "/delegate/" USER1 "/profile/session",
                                                                  U_OPT_URL_PARAMETER, "pattern", user_agent,
                                                                  U_OPT_NONE), U_OK);
  usleep(50000);
  ck_assert_int_eq(ulfius_send_http_request(&admin_req_copy, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_response = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_gt(json_array_size(j_response), 0);
  ck_assert_ptr_eq(NULL, o_strstr(json_string_value(json_object_get(json_array_get(j_response, 0), "issued_for")), GEOLOCATION_CITY " - " GEOLOCATION_COUNTRY));
  json_decref(j_response);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&admin_req_copy);

  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/user/" USER1, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/misc/" CONFIG_NAME_GEOLOC, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_geolocation_incomplete)
{
  json_t * j_geoloc = json_object(), * j_body, * j_response;
  struct _u_request req, admin_req_copy;
  struct _u_response resp;
  int counter = 10;

  ulfius_remove_endpoint_by_val(&instance, "GET", "/", "*");
  ulfius_add_endpoint_by_val(&instance, "GET", "/", "*", 0, &callback_geolocation_incomplete, j_geoloc);
  j_body = json_pack("{ssss}", "username", USER1, "password", USER_PASSWORD);

  ulfius_init_request(&req);
  user_agent[0] = 'I';
  u_map_put(req.map_header, "User-Agent", user_agent);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/auth/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  ulfius_clean_request(&req);

  ulfius_init_request(&admin_req_copy);
  ck_assert_int_eq(ulfius_copy_request(&admin_req_copy, &admin_req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&admin_req_copy, U_OPT_HTTP_VERB, "GET",
                                                                  U_OPT_HTTP_URL, SERVER_URI "/delegate/" USER1 "/profile/session",
                                                                  U_OPT_URL_PARAMETER, "pattern", user_agent,
                                                                  U_OPT_NONE), U_OK);
  
  do {
    ulfius_init_response(&resp);
    ck_assert_int_eq(ulfius_send_http_request(&admin_req_copy, &resp), U_OK);
    ck_assert_int_eq(resp.status, 200);
    ck_assert_ptr_ne(NULL, j_response = ulfius_get_json_body_response(&resp, NULL));
    ck_assert_int_gt(json_array_size(j_response), 0);
    if (o_strstr(json_string_value(json_object_get(json_array_get(j_response, 0), "issued_for")), GEOLOCATION_CITY ) == NULL && o_strstr(json_string_value(json_object_get(json_array_get(j_response, 0), "issued_for")), GEOLOCATION_COUNTRY) == NULL) {
      json_decref(j_response);
      ulfius_clean_response(&resp);
      break;
    }
    json_decref(j_response);
    ulfius_clean_response(&resp);
    usleep(50000);
  } while (counter--);
  ck_assert_int_ne(0, counter);
  ulfius_clean_request(&admin_req_copy);

  ulfius_init_request(&req);
  user_agent[0] = 'J';
  u_map_put(req.map_header, "User-Agent", user_agent);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/auth/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  ulfius_clean_request(&req);

  ulfius_init_request(&admin_req_copy);
  ck_assert_int_eq(ulfius_copy_request(&admin_req_copy, &admin_req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&admin_req_copy, U_OPT_HTTP_VERB, "GET",
                                                                  U_OPT_HTTP_URL, SERVER_URI "/delegate/" USER1 "/profile/session",
                                                                  U_OPT_URL_PARAMETER, "pattern", user_agent,
                                                                  U_OPT_NONE), U_OK);
  
  json_object_set_new(j_geoloc, "city", json_string(GEOLOCATION_CITY));
  counter = 10;
  do {
    ulfius_init_response(&resp);
    ck_assert_int_eq(ulfius_send_http_request(&admin_req_copy, &resp), U_OK);
    ck_assert_int_eq(resp.status, 200);
    ck_assert_ptr_ne(NULL, j_response = ulfius_get_json_body_response(&resp, NULL));
    ck_assert_int_gt(json_array_size(j_response), 0);
    if (o_strstr(json_string_value(json_object_get(json_array_get(j_response, 0), "issued_for")), GEOLOCATION_CITY ) != NULL && o_strstr(json_string_value(json_object_get(json_array_get(j_response, 0), "issued_for")), GEOLOCATION_COUNTRY) == NULL) {
      json_decref(j_response);
      ulfius_clean_response(&resp);
      break;
    }
    json_decref(j_response);
    ulfius_clean_response(&resp);
    usleep(50000);
  } while (counter--);
  ck_assert_int_ne(0, counter);
  ulfius_clean_request(&admin_req_copy);
  
  ulfius_init_request(&req);
  user_agent[0] = 'K';
  u_map_put(req.map_header, "User-Agent", user_agent);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/auth/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  ulfius_clean_request(&req);

  ulfius_init_request(&admin_req_copy);
  ck_assert_int_eq(ulfius_copy_request(&admin_req_copy, &admin_req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&admin_req_copy, U_OPT_HTTP_VERB, "GET",
                                                                  U_OPT_HTTP_URL, SERVER_URI "/delegate/" USER1 "/profile/session",
                                                                  U_OPT_URL_PARAMETER, "pattern", user_agent,
                                                                  U_OPT_NONE), U_OK);
  
  json_object_set_new(j_geoloc, "country_name", json_string(GEOLOCATION_COUNTRY));
  json_object_del(j_geoloc, "city");
  counter = 10;
  do {
    ulfius_init_response(&resp);
    ck_assert_int_eq(ulfius_send_http_request(&admin_req_copy, &resp), U_OK);
    ck_assert_int_eq(resp.status, 200);
    ck_assert_ptr_ne(NULL, j_response = ulfius_get_json_body_response(&resp, NULL));
    ck_assert_int_gt(json_array_size(j_response), 0);
    if (o_strstr(json_string_value(json_object_get(json_array_get(j_response, 0), "issued_for")), GEOLOCATION_CITY ) == NULL && o_strstr(json_string_value(json_object_get(json_array_get(j_response, 0), "issued_for")), GEOLOCATION_COUNTRY) != NULL) {
      json_decref(j_response);
      ulfius_clean_response(&resp);
      break;
    }
    json_decref(j_response);
    ulfius_clean_response(&resp);
    usleep(50000);
  } while (counter--);
  ck_assert_int_ne(0, counter);
  ulfius_clean_request(&admin_req_copy);
  
  ulfius_init_request(&req);
  user_agent[0] = 'L';
  u_map_put(req.map_header, "User-Agent", user_agent);
  ck_assert_int_eq(run_simple_test(&req, "POST", SERVER_URI "/auth/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  ulfius_clean_request(&req);

  ulfius_init_request(&admin_req_copy);
  ck_assert_int_eq(ulfius_copy_request(&admin_req_copy, &admin_req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&admin_req_copy, U_OPT_HTTP_VERB, "GET",
                                                                  U_OPT_HTTP_URL, SERVER_URI "/delegate/" USER1 "/profile/session",
                                                                  U_OPT_URL_PARAMETER, "pattern", user_agent,
                                                                  U_OPT_NONE), U_OK);
  
  json_object_del(j_geoloc, "country_name");
  json_object_del(j_geoloc, "city");
  counter = 10;
  do {
    ulfius_init_response(&resp);
    ck_assert_int_eq(ulfius_send_http_request(&admin_req_copy, &resp), U_OK);
    ck_assert_int_eq(resp.status, 200);
    ck_assert_ptr_ne(NULL, j_response = ulfius_get_json_body_response(&resp, NULL));
    ck_assert_int_gt(json_array_size(j_response), 0);
    if (o_strstr(json_string_value(json_object_get(json_array_get(j_response, 0), "issued_for")), GEOLOCATION_CITY ) == NULL && o_strstr(json_string_value(json_object_get(json_array_get(j_response, 0), "issued_for")), GEOLOCATION_COUNTRY) == NULL) {
      json_decref(j_response);
      ulfius_clean_response(&resp);
      break;
    }
    json_decref(j_response);
    ulfius_clean_response(&resp);
    usleep(50000);
  } while (counter--);
  ck_assert_int_ne(0, counter);
  ulfius_clean_request(&admin_req_copy);

  json_decref(j_body);
  json_decref(j_geoloc);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd geolocation");
  tc_core = tcase_create("test_glwd_geolocation");
  tcase_add_test(tc_core, test_glwd_geolocation_add_user);
  tcase_add_test(tc_core, test_glwd_geolocation_email_location_ok);
  tcase_add_test(tc_core, test_glwd_geolocation_session_ok);
  tcase_add_test(tc_core, test_glwd_geolocation_oidc_ok);
  tcase_add_test(tc_core, test_glwd_geolocation_incomplete);
  tcase_add_test(tc_core, test_glwd_geolocation_remove_user);
  tcase_add_test(tc_core, test_glwd_geolocation_invalid_url);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed = 0;
  Suite *s;
  SRunner *sr;
  struct _u_request auth_req;
  struct _u_response auth_resp;
  int res, do_test = 0, x[1];
  json_t * j_body;
  char * cookie;

  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");

  gnutls_rnd(GNUTLS_RND_NONCE, x, sizeof(int));
  snprintf(user_agent, 32, "glwd_geolocation-%d", x[0]);

  ulfius_init_instance(&instance, PORT_GEOLOCATION, NULL, NULL);
  ulfius_add_endpoint_by_val(&instance, "GET", "/", "*", 0, &callback_geolocation, NULL);
  ulfius_start_framework(&instance);
  
  ulfius_init_request(&admin_req);
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

  run_simple_test(&admin_req, "DELETE", SERVER_URI "/auth/", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);

  ulfius_clean_request(&admin_req);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
  y_close_logs();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
