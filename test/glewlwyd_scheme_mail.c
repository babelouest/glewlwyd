/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>

#include <check.h>
#include <ulfius.h>
#include <orcania.h>
#include <yder.h>

#include "unit-tests.h"

#define SERVER_URI "http://localhost:4593/api/"
#define USERNAME "user1"
#define USERNAME_LANG "user_lang"
#define NAME_LANG "Dave Lopper with e-mails"
#define EMAIL "user_lang@glewlwyd.tld"
#define PASSWORD "password"
#define SCOPE_LIST "scope2"
#define CLIENT "client1_id"
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"

#define MODULE_MODULE "email"
#define MODULE_NAME "mail"
#define MODULE_LANG_NAME "mail_lang"
#define MODULE_DISPLAY_NAME "Mail scheme"
#define MODULE_EXPIRATION 600
#define MODULE_MAX_USE 0

#define MAIL_CODE_DURATION 600
#define MAIL_CODE_LEGTH 6
#define MAIL_HOST "localhost"
#define MAIL_PORT 2525
#define MAIL_FROM "glewlwyd"
#define MAIL_CONTENT_TYPE "text/plain; charset=utf-8"
#define MAIL_SUBJECT "Authorization Code"
#define MAIL_SUBJECT_FR "Code d'autorisation en français"
#define MAIL_BODY_PATTERN "The code is "
#define MAIL_BODY_PATTERN_FR "Le code en français est "
#define MAIL_BODY_CODE "{CODE}"

#define SCOPE_NAME "scope2"
#define SCOPE_DISPLAY_NAME "Glewlwyd mock scope without password"
#define SCOPE_DESCRIPTION "Glewlwyd scope 2 scope description"
#define SCOPE_PASSWORD_MAX_AGE 0
#define SCOPE_SCHEME_1_TYPE "mock"
#define SCOPE_SCHEME_1_NAME "mock_scheme_95"

struct _u_request user_req;
struct _u_request admin_req;
char * mail_host = NULL;

#define BACKLOG_MAX  (10)
#define BUF_SIZE  4096
#define STREQU(a,b)  (strcmp(a, b) == 0)

struct smtp_manager {
  char * mail_data;
  unsigned int port;
  int sockfd;
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

START_TEST(test_glwd_scheme_mail_scope_set)
{
  json_t * j_parameters = json_pack("{sssssisos{s[{ssss}{ssss}]}}", 
                                    "display_name", SCOPE_DISPLAY_NAME,
                                    "description", SCOPE_DESCRIPTION,
                                    "password_max_age", SCOPE_PASSWORD_MAX_AGE,
                                    "password_required", json_false(),
                                    "scheme",
                                      "2",
                                        "scheme_type", SCOPE_SCHEME_1_TYPE,
                                        "scheme_name", SCOPE_SCHEME_1_NAME,
                                        "scheme_type", MODULE_MODULE,
                                        "scheme_name", MODULE_NAME);
  json_t * j_canuse = json_pack("{ssss}", "module", MODULE_MODULE, "name", MODULE_NAME);

  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/scope/" SCOPE_NAME, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/delegate/" USERNAME "/profile/scheme/", NULL, NULL, NULL, NULL, 200, j_canuse, NULL, NULL), 1);
  
  json_decref(j_parameters);
  json_decref(j_canuse);
}
END_TEST

START_TEST(test_glwd_scheme_mail_multilang_scope_set)
{
  json_t * j_parameters = json_pack("{sssssisos{s[{ssss}{ssss}]}}", 
                                    "display_name", SCOPE_DISPLAY_NAME,
                                    "description", SCOPE_DESCRIPTION,
                                    "password_max_age", SCOPE_PASSWORD_MAX_AGE,
                                    "password_required", json_false(),
                                    "scheme",
                                      "2",
                                        "scheme_type", SCOPE_SCHEME_1_TYPE,
                                        "scheme_name", SCOPE_SCHEME_1_NAME,
                                        "scheme_type", MODULE_MODULE,
                                        "scheme_name", MODULE_LANG_NAME);
  json_t * j_canuse = json_pack("{ssss}", "module", MODULE_MODULE, "name", MODULE_LANG_NAME);

  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/scope/" SCOPE_NAME, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/delegate/" USERNAME "/profile/scheme/", NULL, NULL, NULL, NULL, 200, j_canuse, NULL, NULL), 1);
  
  json_decref(j_parameters);
  json_decref(j_canuse);
}
END_TEST

START_TEST(test_glwd_scheme_mail_scope_unset)
{
  json_t * j_parameters = json_pack("{sssssisos{s[{ssss}]}}", 
                                    "display_name", SCOPE_DISPLAY_NAME,
                                    "description", SCOPE_DESCRIPTION,
                                    "password_max_age", SCOPE_PASSWORD_MAX_AGE,
                                    "password_required", json_false(),
                                    "scheme",
                                      "2",
                                        "scheme_type", SCOPE_SCHEME_1_TYPE,
                                        "scheme_name", SCOPE_SCHEME_1_NAME);

  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/scope/" SCOPE_NAME, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_mail_irl_module_add)
{
  char * url = msprintf("%s/mod/scheme/", SERVER_URI);
  json_t * j_parameters = json_pack("{sssssssisis{sisisssissssss}}", 
                                    "module", MODULE_MODULE, 
                                    "name", MODULE_NAME, 
                                    "display_name", MODULE_DISPLAY_NAME, 
                                    "expiration", MODULE_EXPIRATION, 
                                    "max_use", MODULE_MAX_USE, 
                                    "parameters", 
                                      "code-duration", MAIL_CODE_DURATION,
                                      "code-length", MAIL_CODE_LEGTH,
                                      "host", mail_host==NULL?MAIL_HOST:mail_host,
                                      "port", MAIL_PORT,
                                      "from", MAIL_FROM,
                                      "subject", MAIL_SUBJECT,
                                      "body-pattern", MAIL_BODY_PATTERN MAIL_BODY_CODE);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", url, NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  o_free(url);
  
  url = msprintf("%s/mod/scheme/%s", SERVER_URI, MODULE_NAME);
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", url, NULL, NULL, NULL, NULL, 200, j_parameters, NULL, NULL), 1);
  o_free(url);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_mail_irl_module_multilang_add)
{
  json_t * j_parameters = json_pack("{sssssssisis{sisisssisssssss{s{sossss}s{sossss}}}}", 
                                    "module", MODULE_MODULE, 
                                    "name", MODULE_LANG_NAME, 
                                    "display_name", MODULE_DISPLAY_NAME, 
                                    "expiration", MODULE_EXPIRATION, 
                                    "max_use", MODULE_MAX_USE, 
                                    "parameters", 
                                      "code-duration", MAIL_CODE_DURATION,
                                      "code-length", MAIL_CODE_LEGTH,
                                      "host", mail_host==NULL?MAIL_HOST:mail_host,
                                      "port", MAIL_PORT,
                                      "from", MAIL_FROM,
                                      "content-type", MAIL_CONTENT_TYPE,
                                      "user-lang-property", "lang",
                                      "templates",
                                        "en",
                                          "defaultLang", json_true(),
                                          "subject", MAIL_SUBJECT,
                                          "body-pattern", MAIL_BODY_PATTERN MAIL_BODY_CODE,
                                        "fr",
                                          "defaultLang", json_false(),
                                          "subject", MAIL_SUBJECT_FR,
                                          "body-pattern", MAIL_BODY_PATTERN_FR MAIL_BODY_CODE);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/scheme/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "GET", SERVER_URI "/mod/scheme/" MODULE_LANG_NAME, NULL, NULL, NULL, NULL, 200, j_parameters, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_mail_irl_user_fr_add)
{
  json_t * j_parameters = json_pack("{sssssssss[s]so}", "username", USERNAME_LANG, "name", NAME_LANG, "lang", "fr", "email", EMAIL, "scope", SCOPE_LIST, "enabled", json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/user/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_mail_irl_user_de_add)
{
  json_t * j_parameters = json_pack("{sssssssss[s]so}", "username", USERNAME_LANG, "name", NAME_LANG, "lang", "de", "email", EMAIL, "scope", SCOPE_LIST, "enabled", json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/user/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_glwd_scheme_mail_irl_trigger)
{
  struct smtp_manager manager;
  json_t * j_params = json_pack("{sssssss{}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value");
  json_t * j_canuse = json_pack("{ssss}", "module", MODULE_MODULE, "name", MODULE_NAME);
  pthread_t thread;
  json_t * j_response;
  struct _u_request req;
  struct _u_response resp;

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_copy_request(&req, &user_req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "auth/scheme/trigger/",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_JSON_BODY, j_params,
                                                       U_OPT_NONE), U_OK);
  manager.mail_data = NULL;
  manager.port = MAIL_PORT;
  manager.sockfd = 0;
  manager.body_pattern = MAIL_BODY_PATTERN;
  pthread_create(&thread, NULL, simple_smtp, &manager);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", SERVER_URI "profile/scheme/", NULL, NULL, NULL, NULL, 200, j_canuse, NULL, NULL), 1);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, (j_response = ulfius_get_json_body_response(&resp, NULL)));
  ck_assert_int_eq(MAIL_CODE_LEGTH, json_string_length(json_object_get(j_response, "prefix")));
  pthread_join(thread, NULL);
  o_free(manager.mail_data);
  json_decref(j_params);
  json_decref(j_canuse);
  json_decref(j_response);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_glwd_scheme_mail_irl_validate_error)
{
  struct smtp_manager manager;
  json_t * j_params = json_pack("{sssssss{}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value");
  pthread_t thread;

  manager.mail_data = NULL;
  manager.port = MAIL_PORT;
  manager.sockfd = 0;
  manager.body_pattern = MAIL_BODY_PATTERN;
  pthread_create(&thread, NULL, simple_smtp, &manager);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "auth/scheme/trigger/", NULL, NULL, j_params, NULL, 200, NULL, NULL, NULL), 1);
  pthread_join(thread, NULL);
  o_free(manager.mail_data);
  json_decref(j_params);
  
  j_params = json_pack("{sssssss{}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "error");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_params);
}
END_TEST

START_TEST(test_glwd_scheme_mail_irl_validate_ok)
{
  struct smtp_manager manager;
  json_t * j_params = json_pack("{sssssss{}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value");
  pthread_t thread;
  json_t * j_response;
  struct _u_request req;
  struct _u_response resp;

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_copy_request(&req, &user_req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "auth/scheme/trigger/",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_JSON_BODY, j_params,
                                                       U_OPT_NONE), U_OK);

  manager.mail_data = NULL;
  manager.port = MAIL_PORT;
  manager.sockfd = 0;
  manager.body_pattern = MAIL_BODY_PATTERN;
  pthread_create(&thread, NULL, simple_smtp, &manager);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, (j_response = ulfius_get_json_body_response(&resp, NULL)));
  ck_assert_int_eq(MAIL_CODE_LEGTH, json_string_length(json_object_get(j_response, "prefix")));
  pthread_join(thread, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{sssssss{ss+}}", 
                       "username", USERNAME,
                       "scheme_type", MODULE_MODULE,
                       "scheme_name", MODULE_NAME,
                       "value",
                         "code", json_string_value(json_object_get(j_response, "prefix")), manager.mail_data);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_params);
  
  o_free(manager.mail_data);
  json_decref(j_response);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_glwd_scheme_mail_irl_validate_not_valid)
{
  struct smtp_manager manager;
  json_t * j_params = json_pack("{sssssss{}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value");
  pthread_t thread;
  json_t * j_response;
  struct _u_request req;
  struct _u_response resp;
  char built_code[(MAIL_CODE_LEGTH*2)+1] = {0}, built_code_updated[(MAIL_CODE_LEGTH*2)+1] = {0};

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_copy_request(&req, &user_req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "auth/scheme/trigger/",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_JSON_BODY, j_params,
                                                       U_OPT_NONE), U_OK);

  manager.mail_data = NULL;
  manager.port = MAIL_PORT;
  manager.sockfd = 0;
  manager.body_pattern = MAIL_BODY_PATTERN;
  pthread_create(&thread, NULL, simple_smtp, &manager);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, (j_response = ulfius_get_json_body_response(&resp, NULL)));
  ck_assert_int_eq(MAIL_CODE_LEGTH, json_string_length(json_object_get(j_response, "prefix")));
  pthread_join(thread, NULL);
  json_decref(j_params);
  ck_assert_int_eq(MAIL_CODE_LEGTH, o_strlen(manager.mail_data));
  
  o_strcpy(built_code, json_string_value(json_object_get(j_response, "prefix")));
  strcat(built_code, manager.mail_data);
  o_strcpy(built_code_updated, built_code);
  if (built_code_updated[3] == '4') {
    built_code_updated[3] = '5';
  } else {
    built_code_updated[3] = '4';
  }
  
  j_params = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value", "code", "errorr");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_params);
  
  j_params = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value", "code", manager.mail_data);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_params);
  
  j_params = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value", "code", "prefixerrorr");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_params);
  
  j_params = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value", "code", built_code_updated);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_params);
  
  j_params = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value", "code", built_code);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_params);
  
  j_params = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value", "code", built_code);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 401, NULL, NULL, NULL), 1);
  json_decref(j_params);
  
  j_params = json_pack("{sssssss{ss}}", "username", USERNAME, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_NAME, "value", "code", "");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_params);
  
  o_free(manager.mail_data);
  json_decref(j_response);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_glwd_scheme_mail_irl_validate_lang_fr_ok)
{
  struct smtp_manager manager;
  json_t * j_params = json_pack("{sssssss{}}", "username", USERNAME_LANG, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_LANG_NAME, "value");
  pthread_t thread;
  json_t * j_response;
  struct _u_request req;
  struct _u_response resp;

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_copy_request(&req, &user_req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "auth/scheme/trigger/",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_JSON_BODY, j_params,
                                                       U_OPT_NONE), U_OK);

  manager.mail_data = NULL;
  manager.port = MAIL_PORT;
  manager.sockfd = 0;
  manager.body_pattern = MAIL_BODY_PATTERN_FR;
  pthread_create(&thread, NULL, simple_smtp, &manager);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, (j_response = ulfius_get_json_body_response(&resp, NULL)));
  ck_assert_int_eq(MAIL_CODE_LEGTH, json_string_length(json_object_get(j_response, "prefix")));
  pthread_join(thread, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{sssssss{ss+}}", "username", USERNAME_LANG, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_LANG_NAME, "value", "code", json_string_value(json_object_get(j_response, "prefix")), manager.mail_data);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_params);
  
  o_free(manager.mail_data);
  json_decref(j_response);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_glwd_scheme_mail_irl_validate_lang_default_ok)
{
  struct smtp_manager manager;
  json_t * j_params = json_pack("{sssssss{}}", "username", USERNAME_LANG, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_LANG_NAME, "value");
  pthread_t thread;
  json_t * j_response;
  struct _u_request req;
  struct _u_response resp;

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_copy_request(&req, &user_req), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "auth/scheme/trigger/",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_JSON_BODY, j_params,
                                                       U_OPT_NONE), U_OK);

  manager.mail_data = NULL;
  manager.port = MAIL_PORT;
  manager.sockfd = 0;
  manager.body_pattern = MAIL_BODY_PATTERN;
  pthread_create(&thread, NULL, simple_smtp, &manager);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, (j_response = ulfius_get_json_body_response(&resp, NULL)));
  ck_assert_int_eq(MAIL_CODE_LEGTH, json_string_length(json_object_get(j_response, "prefix")));
  pthread_join(thread, NULL);
  json_decref(j_params);
  
  j_params = json_pack("{sssssss{ss+}}", "username", USERNAME_LANG, "scheme_type", MODULE_MODULE, "scheme_name", MODULE_LANG_NAME, "value", "code", json_string_value(json_object_get(j_response, "prefix")), manager.mail_data);
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "auth/", NULL, NULL, j_params, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_params);
  
  o_free(manager.mail_data);
  json_decref(j_response);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_glwd_scheme_mail_irl_user_remove)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/user/" USERNAME_LANG, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_scheme_mail_irl_module_remove)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/scheme/" MODULE_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_scheme_mail_irl_module_multilang_remove)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/scheme/" MODULE_LANG_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd scheme e-mail");
  tc_core = tcase_create("test_glwd_scheme_mail_irl");
  tcase_add_test(tc_core, test_glwd_scheme_mail_irl_module_add);
  tcase_add_test(tc_core, test_glwd_scheme_mail_scope_set);
  tcase_add_test(tc_core, test_glwd_scheme_mail_irl_trigger);
  tcase_add_test(tc_core, test_glwd_scheme_mail_irl_validate_error);
  tcase_add_test(tc_core, test_glwd_scheme_mail_irl_validate_ok);
  tcase_add_test(tc_core, test_glwd_scheme_mail_irl_validate_not_valid);
  tcase_add_test(tc_core, test_glwd_scheme_mail_scope_unset);
  tcase_add_test(tc_core, test_glwd_scheme_mail_irl_module_remove);
  tcase_add_test(tc_core, test_glwd_scheme_mail_irl_module_multilang_add);
  tcase_add_test(tc_core, test_glwd_scheme_mail_multilang_scope_set);
  tcase_add_test(tc_core, test_glwd_scheme_mail_irl_user_fr_add);
  tcase_add_test(tc_core, test_glwd_scheme_mail_irl_validate_lang_fr_ok);
  tcase_add_test(tc_core, test_glwd_scheme_mail_irl_user_remove);
  tcase_add_test(tc_core, test_glwd_scheme_mail_irl_user_de_add);
  tcase_add_test(tc_core, test_glwd_scheme_mail_irl_validate_lang_default_ok);
  tcase_add_test(tc_core, test_glwd_scheme_mail_irl_user_remove);
  tcase_add_test(tc_core, test_glwd_scheme_mail_scope_unset);
  tcase_add_test(tc_core, test_glwd_scheme_mail_irl_module_multilang_remove);
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
  json_t * j_body;
  int res, do_test = 0, i;
  
  if (argc > 1) {
    mail_host = argv[1];
  }
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&user_req);
  ulfius_init_request(&admin_req);
  
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  res = ulfius_send_http_request(&auth_req, &auth_resp);
  if (res == U_OK && auth_resp.status == 200) {
    for (i=0; i<auth_resp.nb_cookies; i++) {
      char * cookie = msprintf("%s=%s", auth_resp.map_cookie[i].key, auth_resp.map_cookie[i].value);
      u_map_put(user_req.map_header, "Cookie", cookie);
      o_free(cookie);
    }
    do_test = 1;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication");
  }
  ulfius_clean_response(&auth_resp);
  ulfius_clean_request(&auth_req);

  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", ADMIN_USERNAME, "password", ADMIN_PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  res = ulfius_send_http_request(&auth_req, &auth_resp);
  if (res == U_OK && auth_resp.status == 200) {
    for (i=0; i<auth_resp.nb_cookies; i++) {
      char * cookie = msprintf("%s=%s", auth_resp.map_cookie[i].key, auth_resp.map_cookie[i].value);
      u_map_put(admin_req.map_header, "Cookie", cookie);
      o_free(cookie);
    }
    do_test = 1;
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
  
  ulfius_clean_request(&user_req);
  ulfius_clean_request(&admin_req);
  
  y_close_logs();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
